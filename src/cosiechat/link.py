"""
Links: sessions between two identities, like Reticulum's Links.

A sealed message pays for a full PQ signature (3.3 KB for ML-DSA-65) and a
KEM encapsulation (1.1 KB for X-Wing) every time. A link pays that once, then
each message is a symmetric COSE_Encrypt0 with ~40 bytes of overhead.

  request (initiator A -> B), sealed like a message:
    COSE_Encrypt0 to B's ratchet of
      A.sign(CBOR {1: A's ephemeral KEM public COSE_Key, 2: part_a (32 random bytes), 3: B's address})

  accept (B -> A):
    link id (16) || COSE_Encrypt0, HPKE to A's ephemeral key, of CBOR {1: part_b (32 random bytes)}
    external_aad = SHA-256(request)

  link id           = SHA-256(request)[0:16]
  keys              = HKDF-SHA-256(ikm = part_a || part_b, salt = link id, info = "cosiechat link", 64 bytes)
  A->B key, B->A key = keys[0:32], keys[32:64]   (ChaCha20/Poly1305)

  link message:
    link id (16) || COSE_Encrypt0(direction key, random IV) of the message body
    (the same CBOR map a sealed message signs, without `to`: the link keys
    already bind both parties and the direction)

Why it holds:
  * A is authenticated by its signature, which also binds A's ephemeral key
    and B's address.
  * B is authenticated without a signature: A's ephemeral key travels only
    inside the request encrypted to B, so only B can produce an accept that
    decrypts under it, and the accept is bound to the exact request.
  * Forward secrecy per link: the keys need both part_a (readable with B's
    ratchet) and part_b (readable only with A's ephemeral key, deleted as soon
    as the link is up). Link keys themselves live only as long as the link.
  * Link messages are authenticated by a key only A and B hold, not signed:
    no third party can be convinced who wrote them (as with Reticulum links).
"""

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import cbor, cose
from . import message as msg
from .identity import Identity, signer_of
from .keys import CHACHA20_POLY1305, QUANTUM_SAFE_KEM, CoseError, HpkeAlg, Key

LINK_ID_SIZE = 16
PART_SIZE = 32

L_EPHEMERAL = 1
L_PART = 2
L_PEER = 3

# extra body field in link messages: the sender is closing the link
M_CLOSE = 7


@dataclass
class LinkKeys:
  link_id: bytes
  peer: bytes  # the other side's address
  initiator: bool
  send_key: Key
  recv_key: Key


@dataclass
class PendingLink:
  """Initiator state between request and accept. Holds the ephemeral private key."""

  link_id: bytes
  peer: bytes
  request: bytes
  ephemeral: Key
  part_a: bytes


def _derive(link_id: bytes, part_a: bytes, part_b: bytes, peer: bytes, initiator: bool) -> LinkKeys:
  okm = HKDF(hashes.SHA256(), 64, link_id, b'cosiechat link').derive(part_a + part_b)
  a_to_b = Key(CHACHA20_POLY1305, priv=okm[:32], kid=link_id)
  b_to_a = Key(CHACHA20_POLY1305, priv=okm[32:], kid=link_id)
  if initiator:
    return LinkKeys(link_id, peer, True, a_to_b, b_to_a)
  return LinkKeys(link_id, peer, False, b_to_a, a_to_b)


def make_request(me: Identity, peer: Identity, peer_ratchet: Key) -> PendingLink:
  """Start a link to `peer`. Send .request as a LINK_REQUEST packet to peer.address."""
  eph = Key.generate(me.kem_alg)
  part_a = os.urandom(PART_SIZE)
  body = cbor.dumps({L_EPHEMERAL: eph.public().to_cose(), L_PART: part_a, L_PEER: peer.address})
  request = msg.envelope(me.sign(body), peer_ratchet)
  return PendingLink(link_id(request), peer.address, request, eph, part_a)


def link_id(request: bytes) -> bytes:
  return hashlib.sha256(request).digest()[:LINK_ID_SIZE]


def read_request(
  me: Identity,
  request: bytes,
  resolve,
  ratchets=None,
  quantum_safe_only: bool = True,
) -> tuple[Identity, Key, bytes]:
  """Open and verify a request: (initiator identity, its ephemeral public key, part_a)."""
  signed, _ = msg._open(cose.decode(request), ratchets)
  sm = cose.decode(signed)
  sender_addr = signer_of(sm)
  sender = resolve(sender_addr) if sender_addr else None
  if sender is None:
    sender = msg.attached_identity(signed)
  if sender is None or sender.address != sender_addr:
    raise CoseError('link request from an unknown identity')
  body = cbor.loads(sender.verify(sm))
  if body.get(L_PEER) != me.address:
    raise CoseError('link request is for someone else')
  part_a = body.get(L_PART)
  if not isinstance(part_a, bytes) or len(part_a) != PART_SIZE:
    raise CoseError('bad link request')
  eph = Key.from_cose(body[L_EPHEMERAL])
  if not isinstance(eph.algorithm, HpkeAlg) or eph.has_private:
    raise CoseError('bad ephemeral key in link request')
  if quantum_safe_only and eph.alg not in QUANTUM_SAFE_KEM:
    raise CoseError('link request uses a key that is not quantum-safe')
  return sender, eph, part_a


def accept_request(
  me: Identity,
  request: bytes,
  resolve,
  ratchets=None,
  quantum_safe_only: bool = True,
) -> tuple[Identity, bytes, LinkKeys]:
  """
  B's side: open and verify a request. Returns (initiator identity, accept
  payload to send back to it, link keys). Raises CoseError if anything is off.
  """
  sender, eph, part_a = read_request(me, request, resolve, ratchets, quantum_safe_only)
  lid = link_id(request)
  part_b = os.urandom(PART_SIZE)
  transcript = hashlib.sha256(request).digest()
  accept = lid + cose.encrypt0(cbor.dumps({L_PART: part_b}), eph, external_aad=transcript)
  return sender, accept, _derive(lid, part_a, part_b, sender.address, initiator=False)


def finish(pending: PendingLink, accept: bytes) -> LinkKeys:
  """A's side: check the accept and derive the link keys. Deletes the ephemeral key."""
  if accept[:LINK_ID_SIZE] != pending.link_id:
    raise CoseError('accept is for another link')
  transcript = hashlib.sha256(pending.request).digest()
  body = cbor.loads(
    cose.decrypt0(accept[LINK_ID_SIZE:], pending.ephemeral, external_aad=transcript)
  )
  part_b = body.get(L_PART)
  if not isinstance(part_b, bytes) or len(part_b) != PART_SIZE:
    raise CoseError('bad link accept')
  keys = _derive(pending.link_id, pending.part_a, part_b, pending.peer, initiator=True)
  pending.ephemeral = None  # forward secrecy: nobody can recompute part_b now
  pending.part_a = b''
  return keys


def seal(keys: LinkKeys, body: bytes) -> bytes:
  """link id || COSE_Encrypt0 of a message body (fresh IV every call)."""
  return keys.link_id + cose.encrypt0(body, keys.send_key, external_aad=keys.link_id)


def unseal(keys: LinkKeys, payload: bytes) -> bytes:
  if payload[:LINK_ID_SIZE] != keys.link_id:
    raise CoseError('not a message on this link')
  return cose.decrypt0(payload[LINK_ID_SIZE:], keys.recv_key, external_aad=keys.link_id)


def message_body(
  content='',
  title: str = '',
  fields: dict | None = None,
  receipt_secret: bytes | None = None,
  close: bool = False,
) -> bytes:
  # no `to`: the link keys already bind the two parties and the direction
  body = {msg.M_TIME: msg.now_ms()}
  if title:
    body[msg.M_TITLE] = title
  if content not in ('', b'', None):
    body[msg.M_CONTENT] = content
  if fields:
    body[msg.M_FIELDS] = fields
  if receipt_secret is not None:
    body[msg.M_RECEIPT] = receipt_secret
  if close:
    body[M_CLOSE] = True
  return cbor.dumps(body)


def read_message(keys: LinkKeys, me: bytes, body_bytes: bytes) -> tuple[msg.Message, bool]:
  """Parse an opened link body into a Message (sender = the link peer). Returns (message, close)."""
  body = cbor.loads(body_bytes)
  if not isinstance(body, dict):
    raise CoseError('bad link message')
  m = msg.Message(
    keys.peer,
    [me],
    body.get(msg.M_TIME, 0),
    body.get(msg.M_TITLE, ''),
    body.get(msg.M_CONTENT, ''),
    body.get(msg.M_FIELDS, {}),
    hashlib.sha256(keys.link_id + body_bytes).digest(),
    b'',
    None,
    msg._receipt_secret(body.get(msg.M_RECEIPT)),
    keys.link_id,
  )
  return m, body.get(M_CLOSE) is True
