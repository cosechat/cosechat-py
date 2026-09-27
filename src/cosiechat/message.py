"""
Messages and announces: the LXMF-like layer.

A message is sign-then-encrypt:

  content = CBOR map {1: [to addresses], 2: time ms, 3: title, 4: content, 5: fields}
            (the time is the sender's claim, shown to users; nothing here acts on it)
  signed  = COSE_Sign1 / COSE_Sign over content, protected kid = sender address
  sealed  = COSE_Encrypt0 to one recipient (HPKE integrated)
            COSE_Encrypt  to many recipients sharing one ciphertext (HPKE-KE, no kids)

Each recipient key is that recipient's current *ratchet* (forward secrecy,
see ratchet.py) when the sender has one, else their long-term KEM key. An
Encrypt0 sealed to a ratchet names it with the ratchet id in its unprotected
kid, so the receiver finds the right private key directly.

Routers only ever see `sealed`, addressed by a packet header that holds the
destination address. Sender, the full recipient list, and content are only
visible to a recipient. The recipient list is inside the signature, so a
message cannot be re-encrypted to someone else and passed off as addressed
to them.

An announce is a signed statement "this keyset lives at this address, and
this is its current ratchet":

  COSE_Sign1 / COSE_Sign over CBOR map
    {1: public keyset, 2: sequence, 3: nonce, 4: app data, 5: ratchet COSE_Key}

The sequence only orders one identity's own announces (the reference uses
Unix milliseconds, but a device with no clock can use a counter). It is never
compared with the local clock.
"""

import hashlib
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from . import cbor, cose
from .identity import Identity, address_of, signer_of
from .keys import CoseError, Key
from .ratchet import check_ratchet

M_TO = 1
M_TIME = 2
M_TITLE = 3
M_CONTENT = 4
M_FIELDS = 5

A_IDENTITY = 1
A_SEQUENCE = 2
A_NONCE = 3
A_APP_DATA = 4
A_RATCHET = 5

# unprotected Sign1/Sign header carrying the sender's public keyset, so a
# recipient that never saw the sender's announce can still verify
H_IDENTITY = -65537

# a shared COSE_Encrypt names no ratchet, so receivers trial-decrypt: cap the work
MAX_TRIAL_RATCHETS = 16

# a ratchet provider (see ratchet.py), a plain list of ratchet keys, or None
Ratchets = object | Iterable[Key] | None


def now_ms() -> int:
  return int(time.time() * 1000)


@dataclass
class Message:
  sender: bytes
  recipients: list[bytes]
  timestamp: int
  title: str = ''
  content: Any = ''
  fields: dict = field(default_factory=dict)
  id: bytes = b''
  signed: bytes = b''
  # id of our ratchet it was sealed to (None: our long-term identity key)
  ratchet_id: bytes | None = None

  @property
  def time(self) -> float:
    return self.timestamp / 1000


def message_id(signed: bytes) -> bytes:
  return hashlib.sha256(signed).digest()


def sign_message(
  sender: Identity,
  recipients: list[Identity],
  content: Any = '',
  title: str = '',
  fields: dict | None = None,
  timestamp: int | None = None,
  attach_identity: bool = False,
) -> Message:
  """The signed layer only (a Message with .signed set); seal it with envelope()."""
  if not recipients:
    raise ValueError('no recipients')
  body = {
    M_TO: [r.address for r in recipients],
    M_TIME: now_ms() if timestamp is None else timestamp,
  }
  if title:
    body[M_TITLE] = title
  if content not in ('', b'', None):
    body[M_CONTENT] = content
  if fields:
    body[M_FIELDS] = fields
  u = {H_IDENTITY: sender.public_bytes} if attach_identity else None
  signed = sender.sign(cbor.dumps(body), unprotected=u)
  return Message(
    sender.address,
    body[M_TO],
    body[M_TIME],
    title,
    content,
    fields or {},
    message_id(signed),
    signed,
  )


def envelope(signed: bytes, recipient: Identity, ratchet: Key | None = None) -> bytes:
  """COSE_Encrypt0 of a signed message to one recipient's ratchet (kid = ratchet id) or identity."""
  if ratchet is not None:
    check_ratchet(ratchet, recipient.kem_key)
    return cose.encrypt0(signed, ratchet, include_kid=True)
  return cose.encrypt0(signed, recipient.kem_key)


def seal(
  sender: Identity,
  recipients: list[Identity],
  content: Any = '',
  title: str = '',
  fields: dict | None = None,
  timestamp: int | None = None,
  attach_identity: bool = False,
  integrated: bool = True,
  ratchets: dict[bytes, Key] | None = None,
) -> tuple[bytes, Message]:
  """
  Sign and encrypt one sealed message for all recipients. Returns (sealed, message).
  One recipient gives COSE_Encrypt0 unless integrated=False; several share one
  COSE_Encrypt. `ratchets` maps recipient address -> their announced ratchet.
  """
  m = sign_message(sender, recipients, content, title, fields, timestamp, attach_identity)
  ratchets = ratchets or {}
  if len(recipients) == 1 and integrated:
    return envelope(m.signed, recipients[0], ratchets.get(recipients[0].address)), m
  keys = []
  for r in recipients:
    rk = ratchets.get(r.address)
    if rk is not None:
      check_ratchet(rk, r.kem_key)
      rk = Key(rk.alg, rk.pub)  # no kid: shared envelopes do not name recipients
    keys.append(rk or r.kem_key)
  return cose.encrypt(m.signed, keys), m


def seal_each(
  sender: Identity,
  recipients: list[Identity],
  content: Any = '',
  title: str = '',
  fields: dict | None = None,
  timestamp: int | None = None,
  attach_identity: bool = False,
  ratchets: dict[bytes, Key] | None = None,
) -> tuple[dict[bytes, bytes], Message]:
  """
  Sign once, then one COSE_Encrypt0 per recipient: {address: sealed}. This is
  what a Node sends, since every destination gets its own packet anyway: it is
  smaller on the wire than a shared COSE_Encrypt, and each copy names only
  its own recipient's ratchet.
  """
  m = sign_message(sender, recipients, content, title, fields, timestamp, attach_identity)
  ratchets = ratchets or {}
  return {r.address: envelope(m.signed, r, ratchets.get(r.address)) for r in recipients}, m


def _open(me: Identity, env: cose.Message, ratchets: Ratchets, require_ratchet: bool):
  """Returns (signed bytes, ratchet id or None)."""
  if hasattr(ratchets, 'keys') and hasattr(ratchets, 'get'):
    lookup, newest = ratchets.get, ratchets.keys
  else:
    held = list(ratchets or [])
    lookup = lambda rid: next((k for k in held if k.kid == rid), None)  # noqa: E731
    newest = lambda: held  # noqa: E731
  if env.kind == 'Encrypt0':
    rid = env.unprotected.get(cose.H_KID)
    if rid is not None:
      rk = lookup(rid)
      if rk is None:
        raise CoseError('sealed to a ratchet we no longer have (or never had)')
      return cose.decrypt0(env, rk), rid
    if require_ratchet:
      raise CoseError('sealed to our long-term key, but ratchets are required')
    return cose.decrypt0(env, me.kem_key), None
  if env.kind == 'Encrypt':
    for rk in newest()[:MAX_TRIAL_RATCHETS]:
      try:
        return cose.decrypt(env, rk), rk.kid
      except CoseError:
        pass
    if require_ratchet:
      raise CoseError('no current ratchet opens this message, and ratchets are required')
    return cose.decrypt(env, me.kem_key), None
  raise CoseError(f'COSE_{env.kind} is not a sealed message')


def unseal(
  me: Identity,
  sealed: bytes,
  resolve: Callable[[bytes], Identity | None],
  ratchets: Ratchets = None,
  require_ratchet: bool = False,
) -> Message:
  """
  Decrypt with one of our ratchets (or our identity KEM key) and verify the
  sender. `resolve(address)` returns the sender's public identity or None.
  With require_ratchet, messages sealed to the long-term key are refused.
  """
  signed, rid = _open(me, cose.decode(sealed), ratchets, require_ratchet)

  sm = cose.decode(signed)
  sender_addr = signer_of(sm)
  if sender_addr is None:
    raise CoseError('message has no sender kid')
  sender = resolve(sender_addr)
  if sender is None:
    attached = sm.unprotected.get(H_IDENTITY)
    if isinstance(attached, bytes) and address_of(attached) == sender_addr:
      sender = Identity.from_bytes(attached)
  if sender is None:
    raise CoseError(f'unknown sender {sender_addr.hex()}')
  if sender.address != sender_addr:
    raise CoseError('resolved identity does not match sender address')

  body = cbor.loads(sender.verify(sm))
  to = body.get(M_TO, [])
  if me.address not in to:
    raise CoseError('message was not addressed to us')
  return Message(
    sender_addr,
    to,
    body.get(M_TIME, 0),
    body.get(M_TITLE, ''),
    body.get(M_CONTENT, ''),
    body.get(M_FIELDS, {}),
    message_id(signed),
    signed,
    rid,
  )


def attached_identity(signed: bytes) -> Identity | None:
  sm = cose.decode(signed)
  data = sm.unprotected.get(H_IDENTITY)
  if isinstance(data, bytes) and address_of(data) == signer_of(sm):
    return Identity.from_bytes(data)
  return None


# --- announces ---


@dataclass
class Announce:
  identity: Identity
  sequence: int
  nonce: bytes
  app_data: Any = None
  ratchet: Key | None = None

  @property
  def address(self) -> bytes:
    return self.identity.address


def make_announce(
  identity: Identity,
  app_data: Any = None,
  sequence: int | None = None,
  ratchet: Key | None = None,
) -> bytes:
  """`sequence` must grow with each announce of this identity (default: Unix ms)."""
  body = {
    A_IDENTITY: identity.public_bytes,
    A_SEQUENCE: now_ms() if sequence is None else sequence,
    A_NONCE: os.urandom(8),
  }
  if app_data is not None:
    body[A_APP_DATA] = app_data
  if ratchet is not None:
    check_ratchet(ratchet, identity.kem_key)
    body[A_RATCHET] = ratchet.public().to_cose()
  return identity.sign(cbor.dumps(body))


def verify_announce(data: bytes, address: bytes | None = None) -> Announce:
  """Check the signature, that the keyset hashes to the signed kid (and `address`), and the ratchet."""
  sm = cose.decode(data)
  kid = signer_of(sm)
  body = cbor.loads(sm.content)
  pub = body.get(A_IDENTITY)
  if not isinstance(pub, bytes):
    raise CoseError('announce without identity')
  ident = Identity.from_bytes(pub)
  if kid != ident.address:
    raise CoseError('announce kid does not match its identity')
  if address is not None and address != ident.address:
    raise CoseError('announce is for a different address')
  ident.verify(sm)
  ratchet = None
  if A_RATCHET in body:
    ratchet = Key.from_cose(body[A_RATCHET])
    if ratchet.has_private:
      raise CoseError('announced ratchet contains a private key')
    check_ratchet(ratchet, ident.kem_key)
  seq = body.get(A_SEQUENCE, 0)
  if not isinstance(seq, int) or seq < 0:
    raise CoseError('announce sequence must be an unsigned integer')
  return Announce(ident, seq, body.get(A_NONCE, b''), body.get(A_APP_DATA), ratchet)
