"""
Messages and announces: the LXMF-like layer.

A message is sign-then-encrypt:

  content = CBOR map {1: [to addresses], 2: time ms, 3: title, 4: content, 5: fields, 6: receipt secret}
            (the time is the sender's claim, shown to users; nothing here acts on it)
  signed  = COSE_Sign1 / COSE_Sign over content, protected kid = sender address
  sealed  = COSE_Encrypt0 to the recipient's ratchet (HPKE integrated, kid = ratchet id)
            or, as an extra, one COSE_Encrypt shared by several recipients (HPKE-KE, no kids)

Identities have no encryption key: every message is sealed to a ratchet the
recipient announced (ratchet.py).

Routers only ever see `sealed`, addressed by a packet header that holds the
destination address. Sender, the full recipient list, and content are only
visible to a recipient. The recipient list is inside the signature, so a
message cannot be re-encrypted to someone else and passed off as addressed
to them.

An announce is a signed statement "this identity is here, and this is its
ratchet":

  COSE_Sign1 / COSE_Sign over CBOR map
    {1: public keyset (only in *full* announces), 2: sequence, 4: app data, 5: ratchet COSE_Key}

A *short* announce leaves out the keyset: receivers that already hold it
(pinned from an earlier full announce, or fetched by address) verify with it.
The keyset hashes to the address, so it can come from anyone.

The sequence grows with every announce, which also makes every announce
unique (for duplicate filtering). It only orders one identity's own announces
(the reference uses Unix milliseconds, but a device with no clock can use a
counter), and is never compared with the local clock.
"""

import hashlib
import hmac
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
M_RECEIPT = 6  # random secret; proving we know it proves we opened the message

RECEIPT_SECRET_SIZE = 16
RECEIPT_TAG_SIZE = 16

A_IDENTITY = 1
A_SEQUENCE = 2
A_APP_DATA = 4
A_RATCHET = 5
A_SERVICES = 7  # optional bitmask: 1 = propagation node

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
  # id of our ratchet it was sealed to
  ratchet_id: bytes | None = None
  # the sender wants a receipt: send receipt_tag(secret, our address) back
  receipt_secret: bytes | None = None
  # set when it came over a link (then it is authenticated by the link key, not signed)
  link_id: bytes | None = None

  @property
  def time(self) -> float:
    return self.timestamp / 1000


class SenderUnknown(CoseError):
  """We opened a message but do not have its sender's keyset (yet)."""

  def __init__(self, address: bytes):
    super().__init__(f'unknown sender {address.hex()}')
    self.address = address


def message_id(signed: bytes) -> bytes:
  return hashlib.sha256(signed).digest()


def receipt_tag(secret: bytes, recipient: bytes) -> bytes:
  """What `recipient` sends back to show it opened the message carrying `secret`."""
  return hmac.new(secret, b'cosechat receipt' + recipient, 'sha256').digest()[:RECEIPT_TAG_SIZE]


def sign_message(
  sender: Identity,
  recipients: list[Identity],
  content: Any = '',
  title: str = '',
  fields: dict | None = None,
  timestamp: int | None = None,
  attach_identity: bool = False,
  receipt_secret: bytes | None = None,
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
  if receipt_secret is not None:
    if len(receipt_secret) != RECEIPT_SECRET_SIZE:
      raise ValueError(f'receipt secret must be {RECEIPT_SECRET_SIZE} bytes')
    body[M_RECEIPT] = receipt_secret
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
    receipt_secret=receipt_secret,
  )


def envelope(signed: bytes, ratchet: Key) -> bytes:
  """COSE_Encrypt0 of a signed message to a recipient's ratchet (kid = ratchet id)."""
  check_ratchet(ratchet)
  return cose.encrypt0(signed, ratchet, include_kid=True)


def _ratchet_for(ratchets: dict[bytes, Key], r: Identity) -> Key:
  rk = ratchets.get(r.address)
  if rk is None:
    raise ValueError(f'no ratchet for {r.address.hex()}: it has to announce one')
  return rk


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
  receipt_secret: bytes | None = None,
) -> tuple[bytes, Message]:
  """
  Sign and encrypt one sealed message for all recipients. Returns (sealed, message).
  `ratchets` maps each recipient address to its announced ratchet. One
  recipient gives COSE_Encrypt0 unless integrated=False; several share one
  COSE_Encrypt (an extra: see seal_each for what a node sends).
  """
  m = sign_message(
    sender, recipients, content, title, fields, timestamp, attach_identity, receipt_secret
  )
  ratchets = ratchets or {}
  if len(recipients) == 1 and integrated:
    return envelope(m.signed, _ratchet_for(ratchets, recipients[0])), m
  keys = []
  for r in recipients:
    rk = _ratchet_for(ratchets, r)
    check_ratchet(rk)
    keys.append(Key(rk.alg, rk.pub))  # no kid: shared envelopes do not name recipients
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
  receipt_secret: bytes | None = None,
) -> tuple[dict[bytes, bytes], Message]:
  """
  Sign once, then one COSE_Encrypt0 per recipient: {address: sealed}. This is
  what a Node sends, since every destination gets its own packet anyway: it is
  smaller on the wire than a shared COSE_Encrypt, and each copy names only
  its own recipient's ratchet.
  """
  m = sign_message(
    sender, recipients, content, title, fields, timestamp, attach_identity, receipt_secret
  )
  ratchets = ratchets or {}
  return {r.address: envelope(m.signed, _ratchet_for(ratchets, r)) for r in recipients}, m


def _open(env: cose.Message, ratchets: Ratchets):
  """Returns (signed bytes, id of the ratchet that opened it)."""
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
    raise CoseError('sealed message names no ratchet')
  if env.kind == 'Encrypt':
    for rk in newest()[:MAX_TRIAL_RATCHETS]:
      try:
        return cose.decrypt(env, rk), rk.kid
      except CoseError:
        pass
    raise CoseError('none of our recent ratchets opens this message')
  raise CoseError(f'COSE_{env.kind} is not a sealed message')


def unseal(
  me: Identity,
  sealed: bytes,
  resolve: Callable[[bytes], Identity | None],
  ratchets: Ratchets = None,
) -> Message:
  """
  Decrypt with one of our ratchets and verify the sender. `resolve(address)`
  returns the sender's public identity or None.
  """
  signed, rid = _open(cose.decode(sealed), ratchets)

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
    raise SenderUnknown(sender_addr)
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
    _receipt_secret(body.get(M_RECEIPT)),
  )


def _receipt_secret(v):
  return v if isinstance(v, bytes) and len(v) == RECEIPT_SECRET_SIZE else None


def attached_identity(signed: bytes) -> Identity | None:
  sm = cose.decode(signed)
  data = sm.unprotected.get(H_IDENTITY)
  if isinstance(data, bytes) and address_of(data) == signer_of(sm):
    return Identity.from_bytes(data)
  return None


# --- announces ---


class KeysetNeeded(CoseError):
  """A short announce from an identity whose keyset we do not have yet."""

  def __init__(self, address: bytes):
    super().__init__(f'need the keyset for {address.hex()}')
    self.address = address


@dataclass
class Announce:
  identity: Identity
  sequence: int
  ratchet: Key
  app_data: Any = None
  full: bool = True  # carried its keyset
  services: int = 0

  @property
  def address(self) -> bytes:
    return self.identity.address


def make_announce(
  identity: Identity,
  ratchet: Key,
  app_data: Any = None,
  sequence: int | None = None,
  full: bool = True,
  services: int = 0,
) -> bytes:
  """
  `sequence` must grow with each announce of this identity (default: Unix ms).
  full=False leaves out the keyset (receivers must already have it).
  """
  body = {A_SEQUENCE: now_ms() if sequence is None else sequence}
  if full:
    body[A_IDENTITY] = identity.public_bytes
  if app_data is not None:
    body[A_APP_DATA] = app_data
  check_ratchet(ratchet)
  body[A_RATCHET] = ratchet.public().to_cose()
  if services:
    body[A_SERVICES] = services
  return identity.sign(cbor.dumps(body))


def announce_address(data: bytes) -> bytes | None:
  """The address an announce claims (its signature kid), without verifying anything."""
  try:
    return signer_of(cose.decode(data))
  except CoseError:
    return None


def verify_announce(
  data: bytes,
  address: bytes | None = None,
  known: Callable[[bytes], Identity | None] | None = None,
) -> Announce:
  """
  Check an announce: its keyset (included, or `known(address)` for a short
  one) hashes to the signed kid and to `address`, the signature verifies, and
  the ratchet is well formed. Raises KeysetNeeded for a short announce from an
  identity `known` does not have.
  """
  sm = cose.decode(data)
  kid = signer_of(sm)
  if kid is None:
    raise CoseError('announce without a kid')
  if address is not None and address != kid:
    raise CoseError('announce is for a different address')
  body = cbor.loads(sm.content)
  pub = body.get(A_IDENTITY)
  if pub is not None:
    if not isinstance(pub, bytes) or address_of(pub) != kid:
      raise CoseError('announce keyset does not match its kid')
    ident = Identity.from_bytes(pub)
  else:
    ident = known(kid) if known else None
    if ident is None:
      raise KeysetNeeded(kid)
  ident.verify(sm)
  if A_RATCHET not in body:
    raise CoseError('announce has no ratchet')
  ratchet = Key.from_cose(body[A_RATCHET])
  if ratchet.has_private:
    raise CoseError('announced ratchet contains a private key')
  check_ratchet(ratchet)
  seq = body.get(A_SEQUENCE, 0)
  if not isinstance(seq, int) or seq < 0:
    raise CoseError('announce sequence must be an unsigned integer')
  services = body.get(A_SERVICES, 0)
  if not isinstance(services, int) or services < 0:
    raise CoseError('bad announce services')
  return Announce(ident, seq, ratchet, body.get(A_APP_DATA), pub is not None, services)
