"""
COSE message structures (RFC 9052) on top of cbor2 + keys.py.

  sign1 / verify_sign1       COSE_Sign1    single signer
  sign / verify_sign         COSE_Sign     multiple signers
  mac0 / verify_mac0         COSE_Mac0     shared-key authentication
  mac / verify_mac           COSE_Mac      MAC key delivered to recipients (HPKE-KE)
  encrypt0 / decrypt0        COSE_Encrypt0 shared key (AEAD) or one recipient (HPKE integrated)
  encrypt / decrypt          COSE_Encrypt  many recipients (HPKE-KE)

All outputs are tagged CBOR. No python COSE library supports ML-DSA / X-Wing
yet, so this is a thin layer: it builds the RFC 9052 to-be-signed/MAC'd/AAD
structures and hands them to pyca/cryptography. It is cross-checked against
pycose and python-cwt in the test-suite for the pre-quantum algorithms.
"""

import os
from dataclasses import dataclass, field

from . import cbor
from .keys import (
  AeadAlg,
  CoseError,
  HmacAlg,
  HpkeAlg,
  Key,
  SignAlg,
  get_alg,
  hpke_variant,
)

# header labels
H_ALG = 1
H_CRIT = 2
H_CTY = 3
H_KID = 4
H_IV = 5
H_PARTIAL_IV = 6
H_EK = -4  # COSE-HPKE encapsulated key

TAG_ENCRYPT0 = 16
TAG_MAC0 = 17
TAG_SIGN1 = 18
TAG_ENCRYPT = 96
TAG_MAC = 97
TAG_SIGN = 98

KINDS = {
  TAG_ENCRYPT0: 'Encrypt0',
  TAG_MAC0: 'Mac0',
  TAG_SIGN1: 'Sign1',
  TAG_ENCRYPT: 'Encrypt',
  TAG_MAC: 'Mac',
  TAG_SIGN: 'Sign',
}


def _prot(m: dict | None) -> bytes:
  return cbor.dumps(m) if m else b''


def _unprot(b: bytes) -> dict:
  return cbor.loads(b) if b else {}


@dataclass
class Layer:
  """One header-carrying layer: a message body, a signer or a recipient."""

  raw_protected: bytes
  unprotected: dict
  protected: dict = field(default_factory=dict)

  @classmethod
  def of(cls, raw_protected: bytes, unprotected: dict) -> 'Layer':
    if not isinstance(raw_protected, bytes) or not isinstance(unprotected, dict):
      raise CoseError('malformed COSE headers')
    return cls(raw_protected, unprotected, _unprot(raw_protected))

  def header(self, label, default=None):
    if label in self.protected:
      return self.protected[label]
    return self.unprotected.get(label, default)

  @property
  def alg(self):
    return self.header(H_ALG)

  @property
  def kid(self):
    return self.header(H_KID)


@dataclass
class Message(Layer):
  kind: str = ''
  content: bytes | None = None  # payload (sign/mac) or ciphertext (encrypt)
  signature: bytes | None = None  # Sign1 signature or Mac/Mac0 tag
  signers: list = field(default_factory=list)  # [(Layer, signature)]
  recipients: list = field(default_factory=list)  # [(Layer, ciphertext)]


def decode(data: bytes, expect: int | None = None) -> Message:
  """Parse a COSE message. Untagged input is accepted when `expect` gives the tag."""
  try:
    return _decode(data, expect)
  except CoseError:
    raise
  except Exception as e:
    raise CoseError(f'malformed COSE message: {e!r}') from None


def _decode(data, expect):
  obj = cbor.loads(data) if isinstance(data, (bytes, bytearray)) else data
  if isinstance(obj, cbor.CBORTag):
    tag, arr = obj.tag, obj.value
  elif expect is not None:
    tag, arr = expect, obj
  else:
    raise CoseError('untagged COSE message')
  if tag not in KINDS or not isinstance(arr, list):
    raise CoseError(f'not a COSE message (tag {tag})')
  if expect is not None and tag != expect:
    raise CoseError(f'expected COSE_{KINDS[expect]}, got COSE_{KINDS[tag]}')
  base = Layer.of(arr[0], arr[1])
  m = Message(base.raw_protected, base.unprotected, base.protected, KINDS[tag], arr[2])
  if tag in (TAG_SIGN1, TAG_MAC0, TAG_MAC):
    m.signature = arr[3]
  if tag == TAG_SIGN:
    m.signers = [(Layer.of(s[0], s[1]), s[2]) for s in arr[3]]
  if tag == TAG_MAC:
    m.recipients = [(Layer.of(r[0], r[1]), r[2]) for r in arr[4]]
  if tag == TAG_ENCRYPT:
    m.recipients = [(Layer.of(r[0], r[1]), r[2]) for r in arr[3]]
  return m


def _as_message(data, tag) -> Message:
  return data if isinstance(data, Message) else decode(data, tag)


def _headers(alg: int, protected, unprotected, kid=None):
  p = {H_ALG: alg, **(protected or {})}
  u = dict(unprotected or {})
  if kid is not None:
    u[H_KID] = kid
  return p, u


def _sign_alg(key: Key) -> SignAlg:
  a = key.algorithm
  if not isinstance(a, SignAlg):
    raise CoseError(f'{a.name} is not a signature algorithm')
  return a


# --- Sign1 ---


def sign1(
  payload: bytes,
  key: Key,
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
  kid_protected: bool = False,
) -> bytes:
  alg = _sign_alg(key)
  p, u = _headers(alg.id, protected, unprotected, None if kid_protected else key.kid)
  if kid_protected and key.kid is not None:
    p[H_KID] = key.kid
  rp = _prot(p)
  tbs = cbor.dumps(['Signature1', rp, external_aad, payload])
  return cbor.dumps(cbor.CBORTag(TAG_SIGN1, [rp, u, payload, alg.sign(key, tbs)]))


def verify_sign1(data, key: Key, external_aad: bytes = b'') -> bytes:
  m = _as_message(data, TAG_SIGN1)
  if m.alg != key.alg:
    raise CoseError(f'algorithm mismatch: message {m.alg}, key {key.alg}')
  tbs = cbor.dumps(['Signature1', m.raw_protected, external_aad, m.content])
  if not _sign_alg(key).verify(key, m.signature, tbs):
    raise CoseError('Sign1 signature is invalid')
  return m.content


# --- Sign (multiple signers) ---


def sign(
  payload: bytes,
  keys: list[Key],
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
) -> bytes:
  rp = _prot(protected)
  sigs = []
  for key in keys:
    alg = _sign_alg(key)
    sp = _prot({H_ALG: alg.id})
    su = {H_KID: key.kid} if key.kid is not None else {}
    tbs = cbor.dumps(['Signature', rp, sp, external_aad, payload])
    sigs.append([sp, su, alg.sign(key, tbs)])
  return cbor.dumps(cbor.CBORTag(TAG_SIGN, [rp, dict(unprotected or {}), payload, sigs]))


def verify_sign(data, keys: list[Key], external_aad: bytes = b'') -> bytes:
  """Every key given must have produced a valid signature (so hybrid PQ + pre-quantum both hold)."""
  m = _as_message(data, TAG_SIGN)
  if not keys:
    raise CoseError('no verification keys')
  for key in keys:
    ok = False
    for layer, sig in m.signers:
      if layer.alg != key.alg:
        continue
      if layer.kid is not None and key.kid is not None and layer.kid != key.kid:
        continue
      tbs = cbor.dumps(['Signature', m.raw_protected, layer.raw_protected, external_aad, m.content])
      if _sign_alg(key).verify(key, sig, tbs):
        ok = True
        break
    if not ok:
      raise CoseError(f'no valid {key.algorithm.name} signature')
  return m.content


# --- Mac0 / Mac ---


def _mac_alg(alg_id: int) -> HmacAlg:
  a = get_alg(alg_id)
  if not isinstance(a, HmacAlg):
    raise CoseError(f'{a.name} is not a MAC algorithm')
  return a


def mac0(
  payload: bytes,
  key: Key,
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
) -> bytes:
  alg = _mac_alg(key.alg)
  p, u = _headers(alg.id, protected, unprotected, key.kid)
  rp = _prot(p)
  tag = alg.tag(key.priv, cbor.dumps(['MAC0', rp, external_aad, payload]))
  return cbor.dumps(cbor.CBORTag(TAG_MAC0, [rp, u, payload, tag]))


def verify_mac0(data, key: Key, external_aad: bytes = b'') -> bytes:
  m = _as_message(data, TAG_MAC0)
  if m.alg != key.alg:
    raise CoseError(f'algorithm mismatch: message {m.alg}, key {key.alg}')
  if not _mac_alg(key.alg).verify(
    key.priv, m.signature, cbor.dumps(['MAC0', m.raw_protected, external_aad, m.content])
  ):
    raise CoseError('Mac0 tag is invalid')
  return m.content


def mac(
  payload: bytes,
  recipients: list[Key],
  alg: int = 5,
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
  include_kid: bool = False,
) -> bytes:
  a = _mac_alg(alg)
  k = os.urandom(a.key_size)
  p, u = _headers(a.id, protected, unprotected)
  rp = _prot(p)
  tag = a.tag(k, cbor.dumps(['MAC', rp, external_aad, payload]))
  rs = [_wrap_cek(k, a.id, r, include_kid) for r in recipients]
  return cbor.dumps(cbor.CBORTag(TAG_MAC, [rp, u, payload, tag, rs]))


def verify_mac(data, key: Key, external_aad: bytes = b'') -> bytes:
  m = _as_message(data, TAG_MAC)
  k = _unwrap_cek(m, key)
  if not _mac_alg(m.alg).verify(
    k, m.signature, cbor.dumps(['MAC', m.raw_protected, external_aad, m.content])
  ):
    raise CoseError('Mac tag is invalid')
  return m.content


# --- recipients (COSE-HPKE key encryption) ---


def _recipient_info(next_layer_alg: int, raw_protected: bytes, extra: bytes = b'') -> bytes:
  return cbor.dumps(['HPKE Recipient', next_layer_alg, raw_protected, extra])


def _wrap_cek(cek: bytes, next_layer_alg: int, key: Key, include_kid: bool):
  ke = hpke_variant(key, integrated=False)
  rp = _prot({H_ALG: ke.id})
  enc, ct = ke.seal(key, cek, info=_recipient_info(next_layer_alg, rp))
  u = {H_EK: enc}
  if include_kid and key.kid is not None:
    u[H_KID] = key.kid
  return [rp, u, ct]


def _unwrap_cek(m: Message, key: Key) -> bytes:
  """Trial-decrypt each recipient; recipients normally carry no kid, to hide who they are."""
  ke = hpke_variant(key, integrated=False)
  for layer, ct in m.recipients:
    if layer.alg != ke.id:
      continue
    if layer.kid is not None and key.kid is not None and layer.kid != key.kid:
      continue
    enc = layer.header(H_EK)
    if not isinstance(enc, bytes):
      continue
    try:
      return ke.open(key, enc, ct, info=_recipient_info(m.alg, layer.raw_protected))
    except Exception:
      continue
  raise CoseError('no recipient entry could be opened with this key')


# --- Encrypt0 / Encrypt ---


def _aead_alg(alg_id: int) -> AeadAlg:
  a = get_alg(alg_id)
  if not isinstance(a, AeadAlg):
    raise CoseError(f'{a.name} is not a content encryption algorithm')
  return a


def encrypt0(
  plaintext: bytes,
  key: Key,
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
  include_kid: bool = False,
) -> bytes:
  """`key` is a shared AEAD key, or the recipient's HPKE public key (integrated mode)."""
  kid = key.kid if include_kid else None
  if isinstance(key.algorithm, HpkeAlg):
    alg = hpke_variant(key, integrated=True)
    p, u = _headers(alg.id, protected, unprotected, kid)
    rp = _prot(p)
    aad = cbor.dumps(['Encrypt0', rp, external_aad])
    enc, ct = alg.seal(key, plaintext, aad=aad)
    u[H_EK] = enc
  else:
    alg = _aead_alg(key.alg)
    p, u = _headers(alg.id, protected, unprotected, kid)
    rp = _prot(p)
    iv = os.urandom(alg.iv_size)
    u[H_IV] = iv
    ct = alg.encrypt(key.priv, iv, plaintext, cbor.dumps(['Encrypt0', rp, external_aad]))
  return cbor.dumps(cbor.CBORTag(TAG_ENCRYPT0, [rp, u, ct]))


def decrypt0(data, key: Key, external_aad: bytes = b'') -> bytes:
  m = _as_message(data, TAG_ENCRYPT0)
  aad = cbor.dumps(['Encrypt0', m.raw_protected, external_aad])
  try:
    if isinstance(key.algorithm, HpkeAlg):
      alg = hpke_variant(key, integrated=True)
      if m.alg != alg.id:
        raise CoseError(f'algorithm mismatch: message {m.alg}, key {alg.id}')
      return alg.open(key, m.header(H_EK), m.content, aad=aad)
    alg = _aead_alg(key.alg)
    if m.alg != alg.id:
      raise CoseError(f'algorithm mismatch: message {m.alg}, key {alg.id}')
    return alg.decrypt(key.priv, m.header(H_IV), m.content, aad)
  except CoseError:
    raise
  except Exception as e:
    raise CoseError(f'Encrypt0 decryption failed: {e!r}') from None


def encrypt(
  plaintext: bytes,
  recipients: list[Key],
  alg: int = 3,
  protected: dict | None = None,
  unprotected: dict | None = None,
  external_aad: bytes = b'',
  include_kid: bool = False,
) -> bytes:
  a = _aead_alg(alg)
  cek = os.urandom(a.key_size)
  iv = os.urandom(a.iv_size)
  p, u = _headers(a.id, protected, unprotected)
  u[H_IV] = iv
  rp = _prot(p)
  ct = a.encrypt(cek, iv, plaintext, cbor.dumps(['Encrypt', rp, external_aad]))
  rs = [_wrap_cek(cek, a.id, r, include_kid) for r in recipients]
  return cbor.dumps(cbor.CBORTag(TAG_ENCRYPT, [rp, u, ct, rs]))


def decrypt(data, key: Key, external_aad: bytes = b'') -> bytes:
  m = _as_message(data, TAG_ENCRYPT)
  cek = _unwrap_cek(m, key)
  a = _aead_alg(m.alg)
  try:
    return a.decrypt(
      cek, m.header(H_IV), m.content, cbor.dumps(['Encrypt', m.raw_protected, external_aad])
    )
  except Exception as e:
    raise CoseError(f'Encrypt decryption failed: {e!r}') from None
