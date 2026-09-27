"""
COSE algorithms and keys (RFC 9052/9053, RFC 9864, draft-ietf-cose-dilithium,
draft-ietf-cose-hpke, draft-reddy-cose-hpke-pq-pqt).

Every primitive comes from pyca/cryptography. This module only maps COSE
algorithm identifiers onto those primitives and (de)serializes COSE_Key maps.
"""

import hashlib
import hmac as _hmac
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hpke
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
  decode_dss_signature,
  encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# COSE key types
KTY_OKP = 1
KTY_EC2 = 2
KTY_SYMMETRIC = 4
KTY_AKP = 7

# COSE_Key labels
KEY_KTY = 1
KEY_KID = 2
KEY_ALG = 3

# COSE curves
CRV_P256 = 1
CRV_P384 = 2
CRV_P521 = 3
CRV_X25519 = 4
CRV_ED25519 = 6

_EC_CURVES = {
  CRV_P256: (ec.SECP256R1(), 32, hashes.SHA256()),
  CRV_P384: (ec.SECP384R1(), 48, hashes.SHA384()),
  CRV_P521: (ec.SECP521R1(), 66, hashes.SHA512()),
}


class CoseError(Exception):
  pass


@dataclass
class Key:
  """
  A COSE key. `pub` is the raw public key (AKP "pub", OKP "x", EC2 x||y).
  `priv` is the raw private key (AKP seed, OKP/EC2 "d", symmetric "k").
  """

  alg: int
  pub: bytes = b''
  priv: bytes | None = None
  kid: bytes | None = None
  _cache: dict = field(default_factory=dict, repr=False, compare=False)

  @property
  def algorithm(self) -> 'Alg':
    return get_alg(self.alg)

  @property
  def has_private(self) -> bool:
    return self.priv is not None

  def public(self) -> 'Key':
    if self.algorithm.kty == KTY_SYMMETRIC:
      raise CoseError('symmetric keys have no public half')
    return Key(self.alg, self.pub, None, self.kid)

  def to_cose(self, private: bool = False) -> dict:
    return self.algorithm.encode_key(self, private)

  @classmethod
  def from_cose(cls, m: dict) -> 'Key':
    if KEY_ALG not in m:
      raise CoseError('COSE_Key without alg is not supported')
    return get_alg(m[KEY_ALG]).decode_key(m)

  @classmethod
  def generate(cls, alg: int, kid: bytes | None = None) -> 'Key':
    key = get_alg(alg).generate()
    key.kid = kid
    return key

  @classmethod
  def from_private(cls, alg: int, priv: bytes, kid: bytes | None = None) -> 'Key':
    """A full key from its private bytes (seed / d / k): the public half is derived."""
    return Key(alg, get_alg(alg).public_from_private(priv), priv, kid)


class Alg:
  id = 0
  name = ''
  kty = 0

  def __repr__(self):
    return f'<{self.name} ({self.id})>'

  def encode_key(self, key: Key, private: bool) -> dict:
    m = {KEY_KTY: self.kty, KEY_ALG: self.id}
    if key.kid is not None:
      m[KEY_KID] = key.kid
    return m

  def decode_key(self, m: dict) -> Key:
    if m.get(KEY_KTY) != self.kty:
      raise CoseError(f'{self.name} requires kty {self.kty}')
    return Key(self.id, kid=m.get(KEY_KID))

  def public_from_private(self, priv: bytes) -> bytes:
    raise CoseError(f'{self.name} cannot derive a public key')


# --- key shapes ---


class _AkpShape(Alg):
  """Algorithm Key Pair: {1: 7, 3: alg, -1: pub, -2: priv}"""

  kty = KTY_AKP

  def encode_key(self, key, private):
    m = super().encode_key(key, private)
    m[-1] = key.pub
    if private and key.priv is not None:
      m[-2] = key.priv
    return m

  def decode_key(self, m):
    k = super().decode_key(m)
    k.pub = m[-1]
    k.priv = m.get(-2)
    return k


class _OkpShape(Alg):
  kty = KTY_OKP
  crv = 0

  def encode_key(self, key, private):
    m = super().encode_key(key, private)
    m[-1] = self.crv
    m[-2] = key.pub
    if private and key.priv is not None:
      m[-4] = key.priv
    return m

  def decode_key(self, m):
    if m.get(-1) != self.crv:
      raise CoseError(f'{self.name} requires crv {self.crv}')
    k = super().decode_key(m)
    k.pub = m[-2]
    k.priv = m.get(-4)
    return k


class _Ec2Shape(Alg):
  kty = KTY_EC2
  crv = CRV_P256

  @property
  def _size(self):
    return _EC_CURVES[self.crv][1]

  def encode_key(self, key, private):
    m = super().encode_key(key, private)
    n = self._size
    m[-1] = self.crv
    m[-2] = key.pub[:n]
    m[-3] = key.pub[n:]
    if private and key.priv is not None:
      m[-4] = key.priv
    return m

  def decode_key(self, m):
    if m.get(-1) != self.crv:
      raise CoseError(f'{self.name} requires crv {self.crv}')
    k = super().decode_key(m)
    k.pub = m[-2] + m[-3]
    k.priv = m.get(-4)
    return k

  def _generate_ec(self):
    curve, n, _ = _EC_CURVES[self.crv]
    prv = ec.generate_private_key(curve)
    nums = prv.private_numbers()
    pub = nums.public_numbers.x.to_bytes(n, 'big') + nums.public_numbers.y.to_bytes(n, 'big')
    return Key(self.id, pub, nums.private_value.to_bytes(n, 'big'))

  def public_from_private(self, priv):
    curve, n, _ = _EC_CURVES[self.crv]
    nums = ec.derive_private_key(int.from_bytes(priv, 'big'), curve).public_key().public_numbers()
    return nums.x.to_bytes(n, 'big') + nums.y.to_bytes(n, 'big')

  def _ec_private(self, key):
    if 'prv' not in key._cache:
      curve = _EC_CURVES[self.crv][0]
      key._cache['prv'] = ec.derive_private_key(int.from_bytes(key.priv, 'big'), curve)
    return key._cache['prv']

  def _ec_public(self, key):
    if 'pub' not in key._cache:
      curve = _EC_CURVES[self.crv][0]
      key._cache['pub'] = ec.EllipticCurvePublicKey.from_encoded_point(curve, b'\x04' + key.pub)
    return key._cache['pub']


# --- signature algorithms ---


class SignAlg(Alg):
  def generate(self) -> Key:
    raise NotImplementedError

  def sign(self, key: Key, data: bytes) -> bytes:
    raise NotImplementedError

  def verify(self, key: Key, sig: bytes, data: bytes) -> bool:
    raise NotImplementedError


class Ed25519Alg(_OkpShape, SignAlg):
  crv = CRV_ED25519

  def __init__(self, id, name):
    self.id = id
    self.name = name

  def generate(self):
    prv = ed25519.Ed25519PrivateKey.generate()
    return Key(self.id, prv.public_key().public_bytes_raw(), prv.private_bytes_raw())

  def public_from_private(self, priv):
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()

  def sign(self, key, data):
    return ed25519.Ed25519PrivateKey.from_private_bytes(key.priv).sign(data)

  def verify(self, key, sig, data):
    try:
      ed25519.Ed25519PublicKey.from_public_bytes(key.pub).verify(sig, data)
      return True
    except InvalidSignature:
      return False


class EcdsaAlg(_Ec2Shape, SignAlg):
  def __init__(self, id, name, crv):
    self.id = id
    self.name = name
    self.crv = crv

  def generate(self):
    return self._generate_ec()

  def sign(self, key, data):
    n, h = _EC_CURVES[self.crv][1:]
    r, s = decode_dss_signature(self._ec_private(key).sign(data, ec.ECDSA(h)))
    return r.to_bytes(n, 'big') + s.to_bytes(n, 'big')

  def verify(self, key, sig, data):
    n, h = _EC_CURVES[self.crv][1:]
    if len(sig) != n * 2:
      return False
    der = encode_dss_signature(int.from_bytes(sig[:n], 'big'), int.from_bytes(sig[n:], 'big'))
    try:
      self._ec_public(key).verify(der, data, ec.ECDSA(h))
      return True
    except InvalidSignature:
      return False


class MlDsaAlg(_AkpShape, SignAlg):
  """ML-DSA (FIPS 204), pure mode, empty context. priv is the 32-byte seed."""

  def __init__(self, id, name, prv_cls, pub_cls):
    self.id = id
    self.name = name
    self._prv_cls = prv_cls
    self._pub_cls = pub_cls

  def generate(self):
    prv = self._prv_cls.generate()
    return Key(self.id, prv.public_key().public_bytes_raw(), prv.private_bytes_raw())

  def public_from_private(self, priv):
    return self._prv_cls.from_seed_bytes(priv).public_key().public_bytes_raw()

  def sign(self, key, data):
    if 'prv' not in key._cache:
      key._cache['prv'] = self._prv_cls.from_seed_bytes(key.priv)
    return key._cache['prv'].sign(data)

  def verify(self, key, sig, data):
    if 'pub' not in key._cache:
      key._cache['pub'] = self._pub_cls.from_public_bytes(key.pub)
    try:
      key._cache['pub'].verify(sig, data)
      return True
    except InvalidSignature:
      return False


# --- HPKE (key encapsulation for COSE_Encrypt0 / COSE_Recipient) ---


class HpkeAlg(Alg):
  """
  COSE-HPKE ciphersuite. `integrated` suites are used directly in
  COSE_Encrypt0; key-encryption ("-KE") suites wrap a CEK in a COSE_Recipient.
  A KEM key advertised with either variant may be used with its sibling.
  """

  def __init__(self, id, name, kem, kdf, aead, integrated, sibling):
    self.id = id
    self.name = name
    self.suite = hpke.Suite(kem, kdf, aead)
    self.enc_length = kem.enc_length()
    self.integrated = integrated
    self.sibling = sibling

  def seal(self, key: Key, plaintext: bytes, info: bytes = b'', aad: bytes = b''):
    pk = self._public(key)
    if aad:
      out = _hpke_seal_aad(self.suite, plaintext, pk, info, aad)
    else:
      out = self.suite.encrypt(plaintext, pk, info=info)
    return out[: self.enc_length], out[self.enc_length :]

  def open(self, key: Key, enc: bytes, ct: bytes, info: bytes = b'', aad: bytes = b''):
    sk = self._private(key)
    if aad:
      return _hpke_open_aad(self.suite, enc + ct, sk, info, aad)
    return self.suite.decrypt(enc + ct, sk, info=info)


class HpkeOkpAlg(_OkpShape, HpkeAlg):
  crv = CRV_X25519

  def generate(self):
    prv = x25519.X25519PrivateKey.generate()
    return Key(self.id, prv.public_key().public_bytes_raw(), prv.private_bytes_raw())

  def public_from_private(self, priv):
    return x25519.X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()

  def _public(self, key):
    return x25519.X25519PublicKey.from_public_bytes(key.pub)

  def _private(self, key):
    return x25519.X25519PrivateKey.from_private_bytes(key.priv)


class HpkeEc2Alg(_Ec2Shape, HpkeAlg):
  def __init__(self, crv, *args):
    self.crv = crv
    HpkeAlg.__init__(self, *args)

  def generate(self):
    return self._generate_ec()

  def _public(self, key):
    return self._ec_public(key)

  def _private(self, key):
    return self._ec_private(key)


def xwing_expand(seed: bytes):
  """X-Wing expandDecapsulationKey (draft-connolly-cfrg-xwing-kem 5.2)."""
  if len(seed) != 32:
    raise CoseError('X-Wing seed must be 32 bytes')
  ex = hashlib.shake_256(seed).digest(96)
  sk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(ex[:64])
  sk_x = x25519.X25519PrivateKey.from_private_bytes(ex[64:96])
  pub = sk_m.public_key().public_bytes_raw() + sk_x.public_key().public_bytes_raw()
  return hpke.MLKEM768X25519PrivateKey(sk_m, sk_x), pub


class HpkeXWingAlg(_AkpShape, HpkeAlg):
  """MLKEM768-X25519 (X-Wing). pub = pk_M || pk_X (1216 bytes), priv = 32-byte seed."""

  def generate(self):
    seed = os.urandom(32)
    return Key(self.id, xwing_expand(seed)[1], seed)

  def public_from_private(self, priv):
    return xwing_expand(priv)[1]

  def _public(self, key):
    return hpke.MLKEM768X25519PublicKey(
      mlkem.MLKEM768PublicKey.from_public_bytes(key.pub[:1184]),
      x25519.X25519PublicKey.from_public_bytes(key.pub[1184:]),
    )

  def _private(self, key):
    if 'prv' not in key._cache:
      key._cache['prv'] = xwing_expand(key.priv)[0]
    return key._cache['prv']


class HpkeMlKemAlg(_AkpShape, HpkeAlg):
  """Pure ML-KEM. priv = 64-byte FIPS 203 seed (d || z)."""

  def __init__(self, prv_cls, pub_cls, *args):
    self._prv_cls = prv_cls
    self._pub_cls = pub_cls
    HpkeAlg.__init__(self, *args)

  def generate(self):
    prv = self._prv_cls.generate()
    return Key(self.id, prv.public_key().public_bytes_raw(), prv.private_bytes_raw())

  def public_from_private(self, priv):
    return self._prv_cls.from_seed_bytes(priv).public_key().public_bytes_raw()

  def _public(self, key):
    return self._pub_cls.from_public_bytes(key.pub)

  def _private(self, key):
    return self._prv_cls.from_seed_bytes(key.priv)


def _hpke_seal_aad(suite, plaintext, pk, info, aad):
  # COSE-HPKE integrated mode needs HPKE's aad input (the Enc_structure).
  # pyca/cryptography only exposes it through this helper so far.
  from cryptography.hazmat.bindings._rust import openssl as rust

  return rust.hpke._encrypt_with_aad(suite, plaintext, pk, info=info, aad=aad)


def _hpke_open_aad(suite, ciphertext, sk, info, aad):
  from cryptography.hazmat.bindings._rust import openssl as rust

  return rust.hpke._decrypt_with_aad(suite, ciphertext, sk, info=info, aad=aad)


# --- symmetric: content encryption and MAC ---


class _SymShape(Alg):
  kty = KTY_SYMMETRIC
  key_size = 32

  def encode_key(self, key, private):
    m = super().encode_key(key, private)
    m[-1] = key.priv
    return m

  def decode_key(self, m):
    k = super().decode_key(m)
    k.priv = m[-1]
    return k

  def generate(self):
    return Key(self.id, priv=os.urandom(self.key_size))

  def public_from_private(self, priv):
    return b''


class AeadAlg(_SymShape):
  iv_size = 12

  def __init__(self, id, name, cls, key_size):
    self.id = id
    self.name = name
    self._cls = cls
    self.key_size = key_size

  def encrypt(self, k: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return self._cls(k).encrypt(iv, plaintext, aad)

  def decrypt(self, k: bytes, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return self._cls(k).decrypt(iv, ciphertext, aad)


class HmacAlg(_SymShape):
  def __init__(self, id, name, digest, key_size, tag_size):
    self.id = id
    self.name = name
    self.digest = digest
    self.key_size = key_size
    self.tag_size = tag_size

  def tag(self, k: bytes, data: bytes) -> bytes:
    return _hmac.new(k, data, self.digest).digest()[: self.tag_size]

  def verify(self, k: bytes, tag: bytes, data: bytes) -> bool:
    return _hmac.compare_digest(self.tag(k, data), tag)


# --- registry ---

# signatures
ESP256 = -9
ES256 = -7
ED25519 = -19
EDDSA = -8
ML_DSA_44 = -48
ML_DSA_65 = -49
ML_DSA_87 = -50

# content encryption
A128GCM = 1
A192GCM = 2
A256GCM = 3
CHACHA20_POLY1305 = 24

# MAC
HMAC_256_64 = 4
HMAC_256_256 = 5
HMAC_384_384 = 6
HMAC_512_512 = 7

# HPKE integrated / key-encryption pairs
HPKE_0, HPKE_0_KE = 35, 46
HPKE_1, HPKE_1_KE = 37, 47
HPKE_2, HPKE_2_KE = 39, 48
HPKE_3, HPKE_3_KE = 41, 49
HPKE_4, HPKE_4_KE = 42, 50
HPKE_7, HPKE_7_KE = 45, 53
HPKE_9, HPKE_9_KE = 56, 57
HPKE_12, HPKE_12_KE = 62, 63
HPKE_13, HPKE_13_KE = 64, 65

_K = hpke.KEM
_D = hpke.KDF
_A = hpke.AEAD

ALGS: dict[int, Alg] = {}


def _reg(alg):
  ALGS[alg.id] = alg


_reg(Ed25519Alg(ED25519, 'Ed25519'))
_reg(Ed25519Alg(EDDSA, 'EdDSA'))
_reg(EcdsaAlg(ESP256, 'ESP256', CRV_P256))
_reg(EcdsaAlg(ES256, 'ES256', CRV_P256))
_reg(MlDsaAlg(ML_DSA_44, 'ML-DSA-44', mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey))
_reg(MlDsaAlg(ML_DSA_65, 'ML-DSA-65', mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey))
_reg(MlDsaAlg(ML_DSA_87, 'ML-DSA-87', mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey))

_reg(AeadAlg(A128GCM, 'A128GCM', AESGCM, 16))
_reg(AeadAlg(A192GCM, 'A192GCM', AESGCM, 24))
_reg(AeadAlg(A256GCM, 'A256GCM', AESGCM, 32))
_reg(AeadAlg(CHACHA20_POLY1305, 'ChaCha20/Poly1305', ChaCha20Poly1305, 32))

_reg(HmacAlg(HMAC_256_64, 'HMAC 256/64', 'sha256', 32, 8))
_reg(HmacAlg(HMAC_256_256, 'HMAC 256/256', 'sha256', 32, 32))
_reg(HmacAlg(HMAC_384_384, 'HMAC 384/384', 'sha384', 48, 48))
_reg(HmacAlg(HMAC_512_512, 'HMAC 512/512', 'sha512', 64, 64))

for _i, _ke, _n, _crv, _kem, _kdf, _aead in [
  (HPKE_0, HPKE_0_KE, 'HPKE-0', CRV_P256, _K.P256, _D.HKDF_SHA256, _A.AES_128_GCM),
  (HPKE_1, HPKE_1_KE, 'HPKE-1', CRV_P384, _K.P384, _D.HKDF_SHA384, _A.AES_256_GCM),
  (HPKE_2, HPKE_2_KE, 'HPKE-2', CRV_P521, _K.P521, _D.HKDF_SHA512, _A.AES_256_GCM),
  (HPKE_7, HPKE_7_KE, 'HPKE-7', CRV_P256, _K.P256, _D.HKDF_SHA256, _A.AES_256_GCM),
]:
  _reg(HpkeEc2Alg(_crv, _i, _n, _kem, _kdf, _aead, True, _ke))
  _reg(HpkeEc2Alg(_crv, _ke, _n + '-KE', _kem, _kdf, _aead, False, _i))

for _i, _ke, _n, _aead in [
  (HPKE_3, HPKE_3_KE, 'HPKE-3', _A.AES_128_GCM),
  (HPKE_4, HPKE_4_KE, 'HPKE-4', _A.CHACHA20_POLY1305),
]:
  _reg(HpkeOkpAlg(_i, _n, _K.X25519, _D.HKDF_SHA256, _aead, True, _ke))
  _reg(HpkeOkpAlg(_ke, _n + '-KE', _K.X25519, _D.HKDF_SHA256, _aead, False, _i))

_reg(
  HpkeXWingAlg(HPKE_9, 'HPKE-9', _K.MLKEM768_X25519, _D.SHAKE256, _A.AES_256_GCM, True, HPKE_9_KE)
)
_reg(
  HpkeXWingAlg(
    HPKE_9_KE, 'HPKE-9-KE', _K.MLKEM768_X25519, _D.SHAKE256, _A.AES_256_GCM, False, HPKE_9
  )
)

for _i, _ke, _n, _kem, _prv, _pub in [
  (HPKE_12, HPKE_12_KE, 'HPKE-12', _K.MLKEM768, mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey),
  (
    HPKE_13,
    HPKE_13_KE,
    'HPKE-13',
    _K.MLKEM1024,
    mlkem.MLKEM1024PrivateKey,
    mlkem.MLKEM1024PublicKey,
  ),
]:
  _reg(HpkeMlKemAlg(_prv, _pub, _i, _n, _kem, _D.SHAKE256, _A.AES_256_GCM, True, _ke))
  _reg(HpkeMlKemAlg(_prv, _pub, _ke, _n + '-KE', _kem, _D.SHAKE256, _A.AES_256_GCM, False, _i))


# algorithms that stay secure against a quantum attacker
QUANTUM_SAFE_SIGN = {ML_DSA_44, ML_DSA_65, ML_DSA_87}
QUANTUM_SAFE_KEM = {HPKE_9, HPKE_9_KE, HPKE_12, HPKE_12_KE, HPKE_13, HPKE_13_KE}


def get_alg(alg_id: int) -> Alg:
  try:
    return ALGS[alg_id]
  except KeyError:
    raise CoseError(f'unsupported COSE algorithm {alg_id}') from None


def hpke_variant(key: Key, integrated: bool) -> HpkeAlg:
  """The HPKE suite to use with `key` for integrated or key-encryption mode."""
  a = key.algorithm
  if not isinstance(a, HpkeAlg):
    raise CoseError(f'{a.name} is not an HPKE algorithm')
  return a if a.integrated == integrated else get_alg(a.sibling)
