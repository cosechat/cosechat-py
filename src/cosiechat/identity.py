"""
Identities and addresses.

An identity is a COSE_KeySet: one or more signing keys followed by one HPKE
KEM key. Its address is the first 16 bytes of SHA-256 over the deterministic
CBOR encoding of the public keyset (keys carry no kid). Like a Reticulum
destination hash, the address is self-certifying: anyone holding the public
keyset can check it hashes to the address.
"""

import hashlib

from . import cbor, cose
from .keys import (
  ED25519,
  HPKE_0,
  HPKE_9,
  ML_DSA_65,
  QUANTUM_SAFE_KEM,
  QUANTUM_SAFE_SIGN,
  CoseError,
  HpkeAlg,
  Key,
  SignAlg,
)

ADDRESS_SIZE = 16

# name -> (signing algs, KEM alg)
SUITES = {
  # ML-DSA-65 signatures, X-Wing (ML-KEM-768 + X25519) encryption
  'pq': ([ML_DSA_65], HPKE_9),
  # Ed25519 AND ML-DSA-65 (COSE_Sign, both must verify), X-Wing encryption
  'hybrid': ([ED25519, ML_DSA_65], HPKE_9),
  # small enough for single LoRa frames; not quantum-safe. Everything here is
  # native to wolfCOSE (Ed25519, HPKE-0-KE, A256GCM)
  'prequantum': ([ED25519], HPKE_0),
}


def address_of(public_bytes: bytes) -> bytes:
  return hashlib.sha256(public_bytes).digest()[:ADDRESS_SIZE]


class Identity:
  def __init__(self, sign_keys: list[Key], kem_key: Key, public_bytes: bytes | None = None):
    if not sign_keys:
      raise CoseError('identity needs at least one signing key')
    for k in sign_keys:
      if not isinstance(k.algorithm, SignAlg):
        raise CoseError(f'{k.algorithm.name} is not a signature algorithm')
    if not isinstance(kem_key.algorithm, HpkeAlg):
      raise CoseError(f'{kem_key.algorithm.name} is not an HPKE algorithm')
    self._sign = [Key(k.alg, k.pub, k.priv) for k in sign_keys]
    self._kem = Key(kem_key.alg, kem_key.pub, kem_key.priv)
    # keep received bytes verbatim so the address never depends on re-encoding
    self.public_bytes = public_bytes or cbor.dumps([k.to_cose() for k in self._sign + [self._kem]])
    self.address = address_of(self.public_bytes)
    self.sign_keys = [Key(k.alg, k.pub, k.priv, self.address) for k in self._sign]
    self.kem_key = Key(self._kem.alg, self._kem.pub, self._kem.priv, self.address)

  def __repr__(self):
    algs = '+'.join(k.algorithm.name for k in self.sign_keys)
    return f'<Identity {self.address.hex()} {algs}/{self.kem_key.algorithm.name}>'

  def __eq__(self, other):
    return isinstance(other, Identity) and self.public_bytes == other.public_bytes

  def __hash__(self):
    return hash(self.address)

  @classmethod
  def generate(cls, suite: str = 'pq') -> 'Identity':
    sign_algs, kem_alg = SUITES[suite]
    return cls([Key.generate(a) for a in sign_algs], Key.generate(kem_alg))

  @property
  def quantum_safe(self) -> bool:
    """
    PQ KEM, and at least one PQ signing key. Verifiers require every signature
    in the keyset, so one PQ signature is enough to stop a quantum forger.
    """
    return self.kem_key.alg in QUANTUM_SAFE_KEM and any(
      k.alg in QUANTUM_SAFE_SIGN for k in self.sign_keys
    )

  @property
  def has_private(self) -> bool:
    return all(k.has_private for k in self.sign_keys) and self.kem_key.has_private

  def public(self) -> 'Identity':
    return Identity([k.public() for k in self._sign], self._kem.public())

  def to_bytes(self, private: bool = True) -> bytes:
    """COSE_KeySet. With private=True this holds secrets: keep it safe."""
    if not private:
      return self.public_bytes
    return cbor.dumps([k.to_cose(private=True) for k in self._sign + [self._kem]])

  @classmethod
  def from_bytes(cls, data: bytes) -> 'Identity':
    keys = [Key.from_cose(m) for m in cbor.loads(data)]
    if len(keys) < 2:
      raise CoseError('keyset needs signing keys and a KEM key')
    public = not any(k.has_private for k in keys)
    return cls(keys[:-1], keys[-1], data if public else None)

  # --- signing ---

  def sign(self, payload: bytes, unprotected: dict | None = None) -> bytes:
    """COSE_Sign1 (one key) or COSE_Sign (several), kid = our address in the protected header."""
    if len(self.sign_keys) == 1:
      return cose.sign1(payload, self.sign_keys[0], unprotected=unprotected, kid_protected=True)
    # signers carry no kid of their own: the body kid names the identity
    return cose.sign(
      payload, self._sign, protected={cose.H_KID: self.address}, unprotected=unprotected
    )

  def verify(self, signed) -> bytes:
    """Verify a Sign1/Sign made by this identity; returns the payload."""
    m = signed if isinstance(signed, cose.Message) else cose.decode(signed)
    if m.kind == 'Sign1':
      if len(self.sign_keys) != 1:
        raise CoseError('identity signs with several keys but message has one signature')
      return cose.verify_sign1(m, self.sign_keys[0])
    if m.kind == 'Sign':
      return cose.verify_sign(m, self.sign_keys)
    raise CoseError(f'COSE_{m.kind} is not a signature')


def signer_of(signed) -> bytes | None:
  """The address in the protected kid of a Sign1/Sign ("from" is in the signed header)."""
  m = signed if isinstance(signed, cose.Message) else cose.decode(signed)
  kid = m.protected.get(cose.H_KID)
  return kid if isinstance(kid, bytes) and len(kid) == ADDRESS_SIZE else None
