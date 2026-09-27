"""
Cross-check our COSE encoding against independent implementations:
pycose (Sign1, Sign, Mac0, Encrypt0) and python-cwt (COSE-HPKE).
Only pre-quantum algorithms can be checked this way; neither library has ML-DSA or X-Wing.
"""

import pytest
from cwt import COSE, COSEKey, Recipient
from pycose.algorithms import A256GCM as P_A256GCM
from pycose.algorithms import HMAC256, EdDSA, Es256
from pycose.headers import IV, KID, Algorithm
from pycose.keys import EC2Key, OKPKey, SymmetricKey
from pycose.messages import CoseMessage, Enc0Message, Mac0Message, Sign1Message, SignMessage
from pycose.messages.signer import CoseSignature

from cosiechat import cose
from cosiechat import keys as K


def _pycose_okp(k, private=True):
  if private:
    return OKPKey(crv='ED25519', x=k.pub, d=k.priv)
  return OKPKey(crv='ED25519', x=k.pub)


def _pycose_ec2(k):
  return EC2Key(crv='P_256', x=k.pub[:32], y=k.pub[32:], d=k.priv)


def test_sign1_ours_to_pycose():
  k = K.Key.generate(K.EDDSA, kid=b'alice')
  msg = CoseMessage.decode(cose.sign1(b'hello', k))
  msg.key = _pycose_okp(k, private=False)
  assert msg.verify_signature()
  assert msg.payload == b'hello'


def test_sign1_pycose_to_ours():
  k = K.Key.generate(K.EDDSA)
  msg = Sign1Message(phdr={Algorithm: EdDSA}, uhdr={KID: b'bob'}, payload=b'from pycose')
  msg.key = _pycose_okp(k)
  assert cose.verify_sign1(msg.encode(), k.public()) == b'from pycose'


def test_sign1_es256_both_ways():
  k = K.Key.generate(K.ES256)
  msg = CoseMessage.decode(cose.sign1(b'p256', k))
  msg.key = _pycose_ec2(k)
  assert msg.verify_signature()
  theirs = Sign1Message(phdr={Algorithm: Es256}, payload=b'p256 back')
  theirs.key = _pycose_ec2(k)
  assert cose.verify_sign1(theirs.encode(), k.public()) == b'p256 back'


def test_sign_multi_both_ways():
  a = K.Key.generate(K.EDDSA, kid=b'a')
  b = K.Key.generate(K.ES256, kid=b'b')
  msg = CoseMessage.decode(cose.sign(b'co-signed', [a, b]))
  msg.signers[0].key = _pycose_okp(a, private=False)
  msg.signers[1].key = _pycose_ec2(b)
  assert all(s.verify_signature() for s in msg.signers)

  s1 = CoseSignature(phdr={Algorithm: EdDSA}, uhdr={KID: b'a'}, key=_pycose_okp(a))
  s2 = CoseSignature(phdr={Algorithm: Es256}, uhdr={KID: b'b'}, key=_pycose_ec2(b))
  theirs = SignMessage(phdr={}, payload=b'pycose co-signed', signers=[s1, s2])
  assert cose.verify_sign(theirs.encode(), [a.public(), b.public()]) == b'pycose co-signed'


def test_mac0_both_ways():
  k = K.Key.generate(K.HMAC_256_256)
  msg = CoseMessage.decode(cose.mac0(b'auth me', k))
  msg.key = SymmetricKey(k=k.priv)
  assert msg.verify_tag()
  theirs = Mac0Message(phdr={Algorithm: HMAC256}, payload=b'pycose mac')
  theirs.key = SymmetricKey(k=k.priv)
  assert cose.verify_mac0(theirs.encode(), k) == b'pycose mac'


def test_encrypt0_symmetric_both_ways():
  k = K.Key.generate(K.A256GCM)
  msg = CoseMessage.decode(cose.encrypt0(b'shared secret', k))
  msg.key = SymmetricKey(k=k.priv)
  assert msg.decrypt() == b'shared secret'
  theirs = Enc0Message(phdr={Algorithm: P_A256GCM}, uhdr={IV: b'\x01' * 12}, payload=b'pycose enc')
  theirs.key = SymmetricKey(k=k.priv)
  assert cose.decrypt0(theirs.encode(), k) == b'pycose enc'


def _cwt_x25519(k, alg, private=True):
  m = {1: 1, 3: alg, -1: 4, -2: k.pub}
  if private:
    m[-4] = k.priv
  return COSEKey.new(m)


@pytest.mark.parametrize('alg', [K.HPKE_3, K.HPKE_4])
def test_hpke_encrypt0_both_ways(alg):
  k = K.Key.generate(alg)
  ctx = COSE.new()
  assert (
    ctx.decode(cose.encrypt0(b'hpke integrated', k.public()), _cwt_x25519(k, alg))
    == b'hpke integrated'
  )
  theirs = ctx.encode(b'cwt integrated', _cwt_x25519(k, alg, private=False), protected={1: alg})
  assert cose.decrypt0(theirs, k) == b'cwt integrated'


@pytest.mark.parametrize('alg', [K.HPKE_3_KE, K.HPKE_4_KE])
def test_hpke_encrypt_recipients_both_ways(alg):
  ks = [K.Key.generate(alg) for _ in range(2)]
  ours = cose.encrypt(b'to many', [k.public() for k in ks], alg=K.A256GCM)
  ctx = COSE.new()
  for k in ks:
    assert ctx.decode(ours, _cwt_x25519(k, alg)) == b'to many'

  # python-cwt 3.3 reuses one "ek" across recipients (its bug), so only one recipient that way
  r = Recipient.new(protected={1: alg}, recipient_key=_cwt_x25519(ks[0], alg, private=False))
  cek = COSEKey.generate_symmetric_key(alg='A256GCM')
  theirs = ctx.encode(b'cwt to one', cek, protected={1: K.A256GCM}, recipients=[r])
  assert cose.decrypt(theirs, ks[0]) == b'cwt to one'
