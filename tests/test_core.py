"""Core data library: COSE primitives, identities, sealed messages, announces, packets."""

from pathlib import Path

import pytest

from cosiechat import cbor, cose
from cosiechat import keys as K
from cosiechat import message as M
from cosiechat import packet as P
from cosiechat.identity import SUITES, Identity, address_of, signer_of
from cosiechat.keys import CoseError, Key
from cosiechat.ratchet import new_ratchet

SIGN_ALGS = [K.ED25519, K.EDDSA, K.ESP256, K.ES256, K.ML_DSA_44, K.ML_DSA_65, K.ML_DSA_87]
HPKE_ALGS = [
  K.HPKE_0,
  K.HPKE_1,
  K.HPKE_2,
  K.HPKE_3,
  K.HPKE_4,
  K.HPKE_7,
  K.HPKE_9,
  K.HPKE_12,
  K.HPKE_13,
]
MAC_ALGS = [K.HMAC_256_64, K.HMAC_256_256, K.HMAC_384_384, K.HMAC_512_512]
AEAD_ALGS = [K.A128GCM, K.A192GCM, K.A256GCM, K.CHACHA20_POLY1305]


def flip(data: bytes, pos: int = -3) -> bytes:
  b = bytearray(data)
  b[pos] ^= 1
  return bytes(b)


# --- sign ---


@pytest.mark.parametrize('alg', SIGN_ALGS)
def test_sign1(alg):
  k = Key.generate(alg, kid=b'k1')
  s = cose.sign1(b'payload', k, external_aad=b'ctx')
  assert cose.verify_sign1(s, k.public(), external_aad=b'ctx') == b'payload'
  with pytest.raises(CoseError):
    cose.verify_sign1(s, k.public())
  with pytest.raises(CoseError):
    cose.verify_sign1(flip(s), k.public(), external_aad=b'ctx')
  with pytest.raises(CoseError):
    cose.verify_sign1(s, Key.generate(alg).public(), external_aad=b'ctx')


def test_sign_multi_requires_every_key():
  a, b = Key.generate(K.ED25519), Key.generate(K.ML_DSA_65)
  s = cose.sign(b'both', [a, b])
  assert cose.verify_sign(s, [a.public(), b.public()]) == b'both'
  with pytest.raises(CoseError):
    cose.verify_sign(s, [a.public(), Key.generate(K.ML_DSA_65).public()])
  only_a = cose.sign(b'both', [a])
  with pytest.raises(CoseError):
    cose.verify_sign(only_a, [a.public(), b.public()])


# --- auth ---


@pytest.mark.parametrize('alg', MAC_ALGS)
def test_mac0(alg):
  k = Key.generate(alg)
  m = cose.mac0(b'data', k)
  assert cose.verify_mac0(m, k) == b'data'
  assert len(cose.decode(m).signature) == K.get_alg(alg).tag_size
  with pytest.raises(CoseError):
    cose.verify_mac0(flip(m, 12), k)
  with pytest.raises(CoseError):
    cose.verify_mac0(m, Key.generate(alg))


@pytest.mark.parametrize('alg', [K.HPKE_4, K.HPKE_9])
def test_mac_multi_recipient(alg):
  rs = [Key.generate(alg) for _ in range(3)]
  m = cose.mac(b'for all of you', [r.public() for r in rs[:2]])
  for r in rs[:2]:
    assert cose.verify_mac(m, r) == b'for all of you'
  with pytest.raises(CoseError):
    cose.verify_mac(m, rs[2])


# --- encrypt ---


@pytest.mark.parametrize('alg', AEAD_ALGS)
def test_encrypt0_symmetric(alg):
  k = Key.generate(alg, kid=b'group')
  e = cose.encrypt0(b'secret', k, external_aad=b'x', include_kid=True)
  assert cose.decode(e).kid == b'group'
  assert cose.decrypt0(e, k, external_aad=b'x') == b'secret'
  with pytest.raises(CoseError):
    cose.decrypt0(e, k)
  with pytest.raises(CoseError):
    cose.decrypt0(flip(e), k, external_aad=b'x')


@pytest.mark.parametrize('alg', HPKE_ALGS)
def test_encrypt0_hpke(alg):
  k = Key.generate(alg)
  e = cose.encrypt0(b'for you only', k.public())
  msg = cose.decode(e)
  assert msg.alg == alg and msg.kid is None
  assert cose.decrypt0(e, k) == b'for you only'
  with pytest.raises(CoseError):
    cose.decrypt0(e, Key.generate(alg))
  with pytest.raises(CoseError):
    cose.decrypt0(flip(e), k)


@pytest.mark.parametrize('alg', HPKE_ALGS)
def test_encrypt_multi_recipient_hides_recipients(alg):
  rs = [Key.generate(alg, kid=bytes([i]) * 16) for i in range(3)]
  e = cose.encrypt(b'for two of you', [r.public() for r in rs[:2]])
  msg = cose.decode(e)
  assert msg.alg == K.A256GCM
  assert [layer.alg for layer, _ in msg.recipients] == [K.get_alg(alg).sibling] * 2
  assert all(layer.kid is None for layer, _ in msg.recipients)
  for r in rs[:2]:
    assert cose.decrypt(e, r) == b'for two of you'
  with pytest.raises(CoseError):
    cose.decrypt(e, rs[2])


def test_hpke_key_works_in_both_modes():
  k = Key.generate(K.HPKE_9_KE)
  assert cose.decrypt0(cose.encrypt0(b'a', k.public()), k) == b'a'
  assert cose.decrypt(cose.encrypt(b'b', [k.public()]), k) == b'b'


# --- keys ---


@pytest.mark.parametrize('alg', SIGN_ALGS + HPKE_ALGS + MAC_ALGS + AEAD_ALGS)
def test_cose_key_roundtrip(alg):
  k = Key.generate(alg, kid=b'id')
  back = Key.from_cose(cbor.loads(cbor.dumps(k.to_cose(private=True))))
  assert (back.alg, back.pub, back.priv, back.kid) == (k.alg, k.pub, k.priv, k.kid)
  if back.pub:
    assert Key.from_cose(k.to_cose()).priv is None


def test_xwing_matches_draft_test_vector():
  seed, pk = (Path(__file__).parent / 'vectors' / 'xwing-seed-pk.txt').read_text().split()
  assert K.xwing_expand(bytes.fromhex(seed))[1] == bytes.fromhex(pk)


def test_akp_key_shape():
  k = Key.generate(K.ML_DSA_65)
  m = k.to_cose(private=True)
  assert m[1] == K.KTY_AKP and m[3] == K.ML_DSA_65
  assert len(m[-1]) == 1952 and len(m[-2]) == 32


# --- identity ---


@pytest.mark.parametrize('suite', SUITES)
def test_identity_roundtrip_and_address(suite):
  i = Identity.generate(suite)
  assert i.has_private
  assert len(i.address) == 16
  assert i.address == address_of(i.public_bytes)
  priv = Identity.from_bytes(i.to_bytes())
  assert priv.address == i.address and priv.has_private
  pub = Identity.from_bytes(i.public_bytes)
  assert pub.address == i.address and not pub.has_private
  s = i.sign(b'me')
  assert signer_of(s) == i.address
  assert pub.verify(s) == b'me'


def test_identity_verify_rejects_other_signer():
  a, b = Identity.generate('prequantum'), Identity.generate('prequantum')
  with pytest.raises(CoseError):
    b.verify(a.sign(b'x'))


def test_hybrid_identity_uses_cose_sign():
  i = Identity.generate('hybrid')
  s = cose.decode(i.sign(b'x'))
  assert s.kind == 'Sign' and len(s.signers) == 2
  assert s.protected[cose.H_KID] == i.address


# --- messages ---


def _book(*ids):
  known = {i.address: i.public() for i in ids}
  return known.get


def _ratchets(*ids):
  """A ratchet each: {address: private ratchet}."""
  return {i.address: new_ratchet(i.kem_alg) for i in ids}


def _pub(rs):
  return {a: r.public() for a, r in rs.items()}


@pytest.mark.parametrize('suite', SUITES)
def test_seal_unseal(suite):
  a, b = Identity.generate(suite), Identity.generate(suite)
  rs = _ratchets(b)
  sealed, sent = M.seal(a, [b.public()], 'hello', title='t', fields={1: b'file'}, ratchets=_pub(rs))
  env = cose.decode(sealed)
  assert env.kind == 'Encrypt0' and env.kid == rs[b.address].kid
  got = M.unseal(b, sealed, _book(a), ratchets=[rs[b.address]])
  assert (got.sender, got.content, got.title, got.fields, got.id) == (
    a.address,
    'hello',
    't',
    {1: b'file'},
    sent.id,
  )
  assert got.recipients == [b.address] and got.ratchet_id == rs[b.address].kid


def test_sealing_needs_a_ratchet():
  a, b = Identity.generate(), Identity.generate()
  with pytest.raises(ValueError, match='ratchet'):
    M.seal(a, [b.public()], 'x')


def test_sealed_message_hides_sender():
  a, b = Identity.generate('prequantum'), Identity.generate('prequantum')
  sealed, _ = M.seal(a, [b.public()], 'x', ratchets=_pub(_ratchets(b)))
  assert a.address not in sealed
  assert a.public_bytes[-32:] not in sealed


def test_seal_to_many():
  a = Identity.generate()
  bs = [Identity.generate() for _ in range(3)]
  rs = _ratchets(*bs)
  sealed, sent = M.seal(a, [b.public() for b in bs], 'all', ratchets=_pub(rs))
  assert cose.decode(sealed).kind == 'Encrypt'
  for b in bs:
    assert M.unseal(b, sealed, _book(a), ratchets=[rs[b.address]]).id == sent.id


def test_unseal_rejects_non_recipient_and_unknown_sender():
  a, b, c = (Identity.generate('prequantum') for _ in range(3))
  rs = _ratchets(b, c)
  sealed, _ = M.seal(a, [b.public()], 'x', ratchets=_pub(rs))
  with pytest.raises(CoseError):
    M.unseal(c, sealed, _book(a), ratchets=[rs[c.address]])
  with pytest.raises(CoseError):
    M.unseal(b, sealed, _book(), ratchets=[rs[b.address]])


def test_forwarded_signature_is_not_addressed_to_new_recipient():
  """b decrypts a's message to b and re-encrypts it to c: c must not accept it as addressed to c."""
  a, b, c = (Identity.generate('prequantum') for _ in range(3))
  rs = _ratchets(b, c)
  sealed, _ = M.seal(a, [b.public()], 'for b', ratchets=_pub(rs))
  signed = cose.decrypt0(sealed, rs[b.address])
  resealed = M.envelope(signed, rs[c.address].public())
  with pytest.raises(CoseError, match='not addressed'):
    M.unseal(c, resealed, _book(a), ratchets=[rs[c.address]])


def test_attached_identity():
  a, b = Identity.generate(), Identity.generate()
  rs = _ratchets(b)
  sealed, _ = M.seal(a, [b.public()], 'x', attach_identity=True, ratchets=_pub(rs))
  assert M.unseal(b, sealed, _book(), ratchets=[rs[b.address]]).sender == a.address


def test_attached_identity_must_match_kid():
  a, b, mallory = (Identity.generate('prequantum') for _ in range(3))
  rs = _ratchets(b)
  body = cbor.dumps({M.M_TO: [b.address], M.M_TIME: 1, M.M_CONTENT: 'x'})
  # signed by mallory, claiming to be a, with mallory's keyset attached
  forged = cose.sign1(
    body,
    Key(mallory.sign_keys[0].alg, mallory.sign_keys[0].pub, mallory.sign_keys[0].priv, a.address),
    unprotected={M.H_IDENTITY: mallory.public_bytes},
    kid_protected=True,
  )
  with pytest.raises(CoseError):
    M.unseal(b, M.envelope(forged, rs[b.address].public()), _book(), ratchets=[rs[b.address]])


# --- announces ---


@pytest.mark.parametrize('suite', SUITES)
def test_announce(suite):
  i = Identity.generate(suite)
  r = new_ratchet(i.kem_alg)
  chain = M.HashChain(8)
  data = M.make_announce(i, r, {'name': 'alice'}, chain=chain)
  ann = M.verify_announce(data, i.address)
  assert ann.identity == i.public() and ann.app_data == {'name': 'alice'} and ann.full
  assert ann.ratchet.pub == r.pub and ann.chain == (chain.anchor, 8)


def test_short_announce_needs_the_keyset():
  i = Identity.generate()
  data = M.make_announce(i, new_ratchet(i.kem_alg), full=False)
  with pytest.raises(M.KeysetNeeded) as e:
    M.verify_announce(data, i.address)
  assert e.value.address == i.address
  ann = M.verify_announce(data, i.address, {i.address: i.public()}.get)
  assert not ann.full and ann.identity == i.public()
  # a keyset for another address does not verify it
  with pytest.raises(CoseError):
    M.verify_announce(data, i.address, lambda a: Identity.generate().public())


def test_short_announce_is_much_smaller():
  i = Identity.generate()
  r = new_ratchet(i.kem_alg)
  full = M.make_announce(i, r, sequence=1)
  short = M.make_announce(i, r, sequence=1, full=False)
  assert len(full) - len(short) >= len(i.public_bytes)


def test_announce_forgeries_rejected():
  real, mallory = Identity.generate('prequantum'), Identity.generate('prequantum')
  r = new_ratchet(real.kem_alg)
  with pytest.raises(CoseError):
    M.verify_announce(M.make_announce(mallory, r), real.address)
  # mallory signs a body containing real's keyset
  body = cbor.dumps(
    {M.A_IDENTITY: real.public_bytes, M.A_SEQUENCE: 1, M.A_RATCHET: r.public().to_cose()}
  )
  forged = cose.sign1(
    body,
    Key(
      mallory.sign_keys[0].alg, mallory.sign_keys[0].pub, mallory.sign_keys[0].priv, real.address
    ),
    kid_protected=True,
  )
  with pytest.raises(CoseError):
    M.verify_announce(forged, real.address)


def test_announce_needs_a_ratchet():
  i = Identity.generate('prequantum')
  body = cbor.dumps({M.A_IDENTITY: i.public_bytes, M.A_SEQUENCE: 1})
  with pytest.raises(CoseError, match='ratchet'):
    M.verify_announce(i.sign(body), i.address)


# --- keepalive chains ---


def test_hash_chain_links_back_to_the_anchor():
  c = M.HashChain(10)
  last_i, last_v = 0, c.anchor
  for _ in range(10):
    i, v = c.next()
    assert M.check_keepalive(last_i, last_v, i, v, 10)
    last_i, last_v = i, v
  assert c.next() is None


def test_keepalive_rejects_replay_forgery_and_big_jumps():
  c = M.HashChain(1000)
  i1, v1 = c.next()
  assert not M.check_keepalive(0, c.anchor, 0, c.anchor, 1000)  # replay of the anchor
  assert not M.check_keepalive(1, v1, 1, v1, 1000)  # replay of the last one
  assert not M.check_keepalive(1, v1, 2, b'\x00' * 32, 1000)  # made up
  assert M.check_keepalive(0, c.anchor, 5, c.value(5), 1000)  # missed a few: fine
  assert not M.check_keepalive(
    0, c.anchor, M.MAX_CHAIN_SKIP + 1, c.value(M.MAX_CHAIN_SKIP + 1), 1000
  )
  assert not M.check_keepalive(0, c.anchor, 1001, c.seed, 1000)  # past the end


def test_keepalive_packet_is_small():
  c = M.HashChain()
  p = P.Packet(P.KEEPALIVE, 0, b'\x01' * 16, None, M.keepalive_payload(1790000000000, *c.next()))
  assert len(p.encode()) < 80


# --- packets ---


def test_packet_roundtrip_and_hash_ignores_hops_and_via():
  p = P.Packet(P.DATA, 0, b'\x01' * 16, None, b'payload')
  q = P.decode(p.encode())
  assert q == p
  moved = P.Packet(P.DATA, 5, b'\x01' * 16, b'\x02' * 16, b'payload')
  assert moved.hash == p.hash


@pytest.mark.parametrize(
  'bad',
  [
    b'',
    b'\xff',
    cbor.dumps([0, 99, 0, b'x' * 16, None, b'']),  # unknown type
    cbor.dumps([0, 1, 0, b'short', None, b'']),  # bad address
    cbor.dumps([1, 1, 0, b'x' * 16, None, b'']),  # future protocol version
    cbor.dumps([1, 0, b'x' * 16, None, b'']),  # no version
  ],
)
def test_packet_decode_rejects_junk(bad):
  with pytest.raises(P.PacketError):
    P.decode(bad)


def test_fragment_reassemble_any_order_and_fit_mtu():
  frame = bytes(range(256)) * 30
  frags = P.fragment(frame, 200 - P.FRAGMENT_OVERHEAD)
  assert all(len(f) <= 200 for f in frags)
  r = P.Reassembler()
  items = [P.decode(f) for f in frags]
  out = [r.add('road', it) for it in reversed(items)]
  assert out[:-1] == [None] * (len(items) - 1)
  assert out[-1] == frame


def test_road_auth_modes():
  frame = P.Packet(P.ANNOUNCE, 0, b'\x07' * 16, None, b'x').encode()
  for mode in ('mac', 'encrypt'):
    auth = P.RoadAuth.from_passphrase('pw', mode)
    wrapped = auth.wrap(frame)
    assert auth.unwrap(wrapped) == frame
    assert len(wrapped) <= len(frame) + auth.overhead
    with pytest.raises(P.PacketError):
      P.RoadAuth.from_passphrase('other', mode).unwrap(wrapped)
  assert b'\x07' * 16 in P.RoadAuth.from_passphrase('pw', 'mac').wrap(frame)
  assert b'\x07' * 16 not in P.RoadAuth.from_passphrase('pw', 'encrypt').wrap(frame)


def test_seal_single_recipient_as_cose_encrypt():
  a, b = Identity.generate('prequantum'), Identity.generate('prequantum')
  rs = _ratchets(b)
  sealed, sent = M.seal(a, [b.public()], 'wolfcose friendly', integrated=False, ratchets=_pub(rs))
  env = cose.decode(sealed)
  assert env.kind == 'Encrypt'
  assert [layer.alg for layer, _ in env.recipients] == [K.HPKE_0_KE]
  assert M.unseal(b, sealed, _book(a), ratchets=[rs[b.address]]).id == sent.id


def test_quantum_safe_suites():
  assert Identity.generate('pq').quantum_safe
  assert Identity.generate('hybrid').quantum_safe
  assert not Identity.generate('prequantum').quantum_safe
  assert Identity.generate('pq').kem_alg == K.HPKE_9
  assert Identity.generate('prequantum').kem_alg == K.HPKE_0


def test_identity_is_signing_keys_only():
  i = Identity.generate('pq')
  assert len(cbor.loads(i.public_bytes)) == 1
  assert len(i.public_bytes) < 2000
