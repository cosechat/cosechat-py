"""Ratchets: the mechanism (no clocks, no storage), announces, and the forward secrecy they buy."""

import pytest
from test_node import inbox, make, run, until

from cosiechat import cose
from cosiechat import keys as K
from cosiechat import message as M
from cosiechat.identity import Identity
from cosiechat.keys import CoseError
from cosiechat.packet import ANNOUNCE, Packet
from cosiechat.ratchet import MemoryRatchets, check_ratchet, new_ratchet, ratchet_id
from cosiechat.roads.memory import MemoryHub


def store(alg=K.HPKE_9, **kw):
  return MemoryRatchets(alg, **kw)


def book(*ids):
  return {i.address: i.public() for i in ids}.get


# --- provider ---


def test_memory_ratchets_only_change_when_told():
  s = store()
  first = s.current()
  assert s.current() is first
  second = s.rotate()
  assert s.current() is second and s.keys() == [second, first]
  assert first.kid == ratchet_id(first.pub)
  s.discard(first.kid)
  assert s.get(first.kid) is None and s.keys() == [second]


def test_memory_ratchets_optional_count_cap():
  s = store(keep=3)
  made = [s.rotate() for _ in range(5)]
  assert s.keys() == made[::-1][:3]


def test_ratchet_must_be_hpke_with_its_own_id():
  check_ratchet(new_ratchet(K.HPKE_9).public())
  bad = new_ratchet(K.HPKE_9).public()
  bad.kid = b'\x00' * 8
  with pytest.raises(CoseError):
    check_ratchet(bad)
  sig = K.Key.generate(K.ED25519)
  sig.kid = ratchet_id(sig.pub)
  with pytest.raises(CoseError):
    check_ratchet(sig)


# --- announces ---


@pytest.mark.parametrize('suite', ['pq', 'hybrid', 'prequantum'])
def test_announce_carries_signed_ratchet(suite):
  ident = Identity.generate(suite)
  s = store(ident.kem_alg)
  r = s.current()
  ann = M.verify_announce(M.make_announce(ident, r), ident.address)
  assert ann.ratchet.pub == r.pub and ann.ratchet.kid == r.kid
  assert not ann.ratchet.has_private


# --- messages ---


def test_sealed_to_ratchet_names_it_and_opens():
  a, b = Identity.generate(), Identity.generate()
  rs = store()
  r = rs.current()
  sealed, sent = M.seal(a, [b.public()], 'fs', ratchets={b.address: r.public()})
  assert cose.decode(sealed).kid == r.kid
  got = M.unseal(b, sealed, book(a), ratchets=rs)
  assert got.id == sent.id and got.ratchet_id == r.kid


def test_forward_secrecy_once_ratchet_is_discarded():
  """Steal everything b has after it discarded the ratchet: the old message stays sealed."""
  a, b = Identity.generate(), Identity.generate()
  rs = store()
  r = rs.current()
  sealed, _ = M.seal(a, [b.public()], 'gone for good', ratchets={b.address: r.public()})
  assert M.unseal(b, sealed, book(a), ratchets=rs).content == 'gone for good'
  rs.discard(r.kid)
  stolen = Identity.from_bytes(b.to_bytes())
  with pytest.raises(CoseError):
    M.unseal(stolen, sealed, book(a), ratchets=rs)


def test_seal_each_gives_each_recipient_its_own_envelope():
  a = Identity.generate()
  bs = [Identity.generate() for _ in range(2)]
  stores = [store() for _ in bs]
  rks = {b.address: s.current().public() for b, s in zip(bs, stores, strict=True)}
  sealed, sent = M.seal_each(a, [b.public() for b in bs], 'hi both', ratchets=rks)
  for b, s in zip(bs, stores, strict=True):
    env = cose.decode(sealed[b.address])
    assert env.kind == 'Encrypt0' and env.kid == rks[b.address].kid
    got = M.unseal(b, sealed[b.address], book(a), ratchets=s)
    assert got.id == sent.id and set(got.recipients) == {x.address for x in bs}


def test_shared_encrypt_with_ratchets_names_nobody():
  a = Identity.generate()
  bs = [Identity.generate() for _ in range(2)]
  stores = [store() for _ in bs]
  rks = {b.address: s.current().public() for b, s in zip(bs, stores, strict=True)}
  sealed, _ = M.seal(a, [b.public() for b in bs], 'shared', ratchets=rks)
  env = cose.decode(sealed)
  assert env.kind == 'Encrypt' and all(layer.kid is None for layer, _ in env.recipients)
  for b, s in zip(bs, stores, strict=True):
    assert M.unseal(b, sealed, book(a), ratchets=s).ratchet_id is not None


# --- nodes ---


def test_nodes_use_ratchets_by_default():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address) and a.address in b.paths)
      await a.send(b.address, 'secret')
      await until(lambda: box)
    assert box[0].ratchet_id == a.peer_ratchet(b.address).kid

  run(main())


def test_rotation_new_ratchet_used_old_messages_still_open():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address) and a.address in b.paths)
      first = a.peer_ratchet(b.address).kid
      await a.send(b.address, 'one')
      await b.rotate_ratchet()  # the application decides when; this announces too
      await until(lambda: a.peer_ratchet(b.address).kid != first)
      await a.send(b.address, 'two')
      await until(lambda: len(box) == 2)
    assert [m.content for m in box] == ['one', 'two']
    assert box[0].ratchet_id == first != box[1].ratchet_id
    assert len(b.ratchets) == 2

  run(main())


def test_replayed_old_announce_cannot_bring_back_old_ratchet():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a, b:
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address))
      old = a.announces[b.address][0]
      old_kid = a.peer_ratchet(b.address).kid
      await b.rotate_ratchet()
      await until(lambda: a.peer_ratchet(b.address).kid != old_kid)
      a._seen.clear()  # get the old announce past duplicate suppression
      a._handle_announce(a.lanes[0], Packet(ANNOUNCE, 0, b.address, None, old))
      assert a.peer_ratchet(b.address).kid != old_kid

  run(main())


def test_announce_sequence_is_not_checked_against_any_clock():
  """A peer with no RTC (sequence 1) or a clock far ahead is accepted: only order matters."""

  async def main():
    hub = MemoryHub()
    a = make(hub)
    async with a:
      for seq in (1, 10**15):
        peer = Identity.generate()
        data = M.make_announce(peer, new_ratchet(peer.kem_alg), sequence=seq)
        a._handle_announce(a.lanes[0], Packet(ANNOUNCE, 0, peer.address, None, data))
        assert a.peer_ratchet(peer.address) is not None

  run(main())


def test_cannot_message_a_peer_that_never_announced():
  """Identities have no KEM key: without an announce (and its ratchet) there is nothing to seal to."""

  async def main():
    hub = MemoryHub()
    a = make(hub)
    stranger = Identity.generate()  # known out of band, never announced
    async with a:
      with pytest.raises(LookupError, match='announce'):
        await a.send(stranger.public(), 'x', timeout=0.2)

  run(main())
