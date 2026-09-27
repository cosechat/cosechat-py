"""Links: one PQ handshake, then tiny symmetric messages, with per-link forward secrecy."""

import random

import pytest
from test_delivery import pair
from test_node import inbox, make, run, until

from cosiechat import cose
from cosiechat import link as L
from cosiechat.identity import Identity
from cosiechat.keys import HPKE_0, CoseError
from cosiechat.node import Node
from cosiechat.packet import LINK_ACCEPT, LINK_DATA, decode
from cosiechat.ratchet import MemoryRatchets
from cosiechat.roads.memory import MemoryHub


def handshake():
  a, b = Identity.generate(), Identity.generate()
  rb = MemoryRatchets(b.kem_alg)
  pending = L.make_request(a, b.public(), rb.current().public())
  book = {a.address: a.public()}.get
  peer, accept, kb = L.accept_request(b, pending.request, book, ratchets=rb)
  assert peer.address == a.address
  return a, b, rb, pending, accept, L.finish(pending, accept), kb


# --- data library ---


def test_handshake_and_both_directions():
  a, b, _, _, _, ka, kb = handshake()
  assert ka.link_id == kb.link_id and ka.send_key.priv == kb.recv_key.priv
  wire = L.seal(ka, L.message_body('hi b'))
  assert len(wire) < 100
  m, close = L.read_message(kb, b.address, L.unseal(kb, wire))
  assert (m.content, m.sender, m.link_id, close) == ('hi b', a.address, ka.link_id, False)
  back = L.seal(kb, L.message_body('hi a'))
  assert L.read_message(ka, a.address, L.unseal(ka, back))[0].content == 'hi a'


def test_directions_use_different_keys():
  _, b, _, _, _, ka, kb = handshake()
  wire = L.seal(ka, L.message_body('x'))
  with pytest.raises(CoseError):
    L.unseal(ka, wire)  # a cannot open its own direction (no reflection)


def test_tampered_link_message_rejected():
  _, b, _, _, _, ka, kb = handshake()
  wire = bytearray(L.seal(ka, L.message_body('x')))
  wire[-3] ^= 1
  with pytest.raises(CoseError):
    L.unseal(kb, bytes(wire))


def test_request_only_opens_for_its_peer():
  a, b = Identity.generate(), Identity.generate()
  c = Identity.generate()
  rb = MemoryRatchets(b.kem_alg)
  pending = L.make_request(a, b.public(), rb.current().public())
  with pytest.raises(CoseError):
    L.accept_request(c, pending.request, {a.address: a.public()}.get)


def test_request_from_unknown_identity_rejected():
  a, b = Identity.generate(), Identity.generate()
  rb = MemoryRatchets(b.kem_alg)
  pending = L.make_request(a, b.public(), rb.current().public())
  with pytest.raises(CoseError, match='unknown'):
    L.accept_request(b, pending.request, {}.get, ratchets=rb)


def test_accept_bound_to_its_request():
  a, b, rb, _, accept, _, _ = handshake()
  other = L.make_request(a, b.public(), rb.current().public())
  with pytest.raises(CoseError):
    L.finish(other, other.link_id + accept[L.LINK_ID_SIZE :])


def test_forward_secrecy_against_full_compromise_of_b():
  """Record the handshake, later steal all of b's keys: the link keys stay out of reach."""
  a, b, rb, pending, accept, ka, _ = handshake()
  assert pending.ephemeral is None  # a deleted its ephemeral key
  # the thief can reopen the request with b's ratchet and learn part_a...
  L.accept_request(b, pending.request, {a.address: a.public()}.get, ratchets=rb)
  # ...but part_b was sealed to a's ephemeral key, which no longer exists anywhere
  for k in rb.keys():
    with pytest.raises(CoseError):
      cose.decrypt0(accept[L.LINK_ID_SIZE :], k)


def test_prequantum_ephemeral_refused_by_default():
  a = Identity.generate('prequantum')
  b = Identity.generate('prequantum')
  rb = MemoryRatchets(HPKE_0)
  pending = L.make_request(a, b.public(), rb.current().public())
  book = {a.address: a.public()}.get
  with pytest.raises(CoseError, match='quantum'):
    L.accept_request(b, pending.request, book, ratchets=rb)
  L.accept_request(b, pending.request, book, ratchets=rb, quantum_safe_only=False)


# --- nodes ---


def test_nodes_talk_over_a_link_both_ways():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub)
    box_a, box_b = inbox(a), inbox(b)
    keys = await a.open_link(b.address)
    assert b.link_to(a.address).link_id == keys.link_id
    sizes = []
    real = a.lanes[0].road.send

    async def spy(frame):
      item = decode(frame)
      if not isinstance(item, tuple) and item.type == LINK_DATA:
        sizes.append(len(frame))
      await real(frame)

    a.lanes[0].road.send = spy
    m = await a.send(b.address, 'over the link')
    assert await a.delivered(m, timeout=5)
    await until(lambda: box_b)
    assert box_b[0].link_id == keys.link_id and box_b[0].id == m.id
    assert sizes and max(sizes) < 160  # whole frame; vs ~4.6 KB for a sealed PQ message
    r = await b.send(a.address, 'and back')
    assert await b.delivered(r, timeout=5)
    await until(lambda: box_a)
    assert box_a[0].content == 'and back' and box_a[0].sender == b.address
    await a.stop()
    await b.stop()

  run(main())


def test_closing_a_link_falls_back_to_sealed_messages():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub)
    box = inbox(b)
    await a.open_link(b.address)
    await a.close_link(b.address)
    await until(lambda: b.link_to(a.address) is None)
    assert a.link_to(b.address) is None
    m = await a.send(b.address, 'sealed again')
    assert await a.delivered(m, timeout=5)
    assert box[-1].link_id is None and box[-1].signed
    await a.stop()
    await b.stop()

  run(main())


def test_lost_accept_is_answered_again():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.1)
    real = b._send_data
    dropped = []

    async def drop_first_accept(dest, payload, kind=None):
      if not dropped and kind == LINK_ACCEPT:
        dropped.append(payload)
        return
      await real(dest, payload, kind)

    b._send_data = drop_first_accept
    keys = await a.open_link(b.address, timeout=5)
    assert dropped and b.link_to(a.address).link_id == keys.link_id
    await a.stop()
    await b.stop()

  run(main())


def test_link_on_lossy_lora_road():
  async def main():
    random.seed(3)
    hub = MemoryHub()
    a, b = await pair(hub, mtu=255, retry_after=0.1, retry_max=0.4, max_attempts=15)
    box = inbox(b)
    await a.open_link(b.address, timeout=20)
    hub.loss = 0.1  # link messages are one frame, so 10% loss is easy
    sent = [await a.send(b.address, f'msg {i}') for i in range(10)]
    for m in sent:
      assert await a.delivered(m, timeout=10)
    assert sorted(x.content for x in box) == sorted(f'msg {i}' for i in range(10))
    await a.stop()
    await b.stop()

  run(main())


def test_link_across_transports():
  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1)
    t = Node(transport=True, rebroadcast_delay=0.01)
    t.add_road(h1.road())
    t.add_road(h2.road())
    b = make(h2)
    box = inbox(b)
    peek = inbox(t)
    async with a, t, b:
      await a.announce()
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address) and b.peer_ratchet(a.address))
      await a.open_link(b.address)
      m = await a.send(b.address, 'through t')
      assert await a.delivered(m, timeout=5)
    assert box[0].content == 'through t' and peek == []

  run(main())


def test_node_can_refuse_links():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.05)
    b.accept_links = False
    with pytest.raises(TimeoutError):
      await a.open_link(b.address, timeout=0.3)
    await a.stop()
    await b.stop()

  run(main())
