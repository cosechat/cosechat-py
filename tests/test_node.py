"""Mesh behaviour over in-memory roads: no radios, no sockets."""

import asyncio

import pytest

from cosechat.identity import Identity
from cosechat.node import Node
from cosechat.packet import RoadAuth
from cosechat.roads.memory import MemoryHub

SUITES = ['pq', 'prequantum', 'hybrid']


def run(coro):
  return asyncio.run(asyncio.wait_for(coro, 30))


async def until(cond, timeout=5.0):
  end = asyncio.get_running_loop().time() + timeout
  while not cond():
    if asyncio.get_running_loop().time() > end:
      raise AssertionError('condition not reached')
    await asyncio.sleep(0.01)


def inbox(node):
  box = []
  node.on_message(box.append)
  return box


def make(hub, suite='pq', mtu=500, **kw):
  kw.setdefault('quantum_safe_only', suite != 'prequantum')
  ident = kw.pop('identity', None) or Identity.generate(suite)
  n = Node(ident, rebroadcast_delay=0.01, **kw)
  n.add_road(hub.road(mtu=mtu))
  return n


@pytest.mark.parametrize('suite', SUITES)
def test_direct_neighbours(suite):
  async def main():
    hub = MemoryHub()
    a, b = make(hub, suite), make(hub, suite)
    box = inbox(b)
    async with a, b:
      await a.announce()
      await b.announce('bob')
      await until(lambda: b.address in a.paths and a.address in b.paths)
      assert a.announces[b.address][1].app_data == 'bob'
      sent = await a.send(b.address, 'hello bob', title='hi')
      await until(lambda: box)
    m = box[0]
    assert (m.sender, m.content, m.title, m.id) == (a.address, 'hello bob', 'hi', sent.id)

  run(main())


def test_multi_hop_across_roads_through_transport():
  """a -(road 1)- t1 -(road 2)- t2 -(road 3)- b; nobody but b can read it."""

  async def main():
    h1, h2, h3 = MemoryHub(), MemoryHub(), MemoryHub()
    a = make(h1)
    t1 = Node(transport=True, rebroadcast_delay=0.01)
    t1.add_road(h1.road())
    t1.add_road(h2.road())
    t2 = Node(transport=True, rebroadcast_delay=0.01)
    t2.add_road(h2.road())
    t2.add_road(h3.road())
    b = make(h3)
    box = inbox(b)
    peeked = []
    for t in (t1, t2):
      t.on_message(peeked.append)
    async with a, t1, t2, b:
      await a.announce()
      await b.announce()
      await until(lambda: b.address in a.paths and a.address in b.paths)
      assert a.paths[b.address].hops == 3
      assert a.paths[b.address].via == t1.address
      await a.send(b.address, 'over two transports')
      await until(lambda: box)
    assert box[0].content == 'over two transports'
    assert peeked == []

  run(main())


def test_path_request_finds_unannounced_destination():
  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1)
    t = Node(transport=True, rebroadcast_delay=0.01)
    t.add_road(h1.road())
    t.add_road(h2.road())
    b = make(h2)
    box = inbox(b)
    async with a, t, b:
      await a.announce()
      await until(lambda: a.address in b.paths)
      # a only knows b's address, e.g. from a QR code
      await a.send(b.address, 'found you', timeout=5)
      await until(lambda: box)
    assert box[0].content == 'found you'

  run(main())


def test_fragmentation_on_small_mtu_road():
  """PQ announces and messages are kilobytes; a LoRa-sized road still carries them."""

  async def main():
    hub = MemoryHub()
    a, b = make(hub, mtu=255), make(hub, mtu=255)
    box = inbox(b)
    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: b.address in a.paths and a.address in b.paths)
      await a.send(b.address, 'x' * 2000, fields={'attachment': b'\x00' * 3000})
      await until(lambda: box)
    assert box[0].content == 'x' * 2000
    assert hub.frames > 20

  run(main())


def test_multiple_recipients_single_ciphertext():
  async def main():
    hub = MemoryHub()
    a, b, c, d = (make(hub) for _ in range(4))
    boxes = [inbox(n) for n in (b, c, d)]
    async with a, b, c, d:
      for n in (a, b, c):
        await n.announce()
      await until(lambda: b.address in a.paths and c.address in a.paths)
      sent = await a.send([b.address, c.address], 'group hello')
      await until(lambda: boxes[0] and boxes[1])
      await asyncio.sleep(0.05)
    for box in boxes[:2]:
      assert box[0].content == 'group hello'
      assert box[0].id == sent.id
      assert set(box[0].recipients) == {b.address, c.address}
    assert boxes[2] == []

  run(main())


def test_propagation_node_stores_and_forwards():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    prop = Node(propagate=True, rebroadcast_delay=0.01)
    prop.add_road(hub.road())
    box = inbox(b)
    async with a:
      async with b:
        await a.announce()
        await b.announce()
        await until(lambda: a.peer_ratchet(b.address) and a.address in b.paths)
      # b is offline now; the propagation node arrives and never saw b
      async with prop:
        await a.send(b.address, 'while you were away')
        await until(lambda: b.address in prop.store)
        async with b:
          await b.announce()
          await until(lambda: box)
    assert box[0].content == 'while you were away'
    assert box[0].sender == a.address
    assert box[0].ratchet_id is not None

  run(main())


def test_attached_identity_lets_unknown_sender_through():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with a, b:
      await b.announce()
      await until(lambda: b.address in a.paths)
      # b never heard a's announce
      await a.send(b.address, 'who am i', attach_identity=True)
      await until(lambda: box)
    assert box[0].sender == a.address
    assert b.known(a.address) == a.identity.public()

  run(main())


def test_unknown_sender_is_looked_up_then_delivered():
  """b never heard a's announce: it fetches a's keyset by address, then opens the message."""

  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with a, b:
      await b.announce()
      await until(lambda: b.address in a.paths)
      await a.send(b.address, 'who am i')
      await until(lambda: box)
    assert box[0].sender == a.address and b.known(a.address) == a.identity.public()

  run(main())


def test_unknown_sender_with_no_keyset_anywhere_is_dropped():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with b:
      async with a:
        await b.announce()
        await until(lambda: b.address in a.paths)
        a._handle_keyset_request = lambda lane, p: None  # nobody will answer b
        await a.send(b.address, 'anonymous', receipt=False)
      await asyncio.sleep(0.1)
    assert box == []

  run(main())


@pytest.mark.parametrize('mode', ['mac', 'encrypt'])
def test_road_auth_keeps_outsiders_out(mode):
  async def main():
    hub = MemoryHub()
    auth = RoadAuth.from_passphrase('correct horse', mode)
    a = Node(rebroadcast_delay=0.01)
    a.add_road(hub.road(), auth)
    b = Node(rebroadcast_delay=0.01)
    b.add_road(hub.road(), auth)
    eve = Node(rebroadcast_delay=0.01)
    eve.add_road(hub.road(), RoadAuth.from_passphrase('wrong', mode))
    box = inbox(b)
    async with a, b, eve:
      await a.announce()
      await b.announce()
      await eve.announce()
      await until(lambda: b.address in a.paths and a.address in b.paths)
      await asyncio.sleep(0.05)
      assert eve.address not in a.paths
      assert b.address not in eve.paths
      await a.send(b.address, 'members only')
      await until(lambda: box)

  run(main())


def test_tampered_frames_are_ignored():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    real_send = a.lanes[0].road.send

    async def flip(frame):
      bad = bytearray(frame)
      bad[-5] ^= 0x01
      await real_send(bytes(bad))

    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: b.address in a.paths and a.address in b.paths)
      a.lanes[0].road.send = flip
      await a.send(b.address, 'mangled')
      await asyncio.sleep(0.1)
      a.lanes[0].road.send = real_send
      await a.send(b.address, 'intact')
      await until(lambda: box)
    assert [m.content for m in box] == ['intact']

  run(main())


def test_quantum_safe_only_is_the_default():
  assert Node(Identity.generate('pq')).quantum_safe_only
  with pytest.raises(ValueError):
    Node(Identity.generate('prequantum'))
  assert not Node(Identity.generate('prequantum'), quantum_safe_only=False).quantum_safe_only


def test_quantum_safe_only_ignores_and_refuses_prequantum_peers():
  async def main():
    hub = MemoryHub()
    strict = make(hub)
    pq, prequantum = make(hub, 'pq'), make(hub, 'prequantum')
    box = inbox(strict)
    async with strict, pq, prequantum:
      for n in (strict, pq, prequantum):
        await n.announce()
      await until(lambda: pq.address in strict.paths and strict.address in prequantum.paths)
      await asyncio.sleep(0.05)
      assert prequantum.address not in strict.paths
      await prequantum.send(strict.address, 'prequantum sender')
      await pq.send(strict.address, 'pq sender')
      await until(lambda: box)
      await asyncio.sleep(0.05)
      with pytest.raises(PermissionError):
        await strict.send(prequantum.identity.public(), 'no', timeout=0.1)
    assert [m.content for m in box] == ['pq sender']

  run(main())


def test_address_is_pinned_to_first_keyset():
  async def main():
    hub = MemoryHub()
    a, b = make(hub, 'prequantum'), make(hub, 'prequantum')
    # stand-in for a hash collision: a already holds a different keyset for b's address
    other = Identity.generate('prequantum').public()
    a.identities[b.address] = other
    async with a, b:
      await b.announce()
      await asyncio.sleep(0.1)
    assert a.known(b.address) is other
    assert b.address not in a.paths

  run(main())
