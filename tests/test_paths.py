"""Path upkeep: fewer hops win, dead paths are rediscovered, failed ones forgotten."""

from test_delivery import pair
from test_node import inbox, make, run, until

from cosiechat.node import Node
from cosiechat.packet import ANNOUNCE, Packet
from cosiechat.roads.memory import MemoryHub


def test_same_announce_over_fewer_hops_wins():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a, b:
      await a.announce()
      await until(lambda: b.path(a.address))
      payload = b.announces[a.address][0]
      lane = b.lanes[0]
      b._on_frame(lane, Packet(ANNOUNCE, 3, a.address, b'\x01' * 16, payload).encode())
      assert b.path(a.address).hops == 1  # the direct copy stays
      b.paths[a.address].hops = 4  # pretend we only knew a long route
      b._on_frame(lane, Packet(ANNOUNCE, 0, a.address, None, payload).encode())
      assert b.path(a.address).hops == 1 and b.path(a.address).via is None

  run(main())


def test_a_copy_with_other_bytes_is_not_trusted_for_free():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a, b:
      await a.announce()
      await until(lambda: b.path(a.address))
      b.paths[a.address].hops = 4
      bad = Packet(ANNOUNCE, 0, a.address, None, b'\x00' * 40)
      b._mark_seen(bad.hash)
      b._on_frame(b.lanes[0], bad.encode())
      assert b.path(a.address).hops == 4

  run(main())


def test_route_around_a_vanished_transport():
  """a and b share two transports; the one a routes through dies, a finds the other."""

  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1, retry_after=0.2, max_attempts=6)
    ts = []
    for _ in range(2):
      t = Node(transport=True, rebroadcast_delay=0.01, rebroadcast_min_interval=0)
      t.add_road(h1.road())
      t.add_road(h2.road())
      ts.append(t)
    b = make(h2, retry_after=0.2)
    box = inbox(b)
    for n in (a, *ts, b):
      await n.start()
    await a.announce()
    await b.announce()
    await until(lambda: a.peer_ratchet(b.address) and b.peer_ratchet(a.address))
    await until(lambda: all(t.path(b.address) for t in ts))
    used = next(t for t in ts if t.address == a.path(b.address).via)
    other = next(t for t in ts if t is not used)
    await used.stop()
    m = await a.send(b.address, 'around the hole')
    assert await a.delivered(m, timeout=10)
    assert box[-1].content == 'around the hole'
    assert a.path(b.address).via == other.address
    for n in (a, other, b):
      await n.stop()

  run(main())


def test_failed_delivery_forgets_the_path():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.05, max_attempts=2)
    await b.stop()
    m = await a.send(b.address, 'gone')
    assert not await a.delivered(m, timeout=5)
    assert a.path(b.address) is None
    await a.stop()

  run(main())
