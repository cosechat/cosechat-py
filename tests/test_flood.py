"""Announce flood control: airtime budget on slow roads, priority, dedupe, per-identity limit."""

import asyncio
import time

from test_node import make, run, until

from cosechat import message as M
from cosechat.identity import Identity
from cosechat.node import Node, _Lane
from cosechat.packet import ANNOUNCE, Packet, decode
from cosechat.ratchet import new_ratchet
from cosechat.roads.memory import MemoryHub
from cosechat.roads.rnode import RNodeRoad


def announce_packet(hops=0, ident=None, seq=None):
  ident = ident or Identity.generate('prequantum')
  data = M.make_announce(ident, new_ratchet(ident.kem_alg), sequence=seq)
  return Packet(ANNOUNCE, hops, ident.address, None, data)


class Recorder:
  """A road stand-in that records when frames go out."""

  mtu = 500
  bitrate = 40_000
  online = True
  name = 'rec'

  def __init__(self):
    self.sent = []

  async def send(self, frame):
    item = decode(frame)
    self.sent.append((time.monotonic(), item))


def test_lora_bitrate_like_reticulum():
  r = RNodeRoad(object(), 868_000_000, 125_000, 7, 8, 5)
  assert round(r.bitrate) == 3125


def test_budget_spaces_announces():
  async def main():
    road = Recorder()
    lane = _Lane(road, None, cap=0.1, max_age=60)  # 4000 bps for announces
    task = asyncio.get_running_loop().create_task(lane.run_announces())
    packets = [announce_packet() for _ in range(3)]
    for p in packets:
      await lane.announce(p)
    await until(lambda: len(road.sent) == 3, timeout=10)
    task.cancel()
    size = len(packets[0].encode())
    gap = size * 8 / (road.bitrate * 0.1)
    times = [t for t, _ in road.sent]
    assert all(b - a >= gap * 0.9 for a, b in zip(times, times[1:], strict=False))

  run(main())


def test_fewest_hops_first_and_newest_per_destination():
  async def main():
    road = Recorder()
    lane = _Lane(road, None, cap=0.1, max_age=60)
    ident = Identity.generate('prequantum')
    far, near = announce_packet(hops=5), announce_packet(hops=1)
    old, new = announce_packet(2, ident, seq=1), announce_packet(2, ident, seq=2)
    lane._ready_at = time.monotonic() + 0.2  # budget busy while we queue
    for p in (far, old, near, new):
      await lane.announce(p)
    task = asyncio.get_running_loop().create_task(lane.run_announces())
    await until(lambda: len(road.sent) == 3, timeout=10)
    task.cancel()
    order = [item for _, item in road.sent]
    assert [p.hops for p in order] == [1, 2, 5]
    assert order[1].payload == new.payload  # the older announce for ident was replaced

  run(main())


def test_stale_queued_announces_are_dropped():
  async def main():
    road = Recorder()
    lane = _Lane(road, None, cap=0.1, max_age=0.05)
    lane._ready_at = time.monotonic() + 0.2
    await lane.announce(announce_packet())
    task = asyncio.get_running_loop().create_task(lane.run_announces())
    await asyncio.sleep(0.4)
    task.cancel()
    assert road.sent == []

  run(main())


def test_fast_roads_are_not_budgeted():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)  # no bitrate: unlimited
    async with a, b:
      for _ in range(3):
        await a.rotate_ratchet()
      await until(
        lambda: (
          b.peer_ratchet(a.address) and b.peer_ratchet(a.address).kid == a.ratchets.current().kid
        )
      )

  run(main())


def test_transport_rebroadcasts_an_identity_at_most_once_per_interval():
  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1)
    t = Node(transport=True, rebroadcast_delay=0.01, rebroadcast_min_interval=60)
    t.add_road(h1.road())
    t.add_road(h2.road())
    b = make(h2)
    seen = []
    b.on_announce(lambda ann, path: seen.append(ann.sequence))
    async with a, t, b:
      for _ in range(3):
        await a.announce()
        await asyncio.sleep(0.05)
      await asyncio.sleep(0.2)
    assert len(seen) == 1  # t passed the first on, held back the rest

  run(main())


def test_junk_announces_rejected_before_signature_check():
  async def main():
    hub = MemoryHub()
    a = make(hub)
    pq_victim = Identity.generate()
    calls = []
    real = M.verify_announce
    M.verify_announce = lambda *x, **k: calls.append(1) or real(*x, **k)
    try:
      async with a:
        a.identities[pq_victim.address] = pq_victim.public()
        # a different keyset claiming a pinned address, and a prequantum identity
        other = Identity.generate()
        wrong = Packet(
          ANNOUNCE, 0, pq_victim.address, None, M.make_announce(other, new_ratchet(other.kem_alg))
        )
        a._handle_announce(a.lanes[0], wrong)
        a._handle_announce(a.lanes[0], announce_packet())
    finally:
      M.verify_announce = real
    assert calls == []

  run(main())
