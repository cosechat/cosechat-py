"""Ingress limits and bounded tables: a noisy neighbour cannot eat CPU or memory."""

import asyncio

from test_flood import Recorder, announce_packet
from test_node import make, run, until

from cosechat import link as L
from cosechat import message as M
from cosechat.identity import Identity
from cosechat.node import ANNOUNCE_QUEUE, _Lane
from cosechat.packet import ANNOUNCE, LINK_REQUEST, Packet
from cosechat.ratchet import new_ratchet
from cosechat.roads.memory import MemoryHub


def test_token_bucket():
  lane = _Lane(Recorder(), None, 0, 60)
  limits = {'x': (1000, 3)}
  assert [lane.allow('x', limits) for _ in range(4)] == [True, True, True, False]


def test_announce_flood_is_verified_only_up_to_the_limit():
  async def main():
    hub = MemoryHub()
    b = make(hub, quantum_safe_only=False, ingress={'announce': (0.001, 5)})
    calls = []
    real = M.verify_announce
    M.verify_announce = lambda *x, **k: calls.append(1) or real(*x, **k)
    try:
      async with b:
        for _ in range(30):  # 30 different valid identities, all at once
          p = announce_packet()
          b._on_frame(b.lanes[0], p.encode())
    finally:
      M.verify_announce = real
    assert len(calls) == 5

  run(main())


def test_link_request_flood_is_limited():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub, ingress={'link': (0.001, 2)})
    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address) and b.path(a.address))
      opened = []
      real = L.accept_request
      L.accept_request = lambda *x, **k: opened.append(1) or real(*x, **k)
      try:
        for _ in range(6):
          pending = L.make_request(a.identity, b.identity.public(), a.peer_ratchet(b.address))
          b._on_frame(
            b.lanes[0], Packet(LINK_REQUEST, 0, b.address, None, pending.request).encode()
          )
      finally:
        L.accept_request = real
    assert len(opened) == 2

  run(main())


def test_peer_table_is_bounded():
  async def main():
    hub = MemoryHub()
    b = make(hub, quantum_safe_only=False, max_peers=10, ingress={'announce': (1000, 1000)})
    async with b:
      first = None
      for _ in range(25):
        ident = Identity.generate('prequantum')
        first = first or ident.address
        data = M.make_announce(ident, new_ratchet(ident.kem_alg))
        b._on_frame(b.lanes[0], Packet(ANNOUNCE, 0, ident.address, None, data).encode())
      assert len(b.identities) <= 11 and len(b.paths) <= 10
      assert first not in b.identities  # the oldest went first

  run(main())


def test_announce_queue_is_bounded_and_keeps_the_nearest():
  async def main():
    lane = _Lane(Recorder(), None, cap=0.02, max_age=60)
    lane.road.bitrate = 1  # budgeted, and very slow: nothing leaves the queue here
    for _ in range(ANNOUNCE_QUEUE):
      await lane.announce(announce_packet(hops=5))
    near = announce_packet(hops=1)
    far = announce_packet(hops=9)
    await lane.announce(near)
    await lane.announce(far)
    assert len(lane.queue) == ANNOUNCE_QUEUE
    assert near.dest in lane.queue and far.dest not in lane.queue

  asyncio.run(main())
