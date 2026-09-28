"""Propagation nodes: deposit for offline peers, fetch over an authenticated link."""

import asyncio

from test_node import inbox, make, run, until

from cosechat.node import Node
from cosechat.roads.memory import MemoryHub


async def mesh(**kw):
  """
  a and b have met (ratchets known); p is a propagation node on the same road.
  When b "restarts" below it keeps its ratchets (as an app with ratchet storage
  would): messages for it are sealed to them.
  """
  hub = MemoryHub()
  a, b = make(hub, retry_after=0.1, **kw), make(hub, retry_after=0.1)
  p = Node(propagate=True, rebroadcast_delay=0.01, retry_after=0.1)
  p.add_road(hub.road())
  for n in (a, b, p):
    await n.start()
  for n in (a, b, p):
    await n.announce()
  await until(lambda: a.peer_ratchet(b.address) and b.path(a.address) and a.path(p.address))
  await until(lambda: p.address in a.propagation_nodes and p.address in b.propagation_nodes)
  return hub, a, b, p


def test_propagation_nodes_are_discovered_from_announces():
  async def main():
    hub, a, b, p = await mesh()
    assert a._propagation_node() == p.address
    assert b.address not in a.propagation_nodes
    for n in (a, b, p):
      await n.stop()

  run(main())


def test_deposit_then_fetch():
  async def main():
    hub, a, b, p = await mesh()
    await b.stop()  # b goes offline
    m = await a.send(b.address, 'while you were away', propagate=True)
    assert await a.delivered(m, timeout=5)  # the propagation node has it
    assert b.address in p.store
    # a returning client remembers its propagation node (app storage), and can
    # fetch without announcing itself (the node learns its keyset on demand)
    b2 = make(
      hub, identity=b.identity, ratchets=b.ratchets, retry_after=0.1, propagation_node=p.address
    )
    box = inbox(b2)
    await b2.start()
    assert await b2.fetch(timeout=10) == 1
    await until(lambda: box)
    assert box[0].content == 'while you were away' and box[0].sender == a.address
    assert b.address not in p.store and not p._batches  # acknowledged and gone
    for n in (a, b2, p):
      await n.stop()

  run(main())


def test_failed_direct_delivery_falls_back_to_a_deposit():
  async def main():
    hub, a, b, p = await mesh(max_attempts=2)
    await b.stop()
    m = await a.send(b.address, 'deposited for you')
    assert await a.delivered(m, timeout=10)
    await until(lambda: b.address in p.store)
    for n in (a, p):
      await n.stop()

  run(main())


def test_only_the_recipient_can_fetch():
  async def main():
    hub, a, b, p = await mesh()
    await b.stop()
    m = await a.send(b.address, 'for b only', propagate=True)
    assert await a.delivered(m, timeout=5)
    c = make(hub, retry_after=0.1, propagation_node=p.address)
    await c.start()
    assert await c.fetch(timeout=5) == 0  # nothing for c
    assert b.address in p.store  # b's message is still there
    for n in (a, c, p):
      await n.stop()

  run(main())


def test_lost_items_are_fetched_again():
  async def main():
    hub, a, b, p = await mesh()
    await b.stop()
    for i in range(3):
      m = await a.send(b.address, f'm{i}', propagate=True)
      assert await a.delivered(m, timeout=5)
    # a returning client remembers its propagation node (app storage), and can
    # fetch without announcing itself (the node learns its keyset on demand)
    b2 = make(
      hub, identity=b.identity, ratchets=b.ratchets, retry_after=0.1, propagation_node=p.address
    )
    box = inbox(b2)
    await b2.start()
    real = p._resource_send
    dropped = []

    def drop_one_item(keys, field_id, value):
      if field_id == 13 and not dropped:
        dropped.append(value)
        return
      real(keys, field_id, value)

    p._resource_send = drop_one_item
    assert await b2.fetch(timeout=10) == 3
    await asyncio.sleep(0.05)
    assert dropped and sorted(x.content for x in box) == ['m0', 'm1', 'm2']
    for n in (a, b2, p):
      await n.stop()

  run(main())


def test_held_messages_are_pushed_when_the_recipient_announces():
  async def main():
    hub, a, b, p = await mesh()
    await b.stop()
    m = await a.send(b.address, 'pushed on return', propagate=True)
    assert await a.delivered(m, timeout=5)
    b2 = make(hub, identity=b.identity, ratchets=b.ratchets, retry_after=0.1)
    box = inbox(b2)
    await b2.start()
    await b2.announce()
    await until(lambda: box)
    assert box[0].content == 'pushed on return'
    for n in (a, b2, p):
      await n.stop()

  run(main())
