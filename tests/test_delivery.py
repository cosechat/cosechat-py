"""Receipts and retransmission: messages get through lossy roads, and the app sees each once."""

import asyncio
import random

import pytest
from test_node import inbox, make, run, until

from cosiechat import message as M
from cosiechat.node import Node
from cosiechat.packet import RECEIPT, Packet, decode
from cosiechat.roads.memory import MemoryHub


async def pair(hub, **kw):
  a, b = make(hub, **kw), make(hub, **kw)
  await a.start()
  await b.start()
  await a.announce()
  await b.announce()
  await until(lambda: a.peer_ratchet(b.address) and b.peer_ratchet(a.address))
  return a, b


def test_receipt_confirms_delivery():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub)
    box, confirmed = inbox(b), []
    a.on_receipt(lambda m, who: confirmed.append((m.id, who)))
    m = await a.send(b.address, 'did you get this?')
    assert await a.delivered(m, timeout=5)
    assert confirmed == [(m.id, b.address)] and len(box) == 1
    assert box[0].receipt_secret is not None
    await a.stop()
    await b.stop()

  run(main())


def test_receipt_is_tiny():
  sizes = []
  tag = M.receipt_tag(b'\x01' * 16, b'\x02' * 16)
  p = Packet(RECEIPT, 0, b'\x03' * 16, None, tag + b'\x00' * 8)
  sizes.append(len(p.encode()))
  assert sizes[0] < 64 and decode(p.encode()) == p


def test_lossy_lora_road_still_delivers_once():
  async def main():
    random.seed(7)
    hub = MemoryHub()
    a, b = await pair(hub, mtu=255, retry_after=0.1, retry_max=0.4, max_attempts=15)
    box = inbox(b)
    # 5% of LoRa frames lost; a PQ message is ~20 frames here. Fragment resume
    # and whole-message resends both help (test_resume.py isolates resume)
    hub.loss = 0.05
    m = await a.send(b.address, 'x' * 100)
    assert await a.delivered(m, timeout=30)
    await asyncio.sleep(0.3)
    assert [x.id for x in box] == [m.id]
    await a.stop()
    await b.stop()

  run(main())


def test_lost_receipt_is_resent_without_redelivery():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.1)
    box = inbox(b)
    road = b.lanes[0].road
    real = road.send
    dropped = []

    async def drop_first_receipt(frame):
      if not dropped and decode(frame).type == RECEIPT:
        dropped.append(frame)
        return
      await real(frame)

    road.send = drop_first_receipt
    m = await a.send(b.address, 'once')
    assert await a.delivered(m, timeout=5)
    assert dropped and [x.content for x in box] == ['once']
    await a.stop()
    await b.stop()

  run(main())


def test_gives_up_when_recipient_is_gone():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.05, max_attempts=3)
    await b.stop()
    sent = hub.frames
    m = await a.send(b.address, 'anyone?')
    assert not await a.delivered(m, timeout=5)
    assert hub.frames > sent  # it did try more than once
    await a.stop()

  run(main())


def test_forged_receipt_does_not_confirm():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, retry_after=10)
    b.on_message(lambda m: None)
    b._deliver = lambda p: None  # b never answers
    m = await a.send(b.address, 'x')
    forged = Packet(RECEIPT, 0, a.address, None, b'\x00' * 24)
    a._handle_receipt(forged)
    assert not await a.delivered(m, timeout=0.2)
    await a.stop()
    await b.stop()

  run(main())


def test_no_receipt_requested():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub)
    box = inbox(b)
    m = await a.send(b.address, 'fire and forget', receipt=False)
    await until(lambda: box)
    assert box[0].receipt_secret is None
    with pytest.raises(LookupError):
      await a.delivered(m)
    await a.stop()
    await b.stop()

  run(main())


def test_each_recipient_confirms():
  async def main():
    hub = MemoryHub()
    a, b, c = (make(hub) for _ in range(3))
    for n in (a, b, c):
      await n.start()
    for n in (a, b, c):
      await n.announce()
    await until(lambda: all(a.peer_ratchet(x.address) for x in (b, c)))
    await until(lambda: b.peer_ratchet(a.address) and c.peer_ratchet(a.address))
    who = []
    a.on_receipt(lambda m, addr: who.append(addr))
    m = await a.send([b.address, c.address], 'both of you')
    assert await a.delivered(m, timeout=5)
    assert set(who) == {b.address, c.address}
    for n in (a, b, c):
      await n.stop()

  run(main())


def test_receipt_travels_back_across_transports():
  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1)
    t = Node(transport=True, rebroadcast_delay=0.01)
    t.add_road(h1.road())
    t.add_road(h2.road())
    b = make(h2)
    async with a, t, b:
      await a.announce()
      await b.announce()
      await until(lambda: a.peer_ratchet(b.address) and b.peer_ratchet(a.address))
      m = await a.send(b.address, 'there and back')
      assert await a.delivered(m, timeout=5)

  run(main())
