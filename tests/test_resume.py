"""Fragment resume: receivers ask for just the fragments they missed."""

import asyncio
import random

from test_delivery import pair
from test_node import inbox, run, until

from cosiechat.node import _Lane
from cosiechat.packet import FRAGMENT_NACK, Nack, Reassembler, decode, fragment, nack
from cosiechat.roads.memory import MemoryHub


def test_nack_frame_is_tiny_and_roundtrips():
  frame = nack(b'\x01' * 8, [3, 7, 11])
  assert len(frame) < 30
  assert decode(frame) == Nack(b'\x01' * 8, [3, 7, 11])


def test_reassembler_reports_missing_and_ignores_late_duplicates():
  r = Reassembler()
  frags = [decode(f) for f in fragment(b'x' * 1000, 100, b'\x02' * 8)]
  for f in frags[:3] + frags[5:]:
    assert r.add('road', f) is None
  assert r.missing('road', b'\x02' * 8) == [3, 4]
  r.add('road', frags[3])
  assert r.add('road', frags[4]) == b'x' * 1000
  assert r.add('road', frags[4]) is None  # a late resend does not start a new set
  assert r.missing('road', b'\x02' * 8) is None


class Recorder:
  mtu = 255
  bitrate = None
  online = True
  name = 'rec'

  def __init__(self):
    self.sent = []

  async def send(self, frame):
    self.sent.append(frame)


def test_sender_resends_only_what_was_asked_for():
  async def main():
    road = Recorder()
    lane = _Lane(road, None, cap=0, max_age=60)
    from cosiechat.packet import DATA, Packet

    await lane.send(Packet(DATA, 0, b'\x01' * 16, None, b'y' * 2000))
    first = list(road.sent)
    fid = decode(first[0])[0]
    road.sent.clear()
    await lane.resend(Nack(fid, [4, 1, 4]))
    assert road.sent == [first[4], first[1]]
    road.sent.clear()
    await lane.resend(Nack(b'\x09' * 8, [0]))  # not ours: ignored
    assert road.sent == []

  run(main())


def lossy_delivery(nack_attempts):
  async def main():
    random.seed(11)
    hub = MemoryHub()
    # whole-message resends are 30 s away: only fragment resume can help in time
    a, b = await pair(hub, mtu=255, retry_after=30, nack_attempts=nack_attempts)
    box = inbox(b)
    hub.loss = 0.1  # 10% of frames lost; a PQ message is ~20 frames at this MTU
    got = []
    for i in range(5):
      await a.send(b.address, f'msg {i}', receipt=False)
      try:
        await until(lambda i=i: len(box) > i, timeout=1.5)
        got.append(i)
      except AssertionError:
        pass
    await a.stop()
    await b.stop()
    return got

  return run(main())


def test_lossy_lora_road_recovers_with_fragment_resume():
  assert lossy_delivery(nack_attempts=3) == [0, 1, 2, 3, 4]


def test_without_resume_the_same_road_loses_messages():
  assert len(lossy_delivery(nack_attempts=0)) < 5


def test_nacks_are_frames_on_the_road():
  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, mtu=255)
    kinds = []
    real = b.lanes[0].road.send

    async def spy(frame):
      item = decode(frame)
      kinds.append(FRAGMENT_NACK if isinstance(item, Nack) else None)
      await real(frame)

    b.lanes[0].road.send = spy
    # drop one fragment of a's next message on the way to b
    real_a = a.lanes[0].road.send
    dropped = []

    async def drop_one(frame):
      if not dropped and isinstance(decode(frame), tuple) and decode(frame)[1] == 2:
        dropped.append(frame)
        return
      await real_a(frame)

    a.lanes[0].road.send = drop_one
    box = inbox(b)
    await a.send(b.address, 'one fragment short', receipt=False)
    await until(lambda: box, timeout=3)
    assert dropped and FRAGMENT_NACK in kinds
    await a.stop()
    await b.stop()

  run(main())


def test_no_nack_storm():
  """A set that never completes is asked for a bounded number of times."""

  async def main():
    hub = MemoryHub()
    a, b = await pair(hub, mtu=255, nack_attempts=2)
    nacks = []
    real = b.lanes[0].road.send

    async def spy(frame):
      if isinstance(decode(frame), Nack):
        nacks.append(frame)
      await real(frame)

    b.lanes[0].road.send = spy
    a.lanes[0].resend = lambda n: asyncio.sleep(0)  # a never answers
    real_a = a.lanes[0].road.send

    async def drop_index_1(frame):
      item = decode(frame)
      if isinstance(item, tuple) and item[1] == 1:
        return
      await real_a(frame)

    a.lanes[0].road.send = drop_index_1
    await a.send(b.address, 'never whole', receipt=False)
    await asyncio.sleep(1.5)
    assert len(nacks) == 2
    await a.stop()
    await b.stop()

  run(main())
