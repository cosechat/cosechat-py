"""Two real RNodes over the air. Skipped unless two serial RNodes are attached.

Detection can be overridden with:

  COSECHAT_RNODE_PORTS=/dev/ttyUSB0,/dev/ttyUSB1
  COSECHAT_RNODE_FREQ=868000000   # default 915000000

Both radios must be the same band and share one config. If the ports exist but
the radios fail to start (wrong band, cable pulled), the test skips.

Discovery is deliberately one-sided. A post-quantum announce is ~6.5 kB, i.e.
a dozen LoRa fragments, so one announce holds the radio for many seconds, and
a radio cannot hear while it transmits. Two nodes announcing at the same time
therefore miss each other's fragments *and* each other's fragment NACKs, and
nothing reassembles. So each side announces on its own, then waits for the
other's burst to leave the air. The nodes also run with `announce_cap=0` (no
announce airtime budget, SPEC 9.0) so every announce in the loop really goes
out instead of queueing behind the first.
"""

import asyncio
import glob
import os
import time

import pytest
from test_node import inbox

from cosechat import Identity, Node
from cosechat.roads.rnode import RNodeError, RNodeRoad

PATTERNS = ['/dev/tty.usbserial*', '/dev/cu.usbserial*', '/dev/ttyUSB*', '/dev/ttyACM*']

# seconds to let one side's announce burst leave the air before the other sends
BURST = float(os.environ.get('COSECHAT_RNODE_BURST', '20'))


def find_ports() -> list[str]:
  env = os.environ.get('COSECHAT_RNODE_PORTS')
  if env:
    return [p for p in (part.strip() for part in env.split(',')) if p]
  found: list[str] = []
  for pattern in PATTERNS:
    found += sorted(glob.glob(pattern))
  return list(dict.fromkeys(found))


PORTS = find_ports()
FREQ = int(os.environ.get('COSECHAT_RNODE_FREQ', '915000000'))

pytestmark = pytest.mark.skipif(
  len(PORTS) < 2, reason=f'two RNodes on serial ports needed, found {PORTS}'
)


async def discover(a, b, deadline: float = 180.0):
  """Announce one side at a time until each side has the other."""
  end = time.monotonic() + deadline
  while not (a.known(b.address) and b.known(a.address)):
    if time.monotonic() > end:
      raise AssertionError('peers did not discover each other over the air')
    if not a.known(b.address):
      await a.announce()
      await asyncio.sleep(BURST)
    if not b.known(a.address):
      await b.announce()
      await asyncio.sleep(BURST)


def test_pq_message_between_two_rnodes():
  async def main():
    ra = RNodeRoad(PORTS[0], frequency=FREQ, sf=8, boot_delay=0.5, timeout=10)
    rb = RNodeRoad(PORTS[1], frequency=FREQ, sf=8, boot_delay=0.5, timeout=10)
    a = Node(
      Identity.generate('pq'), app_data={'name': 'test-a'}, rebroadcast_delay=0, announce_cap=0
    )
    b = Node(
      Identity.generate('pq'), app_data={'name': 'test-b'}, rebroadcast_delay=0, announce_cap=0
    )
    a.add_road(ra)
    b.add_road(rb)
    box = inbox(b)
    try:
      async with a, b:
        await discover(a, b)
        sent = await a.send(b.address, 'over the air')
        await asyncio.wait_for(_received(box), 60)
        assert await a.delivered(sent, timeout=60)
    except RNodeError as e:
      pytest.skip(f'RNode hardware not usable: {e}')
    assert box[0].content == 'over the air'
    assert box[0].sender == a.address

  asyncio.run(asyncio.wait_for(main(), 420))


async def _received(box):
  while not box:
    await asyncio.sleep(0.05)
