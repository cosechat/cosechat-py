"""
Echo bot: whatever you send it, it sends back. It announces itself
periodically so new peers find it. It runs on UDP (default) or an RNode radio.

  uv run examples/echo_bot.py                              # LAN broadcast on port 4242
  uv run examples/echo_bot.py --peer 10.0.0.5:4242         # unicast instead
  uv run examples/echo_bot.py --rnode /dev/ttyACM0 --freq 868000000 --sf 8
  uv run examples/echo_client.py <bot address>             # test it

With --rnode and no --listen it opens *only* the radio, so it can stand in for
a device whose only link is LoRa (no LAN, no internet). Run it on that device,
or on the second RNode of a pair, and reach it from a browser through
examples/lora_gateway.py:

  uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 915000000 --announce-cap 0
  # wait for the gateway's first announce to leave the air (~20 s), then:
  uv run examples/echo_bot.py --rnode /dev/ttyACM0 --freq 915000000 --announce-cap 0

Both radios need the same frequency/bandwidth/SF/CR (and the same --road-key, if
one is set). Announces on LoRa obey the airtime budget (SPEC §9.0), and a radio
cannot hear while it transmits, so --announce-cap 0 is worth having on a quiet
test channel: every announce really goes out instead of queueing for minutes.

Keys are kept with examples/storage.py in ~/.cosechat/echo-bot (ratchets in
echo-bot.ratchets): its address stays the same across restarts, ratchets rotate
every 30 minutes and are deleted after 10 days (the example storage policy).
"""

import argparse
import asyncio
import logging
from pathlib import Path

import storage

from cosechat import Node, RoadAuth
from cosechat.roads.rnode import RNodeRoad
from cosechat.roads.udp import UDPRoad


def hostport(s: str) -> tuple[str, int]:
  host, _, port = s.rpartition(':')
  return (host or '127.0.0.1', int(port))


def build_node(a):
  """Node from parsed args, with the echo handlers attached. Returns (node, ratchets)."""
  ident = storage.load_identity(a.identity)
  ratchets = storage.ratchets_for(a.identity, ident)
  node = Node(ident, ratchets=ratchets, app_data={'name': a.name}, announce_cap=a.announce_cap)
  auth = RoadAuth.from_passphrase(a.road_key) if a.road_key else None
  if a.rnode:
    if not a.freq:
      raise SystemExit('--rnode needs --freq')
    for port in a.rnode:
      node.add_road(RNodeRoad(port, a.freq, a.bw, a.txp, a.sf, a.cr), auth)
  if a.listen or not a.rnode:
    node.add_road(UDPRoad(hostport(a.listen or '0.0.0.0:4242'), a.peer), auth)

  @node.on_message
  async def echo(m):
    print(f'{m.sender.hex()[:12]}: {m.content!r}', flush=True)
    try:
      await node.send(m.sender, m.content, title=m.title, fields=m.fields)
    except (LookupError, PermissionError) as e:
      print(f'  could not reply: {e}', flush=True)

  @node.on_resource
  async def echo_resource(r):
    print(f'{r.peer.hex()[:12]}: resource of {len(r.data)} bytes', flush=True)
    await node.send_resource(r.peer, r.data, r.meta)

  @node.on_announce
  def seen(ann, path):
    name = ann.app_data.get('name') if isinstance(ann.app_data, dict) else None
    print(f'* {name or "?"} {ann.address.hex()} ({path.hops} hop(s))', flush=True)

  return node, ratchets


async def main():
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('--listen', help='UDP address to bind (default 0.0.0.0:4242; unused with --rnode)')
  p.add_argument('--peer', action='append', type=hostport, help='unicast peer (default: broadcast)')
  p.add_argument('--rnode', action='append', metavar='SERIALPORT', help='RNode LoRa road')
  p.add_argument('--freq', type=int, help='LoRa frequency in Hz (needed with --rnode)')
  p.add_argument('--bw', type=int, default=125000)
  p.add_argument('--sf', type=int, default=8)
  p.add_argument('--cr', type=int, default=5)
  p.add_argument('--txp', type=int, default=7, help='dBm')
  p.add_argument('--road-key', metavar='PASSPHRASE', help='authenticate every frame on these roads')
  p.add_argument(
    '--announce-cap',
    type=float,
    default=0.02,
    help='share of a slow road announces may use (SPEC 9.0); 0 sends every announce '
    'at once, so retries are not stuck behind the first (good for a small test mesh)',
  )
  p.add_argument('--identity', type=Path, default=storage.HOME / 'echo-bot')
  p.add_argument('--name', default='echo-bot')
  p.add_argument('--interval', type=float, default=1800.0, help='seconds between announces')
  p.add_argument('-v', '--verbose', action='store_true')
  a = p.parse_args()
  logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING)

  node, ratchets = build_node(a)
  async with node:
    roads = ', '.join(lane.road.name for lane in node.lanes)
    print(f'echo bot {node.address.hex()} on {roads}, announcing every {a.interval:g}s', flush=True)
    await storage.announce_forever(node, a.interval, ratchets)


if __name__ == '__main__':
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
