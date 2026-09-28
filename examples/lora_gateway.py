"""
LoRa gateway: a transport node that bridges an RNode radio and a broadcast
room, so a browser or another host can chat with LoRa nodes. By default it
joins the WebSocket room the web example uses (see room.py); --udp adds a LAN
broadcast road too. It also keeps messages for offline peers (store and
forward), still encrypted.

  uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 868000000
  uv run examples/lora_gateway.py /dev/ttyACM0 --freq 915000000 --sf 9 --udp 4242
  uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 868000000 --ws wss://host/ws/room

Every node on the radio must use the same frequency, bandwidth, SF and CR,
and the same --road-key if one is set. Announces on LoRa obey the airtime
budget (SPEC §9.0): on SF8 a relayed announce waits ~14 minutes, so a small
test mesh is quicker with --announce-cap 0 (relay at once) or a faster SF.

A full test setup with two RNodes (bob on LoRa, alice in the browser). Order
matters: a radio cannot hear while it transmits, and a full announce holds the
air for ~18 s at SF8, so start the gateway and let its first announce finish
before starting the bot, or they will talk over each other and never discover
each other (CAVEATS.md).

  1. the bridge, on the machine with internet:
     uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 915000000 --announce-cap 0
  2. wait ~20 s, then bob, on the LoRa-only side (or the second RNode):
     uv run examples/echo_bot.py --rnode /dev/ttyACM0 --freq 915000000 --announce-cap 0
     # it prints its address
  3. alice: cd cosechat-js && npm start, open http://localhost:8080, and chat
     with bob once his announce shows up (or use Find with his address)
"""

import argparse
import asyncio
import logging
from pathlib import Path

import room
import storage

from cosechat import Node, RoadAuth
from cosechat.roads.rnode import RNodeRoad
from cosechat.roads.udp import UDPRoad
from cosechat.roads.websocket import WebSocketClientRoad


def build_node(a):
  """Node from parsed args. Returns (node, radio, ratchets, ws_roads)."""
  ident = storage.load_identity(a.identity)
  ratchets = storage.ratchets_for(a.identity, ident)
  node = Node(
    ident,
    ratchets=ratchets,
    transport=True,
    propagate=True,
    store=storage.FileStore(a.identity.with_name(a.identity.name + '.store')),
    app_data={'name': 'gateway'},
    announce_cap=a.announce_cap,
  )
  auth = RoadAuth.from_passphrase(a.road_key) if a.road_key else None
  radio = RNodeRoad(a.port, a.freq, a.bw, a.txp, a.sf, a.cr)
  node.add_road(radio, auth)  # the key is for the radio mesh, not the room

  ws_urls = list(a.ws or [])
  if not ws_urls and a.udp is None:
    ws_urls = [room.ROOM]  # nothing else asked for: bridge the web room
  wss = []
  for url in ws_urls:
    road = WebSocketClientRoad(url)
    node.add_road(road)
    wss.append(road)
  if a.udp is not None:
    node.add_road(UDPRoad(('0.0.0.0', a.udp)))

  @node.on_announce
  def seen(ann, path):
    rf = f' rssi {radio.rssi} dBm snr {radio.snr} dB' if path.road is radio else ''
    print(f'* {ann.address.hex()} {path.hops} hop(s) on {path.road.name}{rf}', flush=True)

  return node, radio, ratchets, wss


async def main():
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('port', help='RNode serial port')
  p.add_argument('--freq', type=int, required=True, help='Hz, e.g. 868000000')
  p.add_argument('--bw', type=int, default=125000)
  p.add_argument('--sf', type=int, default=8)
  p.add_argument('--cr', type=int, default=5)
  p.add_argument('--txp', type=int, default=7, help='dBm')
  p.add_argument(
    '--ws',
    nargs='?',
    const=room.ROOM,
    action='append',
    metavar='URL',
    help=f'WebSocket room to join (bare --ws uses {room.ROOM})',
  )
  p.add_argument('--udp', type=int, metavar='PORT', help='also bridge a LAN UDP broadcast road')
  p.add_argument('--road-key', help='passphrase authenticating every LoRa frame')
  p.add_argument(
    '--announce-cap',
    type=float,
    default=0.02,
    help='share of a slow road announces may use (SPEC 9.0); 0 relays them at once '
    '(good for a small test mesh, antisocial on a busy channel)',
  )
  p.add_argument('--identity', type=Path, default=storage.HOME / 'gateway')
  p.add_argument('--interval', type=float, default=3600.0, help='seconds between announces')
  p.add_argument('-v', '--verbose', action='store_true')
  a = p.parse_args()
  logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO)

  node, _radio, ratchets, wss = build_node(a)
  async with node:
    print(
      f'gateway {node.address.hex()}: {", ".join(lane.road.name for lane in node.lanes)}',
      flush=True,
    )
    # a client road drops frames until it is connected: wait before announcing
    if wss:
      await asyncio.gather(*(w.connected.wait() for w in wss))
    await storage.announce_forever(node, a.interval, ratchets)


if __name__ == '__main__':
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
