"""
LoRa <-> LAN gateway: a transport node that bridges an RNode radio and UDP,
so phones and laptops on the LAN reach LoRa nodes and back. It also keeps
messages for offline peers (store and forward), still encrypted.

  uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 868000000
  uv run examples/lora_gateway.py /dev/ttyACM0 --freq 915000000 --sf 9 --road-key 'our mesh'

Every node on the radio must use the same frequency, bandwidth, SF and CR,
and the same --road-key if one is set.
"""

import argparse
import asyncio
import logging
from pathlib import Path

import storage

from cosiechat import Node, RoadAuth
from cosiechat.roads.rnode import RNodeRoad
from cosiechat.roads.udp import UDPRoad


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
  p.add_argument('--udp', type=int, default=4242, help='LAN UDP port (broadcast)')
  p.add_argument('--road-key', help='passphrase authenticating every LoRa frame')
  p.add_argument('--identity', type=Path, default=storage.HOME / 'gateway')
  p.add_argument('--interval', type=float, default=3600.0, help='seconds between announces')
  p.add_argument('-v', '--verbose', action='store_true')
  a = p.parse_args()
  logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO)

  ident = storage.load_identity(a.identity)
  ratchets = storage.ratchets_for(a.identity, ident)
  node = Node(
    ident, ratchets=ratchets, transport=True, propagate=True, app_data={'name': 'gateway'}
  )
  radio = RNodeRoad(a.port, a.freq, a.bw, a.txp, a.sf, a.cr)
  node.add_road(radio, RoadAuth.from_passphrase(a.road_key) if a.road_key else None)
  node.add_road(UDPRoad(('0.0.0.0', a.udp)))

  @node.on_announce
  def seen(ann, path):
    rf = f' rssi {radio.rssi} dBm snr {radio.snr} dB' if path.road is radio else ''
    print(f'* {ann.address.hex()} {path.hops} hop(s) on {path.road.name}{rf}', flush=True)

  async with node:
    print(f'gateway {node.address.hex()}: {radio.name} <-> udp:{a.udp}', flush=True)
    await storage.announce_forever(node, a.interval, ratchets)


if __name__ == '__main__':
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
