"""
Interactive chat node on any roads, with keys kept by examples/storage.py.

  uv run examples/chat.py --name alice --udp 4242
  uv run examples/chat.py --ws-server 4243 --transport          # a hub for browsers
  uv run examples/chat.py --rnode /dev/ttyUSB0 --freq 868000000 --sf 8
  uv run examples/chat.py --lock --udp 4242                     # passphrase-encrypt keys at rest

At the prompt:

  @<address prefix> <text>   send a message (a full address, hex or address
                             text, also finds unknown peers)
  <text>                     reply to whoever wrote last
  /card                      print your contact card (a cosechat: URI)
  /add <cosechat:...>       add someone's contact card
  /peers  /announce  /rotate  /quit
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

import storage

from cosechat import SUITES, Node, RoadAuth, contact


def hostport(s: str, default_host: str) -> tuple[str, int]:
  host, _, port = s.rpartition(':')
  return (host or default_host, int(port))


def build_node(a):
  passphrase = None
  if a.lock:
    passphrase = os.environ.get('COSECHAT_PASSPHRASE') or getpass.getpass('key passphrase: ')
  ident = storage.load_identity(a.identity, a.suite, passphrase)
  ratchets = storage.ratchets_for(a.identity, ident, passphrase)
  node = Node(
    ident,
    transport=a.transport,
    propagate=a.propagate,
    app_data={'name': a.name} if a.name else None,
    quantum_safe_only=not a.allow_prequantum,
    ratchets=ratchets,
  )
  auth = RoadAuth.from_passphrase(a.road_key, a.road_key_mode) if a.road_key else None
  for spec in a.udp or []:
    from cosechat.roads.udp import UDPRoad

    peers = [hostport(p, '127.0.0.1') for p in a.udp_peer] if a.udp_peer else None
    node.add_road(UDPRoad(hostport(spec, '0.0.0.0'), peers), auth)
  for spec in a.ws_server or []:
    from cosechat.roads.websocket import WebSocketServerRoad

    node.add_road(WebSocketServerRoad(*hostport(spec, '0.0.0.0')), auth)
  for url in a.ws or []:
    from cosechat.roads.websocket import WebSocketClientRoad

    node.add_road(WebSocketClientRoad(url), auth)
  for port in a.rnode or []:
    from cosechat.roads.rnode import RNodeRoad

    if not a.freq:
      raise SystemExit('--rnode needs --freq')
    node.add_road(RNodeRoad(port, a.freq, a.bw, a.txp, a.sf, a.cr), auth)
  if not node.lanes:
    raise SystemExit('no roads: add --udp, --ws-server, --ws or --rnode')
  return node, ratchets


def label(node, addr: bytes) -> str:
  ann = node.announces.get(addr)
  name = ann[1].app_data.get('name') if ann and isinstance(ann[1].app_data, dict) else None
  return f'{name} <{addr.hex()[:12]}>' if name else addr.hex()[:12]


async def run(a):
  node, ratchets = build_node(a)
  last = {'from': None}

  @node.on_announce
  def _(ann, path):
    print(f'* {label(node, ann.address)} is {path.hops} hop(s) away on {path.road.name}')

  @node.on_message
  def _(m):
    last['from'] = m.sender
    title = f' [{m.title}]' if m.title else ''
    print(f'{label(node, m.sender)}{title}: {m.content}')

  async with node:
    print(f'you are {contact.address_text(node.address)} ({node.address.hex()})')
    print(f'on {", ".join(lane.road.name for lane in node.lanes)}')
    announcer = asyncio.create_task(storage.announce_forever(node, a.announce_interval, ratchets))
    loop = asyncio.get_running_loop()
    try:
      while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
          break
        line = line.strip()
        if not line:
          continue
        if line == '/quit':
          break
        if line == '/announce':
          await node.announce()
          continue
        if line == '/card':
          print(contact.card_uri(node.contact_card()))
          continue
        if line.startswith('/add '):
          try:
            ann = node.add_contact(contact.card_from_uri(line[5:]))
            print(f'* added {label(node, ann.address)}')
          except Exception as e:
            print(f'! {e}')
          continue
        if line == '/rotate':
          if node.ratchets is not None:
            await node.rotate_ratchet()
          continue
        if line == '/peers':
          for addr, path in node.paths.items():
            print(f'  {label(node, addr)}  {path.hops} hop(s) via {path.road.name}')
          continue
        if line.startswith('@'):
          prefix, _, text = line[1:].partition(' ')
          matches = [
            x for x in node.identities if x.hex().startswith(prefix.lower()) and x != node.address
          ]
          if not matches:
            try:  # a full address (hex or address text): send() asks the mesh for it
              matches = [contact.parse_address(prefix)]
            except Exception:
              pass
          if len(matches) != 1:
            print(f'! {len(matches)} peers match {prefix!r}')
            continue
          to = matches[0]
        elif last['from']:
          to, text = last['from'], line
        else:
          print('! use @<address> <text>')
          continue
        try:
          await node.send(to, text)
        except (LookupError, PermissionError) as e:
          print(f'! {e}')
    finally:
      announcer.cancel()


def main():
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('--identity', type=Path, default=storage.HOME / 'identity')
  p.add_argument('--suite', choices=SUITES, default='pq', help='suite for a new identity')
  p.add_argument('--lock', action='store_true', help='passphrase-encrypt key files at rest')
  p.add_argument('--name', help='display name to announce')
  p.add_argument('--transport', action='store_true', help='route for others')
  p.add_argument('--propagate', action='store_true', help='store and forward for offline peers')
  p.add_argument('--announce-interval', type=float, default=1800.0)
  p.add_argument(
    '--allow-prequantum', action='store_true', help='INSECURE: also talk to prequantum peers'
  )
  p.add_argument('--udp', action='append', metavar='[HOST:]PORT', help='UDP road (broadcast)')
  p.add_argument('--udp-peer', action='append', metavar='HOST:PORT', help='unicast UDP peer')
  p.add_argument('--ws-server', action='append', metavar='[HOST:]PORT')
  p.add_argument('--ws', action='append', metavar='URL', help='WebSocket client road')
  p.add_argument('--rnode', action='append', metavar='SERIALPORT', help='RNode LoRa road')
  p.add_argument('--freq', type=int, help='LoRa frequency in Hz')
  p.add_argument('--bw', type=int, default=125000)
  p.add_argument('--sf', type=int, default=8)
  p.add_argument('--cr', type=int, default=5)
  p.add_argument('--txp', type=int, default=7)
  p.add_argument('--road-key', metavar='PASSPHRASE', help='authenticate every frame on these roads')
  p.add_argument('--road-key-mode', choices=['mac', 'encrypt'], default='mac')
  p.add_argument('-v', '--verbose', action='store_true')
  a = p.parse_args()
  logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING)
  try:
    asyncio.run(run(a))
  except KeyboardInterrupt:
    pass


if __name__ == '__main__':
  main()
