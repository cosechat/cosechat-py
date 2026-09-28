"""
UDP echo bot: whatever you send it, it sends back. It announces itself
periodically so new peers find it.

  uv run examples/echo_bot.py                        # LAN broadcast on port 4242
  uv run examples/echo_bot.py --peer 10.0.0.5:4242   # unicast instead
  uv run examples/echo_client.py <bot address>       # test it

Keys are kept with examples/storage.py in ~/.cosechat/echo-bot (ratchets in
echo-bot.ratchets): its address stays the same across restarts, ratchets rotate
every 30 minutes and are deleted after 10 days (the example storage policy).
"""

import argparse
import asyncio
import logging
from pathlib import Path

import storage

from cosechat import Node
from cosechat.roads.udp import UDPRoad


def hostport(s: str) -> tuple[str, int]:
  host, _, port = s.rpartition(':')
  return (host or '127.0.0.1', int(port))


async def main():
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('--listen', default='0.0.0.0:4242', help='address to bind (default 0.0.0.0:4242)')
  p.add_argument('--peer', action='append', type=hostport, help='unicast peer (default: broadcast)')
  p.add_argument('--identity', type=Path, default=storage.HOME / 'echo-bot')
  p.add_argument('--name', default='echo-bot')
  p.add_argument('--interval', type=float, default=1800.0, help='seconds between announces')
  p.add_argument('-v', '--verbose', action='store_true')
  a = p.parse_args()
  logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING)

  ident = storage.load_identity(a.identity)
  ratchets = storage.ratchets_for(a.identity, ident)
  node = Node(ident, ratchets=ratchets, app_data={'name': a.name})
  node.add_road(UDPRoad(hostport(a.listen), a.peer))

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

  async with node:
    print(
      f'echo bot {node.address.hex()} on {a.listen}, announcing every {a.interval:g}s', flush=True
    )
    await storage.announce_forever(node, a.interval, ratchets)


if __name__ == '__main__':
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
