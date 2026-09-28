"""
Live conformance runner: drives an echo bot written in any implementation
(Python, JS, Arduino) over a real road and checks each protocol feature.

The bot under test must: announce; answer path and keyset requests; echo
every message back to its sender (same content, title and fields) sealed or
over a link, whichever it received; and echo every resource back.
examples/echo_bot.py is the reference bot.

  uv run interop/live.py <bot address> --udp 127.0.0.1:47001 --udp-peer 127.0.0.1:47002
  uv run interop/live.py <bot address> --ws ws://host:4243

Exit status is non-zero if any check fails.
"""

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from cosechat import Identity, Node  # noqa: E402


def hostport(s):
  host, _, port = s.rpartition(':')
  return (host or '127.0.0.1', int(port))


class Runner:
  def __init__(self, node: Node, bot: bytes, timeout: float):
    self.node = node
    self.bot = bot
    self.timeout = timeout
    self.inbox: asyncio.Queue = asyncio.Queue()
    self.resources: asyncio.Queue = asyncio.Queue()
    node.on_message(lambda m: self.inbox.put_nowait(m) if m.sender == bot else None)
    node.on_resource(lambda r: self.resources.put_nowait(r) if r.peer == bot else None)
    self.results = []

  async def check(self, name, coro):
    start = time.monotonic()
    try:
      detail = await asyncio.wait_for(coro, self.timeout)
      ok = True
    except Exception as e:
      ok, detail = False, f'{type(e).__name__}: {e}'
    ms = (time.monotonic() - start) * 1000
    self.results.append(ok)
    print(f'{"PASS" if ok else "FAIL"}  {name:<34} {ms:6.0f} ms  {detail or ""}', flush=True)

  async def echo(self, content, fields=None):
    while not self.inbox.empty():
      self.inbox.get_nowait()
    m = await self.node.send(self.bot, content, title='t', fields=fields or {})
    if not await self.node.delivered(m, self.timeout):
      raise AssertionError('no receipt from the bot')
    back = await self.inbox.get()
    assert back.content == content, f'echo content {back.content!r}'
    assert back.fields == (fields or {}), 'echo fields differ'
    return back

  async def find(self):
    ident = await self.node.request_path(self.bot, self.timeout, fresh=True)
    assert ident is not None and self.node.peer_ratchet(self.bot), 'no announce from the bot'
    return f'{self.node.path(self.bot).hops} hop(s)'

  async def sealed(self):
    back = await self.echo('sealed ping', {1: b'\x00\x01', 'k': 'v'})
    assert back.link_id is None and back.ratchet_id is not None
    return 'receipt + echo'

  async def rotation(self):
    new = await self.node.rotate_ratchet()
    await asyncio.sleep(0.5)  # let the announce get there
    back = await self.echo('after rotation')
    assert back.ratchet_id == new.kid, 'echo was not sealed to our new ratchet'
    return 'echo used the new ratchet'

  async def link(self):
    await self.node.open_link(self.bot, self.timeout)
    back = await self.echo('link ping')
    assert back.link_id is not None, 'echo did not come over the link'
    return 'echo over the link'

  async def resource(self):
    data = os.urandom(5000)
    ok = await self.node.send_resource(self.bot, data, {'name': 'r.bin'}, self.timeout)
    assert ok, 'bot did not confirm the resource'
    back = await self.resources.get()
    assert back.data == data, 'resource echo differs'
    return f'{len(data)} bytes both ways'


async def stranger(road_factory, bot: bytes, timeout: float):
  """A node the bot has never heard of sends first: the bot must fetch our keyset."""
  node = Node(Identity.generate(), rebroadcast_delay=0.01)
  node.add_road(road_factory())
  box: asyncio.Queue = asyncio.Queue()
  node.on_message(lambda m: box.put_nowait(m))
  async with node:
    connected = getattr(node.lanes[0].road, 'connected', None)
    if connected is not None:  # a WebSocket client road: wait until it is up
      await asyncio.wait_for(connected.wait(), timeout)
    await node.request_path(bot, timeout, fresh=True)
    m = await node.send(bot, 'who am i')
    assert await node.delivered(m, timeout), 'no receipt'
    back = await asyncio.wait_for(box.get(), timeout)
    assert back.content == 'who am i'
  return 'bot fetched our keyset'


async def main() -> int:
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('bot', help='bot address (hex)')
  p.add_argument('--udp', type=hostport, help='local UDP address')
  p.add_argument('--udp-peer', type=hostport, action='append')
  p.add_argument('--ws', help='WebSocket server URL')
  p.add_argument('--timeout', type=float, default=20.0)
  a = p.parse_args()
  bot = bytes.fromhex(a.bot)

  def road():
    if a.ws:
      from cosechat.roads.websocket import WebSocketClientRoad

      return WebSocketClientRoad(a.ws)
    from cosechat.roads.udp import UDPRoad

    return UDPRoad(a.udp or ('0.0.0.0', 4242), a.udp_peer)

  node = Node(Identity.generate(), rebroadcast_delay=0.01, retry_after=2.0)
  node.add_road(road())
  r = Runner(node, bot, a.timeout)
  async with node:
    if a.ws:
      await asyncio.wait_for(node.lanes[0].road.connected.wait(), a.timeout)
    await r.check('find the bot (path request)', r.find())
    await node.announce()
    await r.check('sealed message, receipt, echo', r.sealed())
    await r.check('ratchet rotation', r.rotation())
    await r.check('link', r.link())
    await r.check('resource', r.resource())
  # a fresh identity on the same road (the first node has stopped): the bot
  # has never heard of it, so it must fetch its keyset to open the message
  await r.check('stranger (keyset fetch)', stranger(road, bot, a.timeout))
  passed = sum(r.results)
  print(f'\n{passed}/{len(r.results)} checks passed')
  return 0 if all(r.results) else 1


if __name__ == '__main__':
  sys.exit(asyncio.run(main()))
