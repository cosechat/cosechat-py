"""
Send messages to an echo bot and check they come back intact. Exits non-zero
if any echo is missing, so it doubles as a smoke test for any implementation
of the bot (Python, JS, Arduino).

  uv run examples/echo_client.py <bot address> [--count 3] [--listen 0.0.0.0:4242] [--peer HOST:PORT]
"""

import argparse
import asyncio
import sys
import time

from echo_bot import hostport

from cosechat import Identity, Node
from cosechat.roads.udp import UDPRoad


async def main() -> int:
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  p.add_argument('bot', help='echo bot address (hex)')
  p.add_argument('--listen', default='0.0.0.0:4242')
  p.add_argument('--peer', action='append', type=hostport, help='unicast peer (default: broadcast)')
  p.add_argument('--count', type=int, default=3)
  p.add_argument('--timeout', type=float, default=15.0)
  a = p.parse_args()
  bot = bytes.fromhex(a.bot)

  node = Node(Identity.generate(), app_data={'name': 'echo-client'})
  node.add_road(UDPRoad(hostport(a.listen), a.peer))
  replies: asyncio.Queue = asyncio.Queue()
  node.on_message(lambda m: replies.put_nowait(m) if m.sender == bot else None)

  failures = 0
  async with node:
    print(f'client {node.address.hex()}')
    await node.announce()
    if await node.request_path(bot, a.timeout) is None:
      print(f'bot {a.bot} did not answer a path request')
      return 1
    path = node.paths.get(bot)
    print(f'found bot, {path.hops if path else "?"} hop(s) away')
    for i in range(a.count):
      text = f'ping {i} {time.time():.3f}'
      start = time.monotonic()
      await node.send(bot, text, fields={'n': i})
      try:
        m = await asyncio.wait_for(replies.get(), a.timeout)
      except TimeoutError:
        print(f'{text!r}: no echo')
        failures += 1
        continue
      ok = m.content == text and m.fields == {'n': i}
      failures += not ok
      ms = (time.monotonic() - start) * 1000
      print(f'{text!r}: {"ok" if ok else "MISMATCH " + repr(m.content)} in {ms:.0f} ms')
  print('all echoes ok' if not failures else f'{failures} failed')
  return 1 if failures else 0


if __name__ == '__main__':
  sys.exit(asyncio.run(main()))
