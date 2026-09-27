"""
One physical road, several nodes: for running several identities (apps) on
one device over one radio or socket. There is no protocol change: each node
gets a virtual road; what one sends goes out on the real road and to the
other nodes on this device, and what the real road receives goes to all.

  shared = SharedRoad(RNodeRoad(...))
  chat = Node(chat_identity); chat.add_road(shared.branch())
  bot = Node(bot_identity);  bot.add_road(shared.branch())

(Reticulum gives one identity several "aspects"; here an address is one
keyset, so an app that wants its own address uses its own identity.)
"""

import asyncio

from . import Road


class SharedRoad:
  def __init__(self, road: Road):
    self.road = road
    self.branches: list[Branch] = []
    road.on_frame = self._received
    self._users = 0

  def branch(self, name: str | None = None) -> 'Branch':
    b = Branch(self, name or f'{self.road.name}#{len(self.branches)}')
    self.branches.append(b)
    return b

  def _received(self, frame: bytes):
    for b in self.branches:
      if b.online:
        b._deliver(frame)

  async def _start(self):
    self._users += 1
    if self._users == 1:
      await self.road.start()

  async def _stop(self):
    self._users -= 1
    if self._users == 0:
      await self.road.stop()


class Branch(Road):
  def __init__(self, shared: SharedRoad, name: str):
    super().__init__(name, shared.road.mtu)
    self.shared = shared
    self.bitrate = shared.road.bitrate

  async def start(self):
    await self.shared._start()
    await super().start()

  async def stop(self):
    await super().stop()
    await self.shared._stop()

  async def send(self, frame: bytes):
    loop = asyncio.get_running_loop()
    for b in self.shared.branches:
      if b is not self and b.online:
        loop.call_soon(b._deliver, bytes(frame))  # siblings on this device
    await self.shared.road.send(frame)
