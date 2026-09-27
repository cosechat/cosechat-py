"""In-process road for tests and simulations: every road on a hub hears every other."""

import asyncio
import random

from . import Road


class MemoryHub:
  def __init__(self, loss: float = 0.0, latency: float = 0.0):
    self.loss = loss
    self.latency = latency
    self.roads: list[MemoryRoad] = []
    self.frames = 0

  def road(self, name: str | None = None, mtu: int = 500) -> 'MemoryRoad':
    return MemoryRoad(self, name, mtu)


class MemoryRoad(Road):
  def __init__(self, hub: MemoryHub, name: str | None = None, mtu: int = 500):
    super().__init__(name, mtu)
    self.hub = hub
    hub.roads.append(self)

  async def send(self, frame: bytes):
    if len(frame) > self.mtu:
      raise ValueError(f'{self}: frame of {len(frame)} bytes exceeds MTU {self.mtu}')
    self.hub.frames += 1
    loop = asyncio.get_running_loop()
    for r in self.hub.roads:
      if r is self or not r.online:
        continue
      if self.hub.loss and random.random() < self.hub.loss:
        continue
      loop.call_later(self.hub.latency, r._deliver, bytes(frame))
