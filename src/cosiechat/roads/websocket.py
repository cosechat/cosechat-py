"""
WebSocket roads (binary messages, one frame each). Needs `websockets`.

  WebSocketServerRoad  accepts many peers; send() goes to all of them
  WebSocketClientRoad  connects to a server and reconnects when dropped

A server road is one shared medium: the node behind it (with transport=True)
relays between its clients, so browsers can reach each other and the rest of
the mesh through it.
"""

import asyncio

from . import Road, log

try:
  from websockets.asyncio.client import connect
  from websockets.asyncio.server import serve
  from websockets.exceptions import ConnectionClosed
except ImportError as e:  # pragma: no cover
  raise ImportError('WebSocket roads need: pip install cosiechat[websocket]') from e

WS_MTU = 1 << 20


class WebSocketServerRoad(Road):
  mtu = WS_MTU

  def __init__(
    self, host: str = '0.0.0.0', port: int = 4243, name: str | None = None, mtu: int | None = None
  ):
    super().__init__(name or f'ws-server:{port}', mtu)
    self.host = host
    self._port = port
    self._server = None
    self.clients: set = set()

  @property
  def port(self) -> int:
    if self._server:
      return next(iter(self._server.sockets)).getsockname()[1]
    return self._port

  async def start(self):
    self._server = await serve(self._handler, self.host, self._port, max_size=self.mtu)
    await super().start()

  async def stop(self):
    await super().stop()
    if self._server:
      self._server.close()
      await self._server.wait_closed()
      self._server = None

  async def _handler(self, ws):
    self.clients.add(ws)
    try:
      async for data in ws:
        if isinstance(data, bytes):
          self._deliver(data)
    except ConnectionClosed:
      pass
    finally:
      self.clients.discard(ws)

  async def send(self, frame: bytes):
    for ws in list(self.clients):
      try:
        await ws.send(frame)
      except ConnectionClosed:
        self.clients.discard(ws)


class WebSocketClientRoad(Road):
  mtu = WS_MTU

  def __init__(
    self, url: str, name: str | None = None, mtu: int | None = None, reconnect: float = 2.0
  ):
    super().__init__(name or url, mtu)
    self.url = url
    self.reconnect = reconnect
    self._ws = None
    self._task = None
    self.connected = asyncio.Event()

  async def start(self):
    await super().start()
    self._task = asyncio.get_running_loop().create_task(self._run())

  async def stop(self):
    await super().stop()
    if self._task:
      self._task.cancel()
      self._task = None
    if self._ws:
      await self._ws.close()

  async def _run(self):
    while self.online:
      try:
        async with connect(self.url, max_size=self.mtu) as ws:
          self._ws = ws
          self.connected.set()
          async for data in ws:
            if isinstance(data, bytes):
              self._deliver(data)
      except (OSError, ConnectionClosed) as e:
        log.debug('%s: %s', self, e)
      finally:
        self._ws = None
        self.connected.clear()
      if self.online:
        await asyncio.sleep(self.reconnect)

  async def send(self, frame: bytes):
    if self._ws is None:
      return
    try:
      await self._ws.send(frame)
    except ConnectionClosed:
      pass
