"""
UDP road. Each frame is one datagram. By default it broadcasts on the local
network, like Reticulum's UDPInterface; give `peers` for unicast links.
"""

import asyncio
import hashlib
import socket
from collections import deque

from . import Road, log

DEFAULT_PORT = 4242


class _Protocol(asyncio.DatagramProtocol):
  def __init__(self, road: 'UDPRoad'):
    self.road = road

  def datagram_received(self, data, addr):
    self.road._received(data, addr)

  def error_received(self, exc):
    log.debug('%s: %s', self.road, exc)


class UDPRoad(Road):
  # stays under common path MTUs so datagrams are not IP-fragmented
  mtu = 1200

  def __init__(
    self,
    listen: tuple[str, int] = ('0.0.0.0', DEFAULT_PORT),
    peers: list[tuple[str, int]] | None = None,
    name: str | None = None,
    mtu: int | None = None,
  ):
    super().__init__(name or f'udp:{listen[1]}', mtu)
    self.listen = listen
    self.peers = peers if peers is not None else [('255.255.255.255', listen[1])]
    self._transport = None
    self._sent = deque(maxlen=64)

  @property
  def port(self) -> int:
    return self._transport.get_extra_info('sockname')[1] if self._transport else self.listen[1]

  async def start(self):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(self.listen)
    self._transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(self), sock=sock)
    await super().start()

  async def stop(self):
    await super().stop()
    if self._transport:
      self._transport.close()
      self._transport = None

  async def send(self, frame: bytes):
    if not self._transport:
      return
    self._sent.append(hashlib.sha256(frame).digest()[:8])
    for peer in self.peers:
      self._transport.sendto(frame, peer)

  def _received(self, data: bytes, addr):
    # broadcasts come back to the sender; drop our own frames early
    if hashlib.sha256(data).digest()[:8] in self._sent:
      return
    self._deliver(data)
