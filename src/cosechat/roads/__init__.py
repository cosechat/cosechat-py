"""
Roads move opaque frames. They know nothing about identities or crypto; a
Node attaches to any number of them. A road is a broadcast medium: send()
reaches every peer on it, and received frames are handed to `on_frame`.

Road implementations:
  ``wifi_raw``      raw 802.11 management-frame road (no association needed)
  ``ble``           anonymous BLE extended-advertising road
  ``udp``           UDP datagrams (local broadcast or unicast peers)
  ``websocket``     WebSocket binary messages (server + client)
  ``rnode``         RNode LoRa radio over serial port (KISS protocol)
  ``kiss``          KISS frame decoder
  ``memory``        in-process roads for tests and simulations
  ``shared``        one physical road, several nodes (branches)
"""

import logging
from collections.abc import Callable

log = logging.getLogger('cosechat.road')


class Road:
  # largest frame this road can carry in one piece; Node fragments above it
  mtu = 500
  # bits per second, if the medium is slow enough that announces need a budget
  # (None: treat as unlimited, e.g. UDP on a LAN)
  bitrate: float | None = None

  def __init__(self, name: str | None = None, mtu: int | None = None):
    self.name = name or self.__class__.__name__
    if mtu is not None:
      self.mtu = mtu
    self.on_frame: Callable[[bytes], None] | None = None
    self.online = False

  def __repr__(self):
    return f'<{self.__class__.__name__} {self.name}>'

  async def start(self):
    self.online = True

  async def stop(self):
    self.online = False

  async def send(self, frame: bytes):
    raise NotImplementedError

  def _deliver(self, frame: bytes):
    if self.on_frame is None:
      return
    try:
      self.on_frame(frame)
    except Exception:
      log.exception('%s: frame handler failed', self)
