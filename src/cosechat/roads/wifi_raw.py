"""
Raw 802.11 management-frame road: anonymous Wi-Fi broadcast.

Each cosechat frame rides one vendor-specific action frame (category 127,
OUI ``0xCC-0C-05``) addressed to the broadcast MAC.  An action frame needs
no association, no authentication and no ACK, so this road never joins a
network and leaves no state behind.  Both ends must sit on the same channel.

The sender uses a random locally-administered MAC address.

Real transport (Linux only): AF_PACKET raw socket on an interface in monitor
mode.  The user must place the interface in monitor mode on the desired
channel before creating the road::

    iw dev wlan0 set type monitor
    iw dev wlan0 set channel 6

Other platforms raise ``RuntimeError`` at ``start()``.  For tests and
simulation use ``memoy.MemoryHub`` with the right MTU::

    from cosechat.roads.memory import MemoryHub
    hub = MemoryHub()
    node.add_road(hub.road(mtu=WIFI_MTU))

Bits on the wire::

    [mgmt-hdr 24][cat=127][OUI 3][payload <=252]
       addr1 = ff:ff:ff:ff:ff:ff  (broadcast)
       addr2 = random local MAC
       addr3 = ff:ff:ff:ff:ff:ff
"""

import asyncio
import os
import platform
import socket as _socket

from . import Road

__all__ = ['WIFI_MTU', 'OUI', 'CATEGORY', 'RawWifiRoad', 'encode', 'decode', 'random_mac']

# 802.11 management frame layout
HDR = 24
ACTION = 4
CATEGORY = 127
OUI = bytes([0xCC, 0x0C, 0x05])
FRAME_MAX = 280
WIFI_MTU = FRAME_MAX - HDR - ACTION  # 252

BROADCAST = bytes([0xFF] * 6)
ACTION_FC = bytes([0xD0, 0x00])

_linux = platform.system() == 'Linux'

try:
  from socket import AF_PACKET, ETH_P_ALL, SOCK_RAW
except ImportError:
  AF_PACKET = ETH_P_ALL = SOCK_RAW = None  # type: ignore


def random_mac() -> bytes:
  """Return a 6-byte random locally-administered unicast MAC."""
  mac = bytearray(os.urandom(6))
  mac[0] = (mac[0] & 0xFC) | 0x02
  return bytes(mac)


def encode(payload: bytes, src: bytes | None = None) -> bytes:
  """Wrap *payload* in an 802.11 vendor-specific action frame.

  Raises ``ValueError`` when payload exceeds ``WIFI_MTU``.
  """
  if len(payload) > WIFI_MTU:
    raise ValueError(f'payload {len(payload)} > WIFI_MTU {WIFI_MTU}')
  if src is None:
    src = random_mac()
  frame = bytearray(HDR + ACTION + len(payload))
  frame[0:2] = ACTION_FC
  frame[4:10] = BROADCAST
  frame[10:16] = src
  frame[16:22] = BROADCAST
  frame[HDR] = CATEGORY
  frame[HDR + 1 : HDR + 4] = OUI
  frame[HDR + ACTION :] = payload
  return bytes(frame)


def decode(frame: bytes) -> bytes | None:
  """Extract payload from an 802.11 action frame, or ``None`` on mismatch."""
  if len(frame) < HDR + ACTION:
    return None
  if frame[0] & 0xFC != 0xD0:
    return None
  if frame[4:10] != BROADCAST:
    return None
  if frame[HDR] != CATEGORY:
    return None
  if frame[HDR + 1 : HDR + 4] != OUI:
    return None
  payload = frame[HDR + ACTION :]
  return payload if len(payload) <= WIFI_MTU else None


# ---------------------------------------------------------------------------
# Road
# ---------------------------------------------------------------------------


class RawWifiRoad(Road):
  """Anonymous 802.11 broadcast road.

  Parameters
  ----------
  interface : str, optional
      Linux WiFi interface in monitor mode (e.g. ``wlan0``).  When given,
      the road opens an AF_PACKET raw socket for real I/O.
      If omitted, the road is codec-only and raises at ``start()``.
  channel : int
      Channel number (metadata only; set the interface channel yourself).
  name : str, optional
      Road name.
  """

  def __init__(
    self,
    interface: str | None = None,
    channel: int = 1,
    name: str | None = None,
  ):
    super().__init__(name or 'wifi-raw', WIFI_MTU)
    self.interface = interface
    self.channel = channel
    self.src = random_mac()
    self._sock: _socket.socket | None = None
    self._reader: asyncio.Future | None = None
    self.bitrate = None  # unlimited (it's raw radio)

  async def start(self):
    if self.interface is None:
      raise RuntimeError(
        f'{self}: no interface. The raw 802.11 road needs a Linux WiFi '
        f'interface in monitor mode (or pass one); for tests and simulation '
        f'use MemoryHub with the same MTU.'
      )
    if not _linux or AF_PACKET is None:
      raise RuntimeError(
        f'{self}: AF_PACKET raw sockets are Linux-only. Use MemoryHub for emulation.'
      )
    sock = _socket.socket(AF_PACKET, SOCK_RAW, _socket.htons(ETH_P_ALL))
    sock.bind((self.interface, 0))
    sock.setblocking(False)
    self._sock = sock
    self._reader = asyncio.ensure_future(self._read_loop())
    await super().start()

  async def stop(self):
    if self._reader:
      self._reader.cancel()
      self._reader = None
    if self._sock:
      self._sock.close()
      self._sock = None
    await super().stop()

  async def send(self, frame: bytes):
    if self._sock is None:
      raise RuntimeError(f'{self}: not started (no AF_PACKET socket)')
    raw = encode(frame, self.src)
    try:
      self._sock.send(raw, 0)
    except OSError:
      pass  # interface down / queue full

  async def _read_loop(self):
    loop = asyncio.get_running_loop()
    while self.online and self._sock:
      try:
        data = await loop.sock_recv(self._sock, 65535)
      except (OSError, ConnectionError):
        break
      except asyncio.CancelledError:
        break
      payload = decode(bytes(data))
      if payload is not None:
        self._deliver(payload)
