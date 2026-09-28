"""
Anonymous BLE extended-advertising road.

Each cosechat frame rides one BLE 5 extended advertisement as
manufacturer-specific data (company id ``0xFFFF``): non-connectable,
non-scannable, no GATT, no bonding.  On the wire each advertisement carries at
most 251 bytes of AD data; with the AD header (2) and company id (2) that
leaves ``BLE_MTU`` (247) bytes for one road frame, so what a node transmits is
exactly ``encode(frame)``.  The same bytes come off an ESP32 running the C
reference (``road_ble.cpp``), so the two interoperate.

Real transport (Linux)
  Both directions go through BlueZ over D-Bus (``dbus-fast``, which bleak
  already pulls in; ``dbus-next`` works too):

  * **TX** registers an ``org.bluez.LEAdvertisement1`` object whose
    ``ManufacturerData`` is ``{0xFFFF: frame}``, waits ``adv_ms``, unregisters.
    BlueZ builds the AD structure, so the air bytes match ``encode()``.
  * **RX** reads ``ManufacturerData`` from advertisements seen by BlueZ.

  Extended advertising needs a controller and kernel that support it; the
  adapter must report ``SupportedCapabilities.MaxAdvLen >= 251`` (BlueZ says so
  through ``org.bluez.LEAdvertisingManager1``).  On other platforms, or when
  the adapter is too small, ``start()`` logs and ``send()`` raises.

  Honest gap vs the ESP32 road: BlueZ always puts the adapter's address in the
  advertisement, so a host node is not *address-less* the way
  ``road_ble.cpp``'s ``setAnonymous(true)`` makes the ESP32 one.  It is still
  non-connectable and carries nothing but the frame.

Tests / simulation
  Use ``MemoryHub`` with the right MTU::

    from cosechat.roads.memory import MemoryHub
    hub = MemoryHub()
    node.add_road(hub.road(mtu=BLE_MTU))
"""

import asyncio
import platform
import uuid

from . import Road, log

__all__ = [
  'ADV_MAX',
  'BLE_MTU',
  'BLERoad',
  'COMPANY_ID',
  'decode',
  'encode',
]

COMPANY_ID = 0xFFFF  # reserved for testing (matches the C road)
ADV_MAX = 251  # BLE 5 extended-advertising data limit
BLE_MTU = ADV_MAX - 4  # 247: ADV_MAX minus AD header (2) and company id (2)

AD_TYPE_MANUFACTURER = 0xFF

BLUEZ = 'org.bluez'
ADV_IFACE = 'org.bluez.LEAdvertisement1'
MGR_IFACE = 'org.bluez.LEAdvertisingManager1'

_linux = platform.system() == 'Linux'


def encode(frame: bytes) -> bytes:
  """Wrap road *frame* in a Manufacturer-Specific AD structure.

  This is what a node puts on the air; BlueZ builds the same bytes from
  ``ManufacturerData``.  Raises ``ValueError`` when frame exceeds ``BLE_MTU``.
  """
  if len(frame) > BLE_MTU:
    raise ValueError(f'frame {len(frame)} > BLE_MTU {BLE_MTU}')
  ad = bytearray(4 + len(frame))
  ad[0] = 3 + len(frame)  # length (type + company id + data)
  ad[1] = AD_TYPE_MANUFACTURER
  ad[2] = COMPANY_ID & 0xFF
  ad[3] = (COMPANY_ID >> 8) & 0xFF
  ad[4:] = frame
  return bytes(ad)


def decode(ad: bytes) -> bytes | None:
  """Extract a road frame from a Manufacturer-Specific AD, or ``None``."""
  if len(ad) < 5:
    return None
  ad_len = ad[0]
  if ad_len + 1 > len(ad):
    return None
  if ad[1] != AD_TYPE_MANUFACTURER:
    return None
  if ad_len < 3:
    return None
  cid = ad[2] | (ad[3] << 8)
  if cid != COMPANY_ID:
    return None
  frame = ad[4 : ad_len + 1]
  return frame if len(frame) <= BLE_MTU else None


# ---------------------------------------------------------------------------
# BlueZ (D-Bus) transport
# ---------------------------------------------------------------------------


def import_dbus():
  """Return the dbus module to use, or raise ImportError with a hint.

  ``dbus-fast`` is what bleak uses on Linux; ``dbus-next`` exposes the same
  service API, so either works.
  """
  try:
    import dbus_fast as dbus
    import dbus_fast.service as service
    from dbus_fast.aio import MessageBus
  except ImportError:
    try:
      import dbus_next as dbus
      import dbus_next.service as service
      from dbus_next.aio import MessageBus
    except ImportError:
      raise ImportError(
        'the BLE road needs dbus-fast or dbus-next: pip install cosechat[ble]'
      ) from None
  return dbus, service, MessageBus


def advertisement_class(service, Variant):
  """Build the ``org.bluez.LEAdvertisement1`` class for a dbus module.

  BlueZ builds the AD structure from these properties, so the frame is carried
  verbatim in ``ManufacturerData``.  ``Type='broadcast'`` makes it
  non-connectable (like the ESP32 road's anonymous advertising).
  """

  class Advertisement(service.ServiceInterface):
    def __init__(self, data: bytes, secondary: str | None = None, tx_power: int | None = None):
      super().__init__(ADV_IFACE)
      self._data = bytes(data)
      self._secondary = secondary
      self._tx_power = tx_power

    @service.dbus_property
    def Type(self) -> 's':
      return 'broadcast'

    @service.dbus_property
    def ManufacturerData(self) -> 'a{qv}':
      return {COMPANY_ID: Variant('ay', list(self._data))}

    @service.dbus_property
    def SecondaryChannel(self) -> 's':
      # "1M" is BlueZ's documented default; a non-empty value also selects an
      # extended advertising set, which is what a 251-byte AD needs
      return self._secondary or '1M'

    @service.dbus_property
    def TxPower(self) -> 'n':
      return self._tx_power if self._tx_power is not None else 0

  return Advertisement


class BlueZAdvertiser:
  """Registers one advertisement at a time with BlueZ.

  BlueZ has no "update the advertisement in place", so each frame is a fresh
  object: export, register, hold for ``adv_ms``, unregister, unexport.  That is
  also how the ESP32 road swaps its advertisement per fragment.
  """

  def __init__(
    self,
    adapter: str | None = None,
    secondary: str | None = None,
    tx_power: int | None = None,
  ):
    self.adapter = adapter
    self.secondary = secondary
    self.tx_power = tx_power
    self.max_adv_len: int | None = None
    self._bus = None
    self._mgr = None
    self._path = None
    self._adv_cls = None

  @property
  def path(self) -> str | None:
    return self._path

  async def open(self):
    if not _linux:
      raise RuntimeError('BLE advertising needs Linux + BlueZ')
    dbus, service, message_bus = import_dbus()
    self._adv_cls = advertisement_class(service, dbus.Variant)
    self._bus = await message_bus(bus_type=dbus.BusType.SYSTEM).connect()
    self._path = await self._find_adapter()
    proxy = self._bus.get_proxy_object(BLUEZ, self._path)
    self._mgr = proxy.get_interface(MGR_IFACE)
    caps = await self._mgr.get_supported_capabilities()
    self.max_adv_len = caps.get('MaxAdvLen') if caps else None
    if self.max_adv_len is not None and self.max_adv_len < BLE_MTU + 4:
      raise RuntimeError(
        f'{self._path} advertises at most {self.max_adv_len} AD bytes; '
        f'the road needs {BLE_MTU + 4} (extended advertising)'
      )
    if self.secondary is None:
      channels = await self._mgr.get_supported_secondary_channels()
      # a secondary channel selects an extended advertising set, which is what
      # a 251-byte advertisement needs; prefer the most compatible PHY
      for phy in ('1M', '2M', 'Coded'):
        if channels and phy in channels:
          self.secondary = phy
          break

  async def _find_adapter(self) -> str:
    if self.adapter:
      return self.adapter if self.adapter.startswith('/') else f'/org/bluez/{self.adapter}'
    for i in range(8):
      path = f'/org/bluez/hci{i}'
      try:
        mgr = self._bus.get_proxy_object(BLUEZ, path).get_interface(MGR_IFACE)
        await mgr.get_supported_instances()  # the call that proves it is there
        return path
      except Exception:
        continue
    raise RuntimeError(f'no BlueZ adapter with {MGR_IFACE}')

  async def advertise(self, frame: bytes, seconds: float):
    """Broadcast ``frame`` for ``seconds`` seconds."""
    if self._mgr is None:
      raise RuntimeError('advertiser is not open')
    if len(frame) > BLE_MTU:
      raise ValueError(f'frame {len(frame)} > BLE_MTU {BLE_MTU}')
    path = f'/com/cosechat/ble/{uuid.uuid4().hex}'
    adv = self._adv_cls(frame, self.secondary, self.tx_power)
    self._bus.export(path, adv)
    try:
      await self._mgr.call_register_advertisement(path, {})
      await asyncio.sleep(seconds)
      await self._mgr.call_unregister_advertisement(path)
    finally:
      try:
        self._bus.unexport(path, adv)
      except Exception:
        pass

  async def close(self):
    if self._bus is not None:
      try:
        self._bus.disconnect()
      except Exception:
        pass
    self._bus = self._mgr = None


# ---------------------------------------------------------------------------
# bleak scanner (cross-platform RX)
# ---------------------------------------------------------------------------

try:
  from bleak import BleakScanner

  _SCAN_AVAILABLE = True
except ImportError:
  _SCAN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Road
# ---------------------------------------------------------------------------


class BLERoad(Road):
  """Anonymous BLE extended-advertising road.

  Parameters
  ----------
  adapter : str, optional
      BlueZ adapter (``hci1`` or ``/org/bluez/hci1``).  Defaults to the first
      adapter that advertises.
  adv_ms : int
      How long each frame stays on air.  Longer than the ESP32 road's 120 ms
      because BlueZ's advertising interval is coarser, so a short window can
      mean a frame that never leaves the controller.
  tx_power, secondary : optional
      Passed through to BlueZ (dBm; ``'1M'``/``'2M'``/``'Coded'``).
  """

  def __init__(
    self,
    adapter: str | None = None,
    adv_ms: int = 250,
    tx_power: int | None = None,
    secondary: str | None = None,
    name: str | None = None,
  ):
    super().__init__(name or 'ble', BLE_MTU)
    self.bitrate = 1_000_000  # 1 Mbps BLE PHY
    self.adv_ms = adv_ms
    self._advertiser = BlueZAdvertiser(adapter, secondary, tx_power)
    self._scanner = None
    self.tx_ready = False

  @property
  def adapter(self):
    return self._advertiser.adapter

  async def start(self):
    self._start_scan()
    if _linux:
      try:
        await self._advertiser.open()
        self.tx_ready = True
        log.info(
          '%s: advertising through BlueZ on %s (max %s AD bytes)',
          self,
          self._advertiser.path,
          self._advertiser.max_adv_len,
        )
      except Exception as exc:
        log.warning('%s: cannot advertise: %s', self, exc)
    else:
      log.warning('%s: advertising needs Linux + BlueZ; scanning only', self)
    await super().start()

  async def stop(self):
    await super().stop()
    if self._scanner is not None:
      try:
        await self._scanner.stop()
      except Exception:
        pass
      self._scanner = None
    await self._advertiser.close()
    self.tx_ready = False

  async def send(self, frame: bytes):
    if not self.tx_ready:
      raise RuntimeError(
        f'{self}: no BLE advertiser (needs Linux, BlueZ and an adapter that '
        f'supports extended advertising). Use MemoryHub for emulation.'
      )
    await self._advertiser.advertise(frame, self.adv_ms / 1000)

  def _start_scan(self):
    if not _SCAN_AVAILABLE:
      log.warning('%s: bleak not installed; scanning disabled', self)
      return
    try:
      self._scanner = BleakScanner(detection_callback=self._on_scan)
    except TypeError:  # very old bleak
      log.warning('%s: this bleak cannot filter; scanning disabled', self)
      return

    async def run():
      try:
        await self._scanner.start()
      except Exception as exc:  # no adapter, no permission: say so, keep the road up
        log.warning('%s: scan failed: %s', self, exc)

    asyncio.get_running_loop().create_task(run())

  def _on_scan(self, device, advertisement_data):
    """A frame arrived in some advertisement's manufacturer data."""
    data = getattr(advertisement_data, 'manufacturer_data', None) or {}
    frame = data.get(COMPANY_ID)
    if frame:
      self._deliver(bytes(frame))
