"""
The BLE road's BlueZ path, exercised against a fake D-Bus.

There is no Bluetooth stack in CI, so the two D-Bus touch points are faked:
the ``dbus_fast`` module (so ``import_dbus()`` takes the real branch) and the
bus itself.  What this checks is the part that would otherwise be untested --
that we export an ``org.bluez.LEAdvertisement1`` carrying the frame as
``ManufacturerData`` under ``COMPANY_ID``, register it on
``org.bluez.LEAdvertisingManager1``, hold it, and unregister it -- plus the
adapter capability gate and adapter discovery.
"""

import sys
import types

import pytest
from test_node import run

from cosechat.roads import ble
from cosechat.roads.ble import BLE_MTU, COMPANY_ID, BLERoad, BlueZAdvertiser


class FakeVariant:
  def __init__(self, signature, value):
    self.signature = signature
    self.value = value

  def __eq__(self, other):
    return (self.signature, self.value) == (other.signature, other.value)

  def __repr__(self):
    return f'Variant({self.signature!r}, {self.value!r})'


class FakeServiceInterface:
  def __init__(self, name):
    self.name = name


class FakeManager:
  def __init__(self, bus, path):
    self.bus = bus
    self.path = path

  @property
  def info(self):
    return self.bus.adapters[self.path]

  async def get_supported_capabilities(self):
    return self.info['caps']

  async def get_supported_secondary_channels(self):
    return self.info['channels']

  async def get_supported_instances(self):
    return 1

  async def call_register_advertisement(self, path, options):
    self.bus.registered.append((path, options))

  async def call_unregister_advertisement(self, path):
    self.bus.unregistered.append(path)


class FakeProxy:
  def __init__(self, bus, path):
    self.bus = bus
    self.path = path

  def get_interface(self, name):
    if name != ble.MGR_IFACE or self.path not in self.bus.adapters:
      raise RuntimeError(f'no {name} on {self.path}')
    return FakeManager(self.bus, self.path)


class FakeBus:
  def __init__(self, adapters):
    self.adapters = adapters
    self.exported = {}
    self.registered = []
    self.unregistered = []
    self.disconnected = False

  async def connect(self):
    return self

  def export(self, path, interface):
    self.exported[path] = interface

  def unexport(self, path, interface=None):
    self.exported.pop(path, None)

  def disconnect(self):
    self.disconnected = True

  def get_proxy_object(self, name, path):
    return FakeProxy(self, path)


FULL = {'MaxAdvLen': 251}
SMALL = {'MaxAdvLen': 31}


def make_bus(spec):
  """spec: {'hci0': (caps, channels), ...}"""
  return FakeBus(
    {f'/org/bluez/{name}': {'caps': caps, 'channels': ch} for name, (caps, ch) in spec.items()}
  )


def install_dbus(monkeypatch, bus):
  """Make ``import dbus_fast`` resolve to a fake, and mark the host as Linux."""
  top = types.ModuleType('dbus_fast')
  top.BusType = types.SimpleNamespace(SYSTEM='system')
  top.Variant = FakeVariant
  service = types.ModuleType('dbus_fast.service')
  service.ServiceInterface = FakeServiceInterface
  service.dbus_property = lambda fn: fn  # keep the getter callable in tests
  aio = types.ModuleType('dbus_fast.aio')
  aio.MessageBus = lambda **kw: bus
  top.service = service
  top.aio = aio
  for name, mod in (('dbus_fast', top), ('dbus_fast.service', service), ('dbus_fast.aio', aio)):
    monkeypatch.setitem(sys.modules, name, mod)
  monkeypatch.setattr(ble, '_linux', True)


def test_advertise_registers_then_unregisters(monkeypatch):
  bus = make_bus({'hci0': (FULL, ['1M', '2M'])})
  install_dbus(monkeypatch, bus)
  frame = bytes(range(200))

  async def main():
    adv = BlueZAdvertiser()
    await adv.open()
    assert adv.max_adv_len == 251
    await adv.advertise(frame, 0.01)
    await adv.close()

  run(main())

  assert len(bus.registered) == 1
  path, options = bus.registered[0]
  assert path.startswith('/com/cosechat/ble/') and options == {}
  assert bus.unregistered == [path]
  assert path not in bus.exported  # unexported again
  assert bus.disconnected


def test_advertisement_is_a_broadcast_with_our_manufacturer_data(monkeypatch):
  bus = make_bus({'hci0': (FULL, ['1M'])})
  install_dbus(monkeypatch, bus)
  frame = bytes([7]) * BLE_MTU
  seen = {}

  async def main():
    adv = BlueZAdvertiser()
    await adv.open()
    original = bus.export

    def keep(path, interface):
      seen['iface'] = interface
      original(path, interface)

    bus.export = keep
    await adv.advertise(frame, 0.01)

  run(main())

  iface = seen['iface']
  assert iface.name == ble.ADV_IFACE
  assert iface.Type() == 'broadcast'
  assert iface.SecondaryChannel() == '1M'
  assert iface.ManufacturerData() == {COMPANY_ID: FakeVariant('ay', list(frame))}
  # and the bytes BlueZ builds are the ones the C road expects on the air
  assert ble.decode(ble.encode(frame)) == frame


def test_open_refuses_an_adapter_without_extended_advertising(monkeypatch):
  install_dbus(monkeypatch, make_bus({'hci0': (SMALL, [])}))

  async def main():
    with pytest.raises(RuntimeError, match='251'):
      await BlueZAdvertiser().open()

  run(main())


def test_open_finds_the_first_adapter_that_advertises(monkeypatch):
  install_dbus(monkeypatch, make_bus({'hci2': (FULL, ['1M'])}))

  async def main():
    adv = BlueZAdvertiser()
    await adv.open()
    assert adv._path == '/org/bluez/hci2'
    await adv.close()

  run(main())


def test_open_honours_an_explicit_adapter_and_secondary_phy(monkeypatch):
  install_dbus(monkeypatch, make_bus({'hci0': (FULL, ['1M']), 'hci1': (FULL, ['2M'])}))

  async def main():
    adv = BlueZAdvertiser(adapter='hci1')
    await adv.open()
    assert adv._path == '/org/bluez/hci1'
    assert adv.secondary == '2M'  # '1M' is not offered here, so '2M' is chosen
    await adv.close()

  run(main())


def test_road_start_enables_tx_and_send_advertises(monkeypatch):
  bus = make_bus({'hci0': (FULL, ['1M'])})
  install_dbus(monkeypatch, bus)

  async def main():
    road = BLERoad(adv_ms=1)
    await road.start()
    assert road.tx_ready
    await road.send(b'road frame')
    await road.stop()

  run(main())

  assert len(bus.registered) == 1
  assert len(bus.unregistered) == 1


def test_road_stays_up_but_unsendable_without_a_usable_adapter(monkeypatch):
  install_dbus(monkeypatch, make_bus({'hci0': (SMALL, [])}))

  async def main():
    road = BLERoad(adv_ms=1)
    await road.start()  # logs and carries on
    assert not road.tx_ready
    with pytest.raises(RuntimeError, match='advertiser'):
      await road.send(b'x')
    await road.stop()

  run(main())
