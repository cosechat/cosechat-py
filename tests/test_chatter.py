"""Wi-Fi raw and BLE roads: codec tests + node integration via MemoryHub."""

import asyncio

import pytest
from test_node import inbox, run, until

from cosechat.node import Node
from cosechat.roads import ble, wifi_raw
from cosechat.roads.ble import BLE_MTU, COMPANY_ID
from cosechat.roads.memory import MemoryHub
from cosechat.roads.wifi_raw import WIFI_MTU

# --- Codec: 802.11 action frames -------------------------------------------


class TestWifiRawCodec:
  def test_roundtrip(self):
    payload = b'\x01\x02\x03' + bytes(range(240))
    src = wifi_raw.random_mac()
    frame = wifi_raw.encode(payload, src)
    assert len(frame) == 24 + 4 + len(payload)
    assert frame[0] & 0xFC == 0xD0
    assert frame[4:10] == wifi_raw.BROADCAST
    assert frame[10:16] == src
    assert frame[24] == wifi_raw.CATEGORY
    assert frame[25:28] == wifi_raw.OUI
    out = wifi_raw.decode(frame)
    assert out == payload

  def test_max_payload_fits(self):
    payload = bytes(WIFI_MTU)
    frame = wifi_raw.encode(payload)
    assert len(frame) == 24 + 4 + len(payload)

  def test_oversized_rejected(self):
    with pytest.raises(ValueError):
      wifi_raw.encode(bytes(WIFI_MTU + 1))

  def test_decode_bad_fc(self):
    frame = wifi_raw.encode(b'hi')
    frame = bytes([0x08]) + frame[1:]
    assert wifi_raw.decode(frame) is None

  def test_decode_non_broadcast(self):
    frame = wifi_raw.encode(b'hi')
    ba = bytearray(frame)
    ba[4:10] = bytes([0x02] * 6)
    assert wifi_raw.decode(bytes(ba)) is None

  def test_decode_noise(self):
    assert wifi_raw.decode(b'\x00' * 30) is None

  def test_mtu_constant(self):
    assert WIFI_MTU == 252


# --- Codec: BLE manufacturer data ------------------------------------------


class TestBleCodec:
  def test_roundtrip(self):
    frame = b'\x99' * 100
    ad = ble.encode(frame)
    assert ad[0] == 3 + 100
    assert ad[1] == 0xFF
    cid = ad[2] | (ad[3] << 8)
    assert cid == COMPANY_ID
    out = ble.decode(ad)
    assert out == frame

  def test_max_frame_fits(self):
    frame = bytes(BLE_MTU)
    ad = ble.encode(frame)
    assert len(ad) <= 252
    out = ble.decode(ad)
    assert out == frame

  def test_oversized_rejected(self):
    with pytest.raises(ValueError):
      ble.encode(bytes(BLE_MTU + 1))

  def test_decode_noise(self):
    assert ble.decode(b'') is None
    assert ble.decode(b'\x00' * 5) is None
    assert ble.decode(b'\x03\xff\xaa\xbb') is None

  def test_mtu_constant(self):
    assert BLE_MTU == 247


# --- Node integration via MemoryHub ----------------------------------------


class TestNodeIntegration:
  def test_two_nodes_via_memory_road(self):
    """Baseline: MemoryRoad with default MTU works."""

    async def main():
      hub = MemoryHub()
      a = Node(rebroadcast_delay=0)
      b = Node(rebroadcast_delay=0)
      a.add_road(hub.road())
      b.add_road(hub.road())
      box = inbox(b)
      async with a, b:
        await a.announce()
        await b.announce()
        await until(lambda: b.address in a.paths and a.address in b.paths)
        await a.send(b.address, 'memory-ok')
        await until(lambda: box)
      assert box[0].content == 'memory-ok'

    run(main())

  def test_two_nodes_via_wifi_mtu(self):
    """Wifi MTU over MemoryHub."""

    async def main():
      hub = MemoryHub()
      a = Node(rebroadcast_delay=0)
      b = Node(rebroadcast_delay=0)
      a.add_road(hub.road(mtu=WIFI_MTU))
      b.add_road(hub.road(mtu=WIFI_MTU))
      box = inbox(b)
      async with a, b:
        await a.announce()
        await b.announce()
        await until(lambda: b.address in a.paths and a.address in b.paths)
        await a.send(b.address, 'wifi-mtu-ok')
        await until(lambda: box)
      assert box[0].content == 'wifi-mtu-ok'

    run(main())

  def test_two_nodes_via_ble_mtu(self):
    """Ble MTU over MemoryHub."""

    async def main():
      hub = MemoryHub()
      a = Node(rebroadcast_delay=0)
      b = Node(rebroadcast_delay=0)
      a.add_road(hub.road(mtu=BLE_MTU))
      b.add_road(hub.road(mtu=BLE_MTU))
      box = inbox(b)
      async with a, b:
        await a.announce()
        await b.announce()
        await until(lambda: b.address in a.paths and a.address in b.paths)
        await a.send(b.address, 'ble-mtu-ok')
        await until(lambda: box)
      assert box[0].content == 'ble-mtu-ok'

    run(main())

  def test_different_mtus_isolated(self):
    """Roads with different MTUs are separate media: no cross-talk."""

    async def main():
      h1 = MemoryHub()
      h2 = MemoryHub()
      a = Node(rebroadcast_delay=0)
      b = Node(rebroadcast_delay=0)
      a.add_road(h1.road(mtu=WIFI_MTU))
      b.add_road(h2.road(mtu=BLE_MTU))
      box = inbox(b)
      async with a, b:
        await a.announce()
        await b.announce()
        await asyncio.sleep(0.3)
      assert len(box) == 0

    run(main())

  def test_transport_between_memory_hubs(self):
    """A transport node bridges two MemoryHubs (wifi- and ble-like)."""

    async def main():
      h1 = MemoryHub()
      h2 = MemoryHub()
      a = Node(rebroadcast_delay=0)
      c = Node(rebroadcast_delay=0)
      a.add_road(h1.road(mtu=WIFI_MTU))
      c.add_road(h1.road(mtu=WIFI_MTU))

      t = Node(transport=True, rebroadcast_delay=0)
      t.add_road(h1.road())
      t.add_road(h2.road())

      b = Node(rebroadcast_delay=0)
      b.add_road(h2.road(mtu=BLE_MTU))
      box = inbox(b)

      async with a, c, t, b:
        await a.announce()
        await b.announce()
        await until(lambda: b.address in a.paths)
        await until(lambda: a.address in b.paths)
        await a.send(b.address, 'via-transport')
        await until(lambda: box)
      assert box[0].content == 'via-transport'

    run(main())

  def test_raw_wifi_road_needs_an_interface(self):
    """Constructing is fine (the codec is module level); starting without an
    interface fails loudly instead of quietly dropping frames."""
    road = wifi_raw.RawWifiRoad()
    assert road.mtu == WIFI_MTU
    assert road.name == 'wifi-raw'
    assert road.interface is None
    with pytest.raises(RuntimeError, match='no interface'):
      run(road.start())

  def test_ble_road_no_adapter(self):
    """BLERoad with no adapter creates instance without error."""
    road = ble.BLERoad()
    assert road.mtu == BLE_MTU
    assert road.name == 'ble'

  def test_ble_send_raises_on_macos(self):
    """BLERoad.send() raises RuntimeError where real TX is unavailable."""
    road = ble.BLERoad()
    with pytest.raises(RuntimeError):
      run(road.send(b'test'))
