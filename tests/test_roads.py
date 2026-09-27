"""Roads over real sockets (localhost) and an emulated RNode on a fake serial port."""

import asyncio
import queue
import threading

from test_node import inbox, run, until

from cosiechat.identity import Identity
from cosiechat.node import Node
from cosiechat.roads import kiss
from cosiechat.roads import rnode as R
from cosiechat.roads.udp import UDPRoad
from cosiechat.roads.websocket import WebSocketClientRoad, WebSocketServerRoad


async def exchange(a, b, content='hi'):
  box = inbox(b)
  await a.announce()
  await b.announce()
  await until(lambda: b.address in a.paths and a.address in b.paths)
  await a.send(b.address, content)
  await until(lambda: box)
  return box[0]


# --- UDP ---


def test_udp_unicast_pair():
  async def main():
    ra = UDPRoad(('127.0.0.1', 0), peers=[])
    rb = UDPRoad(('127.0.0.1', 0), peers=[])
    a = Node(rebroadcast_delay=0)
    b = Node(rebroadcast_delay=0)
    a.add_road(ra)
    b.add_road(rb)
    async with a, b:
      ra.peers = [('127.0.0.1', rb.port)]
      rb.peers = [('127.0.0.1', ra.port)]
      m = await exchange(a, b, 'over udp, fragmented')
    assert m.content == 'over udp, fragmented'

  run(main())


# --- WebSocket ---


def test_websocket_clients_meet_through_server_node():
  async def main():
    server_road = WebSocketServerRoad('127.0.0.1', 0)
    hubnode = Node(transport=True, rebroadcast_delay=0)
    hubnode.add_road(server_road)
    async with hubnode:
      url = f'ws://127.0.0.1:{server_road.port}'
      ca, cb = WebSocketClientRoad(url), WebSocketClientRoad(url)
      a = Node(rebroadcast_delay=0)
      b = Node(rebroadcast_delay=0)
      a.add_road(ca)
      b.add_road(cb)
      async with a, b:
        await ca.connected.wait()
        await cb.connected.wait()
        await until(lambda: len(server_road.clients) == 2)
        m = await exchange(a, b, 'via websocket hub')
        assert a.paths[b.address].via == hubnode.address
    assert m.content == 'via websocket hub'

  run(main())


# --- KISS ---


def test_kiss_roundtrip_with_special_bytes():
  data = bytes([0x00, kiss.FEND, 0x01, kiss.FESC, kiss.FEND, kiss.FESC, 0xFF])
  wire = kiss.frame(R.CMD_DATA, data)
  assert kiss.FEND not in wire[1:-1]
  d = kiss.Decoder()
  frames = []
  for i in range(len(wire)):  # byte at a time, like a slow serial port
    frames += d.feed(wire[i : i + 1])
  assert frames == [(R.CMD_DATA, data)]


# --- RNode ---


class Air:
  """The shared LoRa channel between emulated RNodes."""

  def __init__(self):
    self.radios = []


class FakeRNode:
  """Serial-port stand-in that answers like RNode firmware 1.80."""

  def __init__(self, air: Air):
    self.air = air
    air.radios.append(self)
    self.rx = queue.Queue()
    self.decoder = kiss.Decoder()
    self.state = {}
    self.on = False
    self.lock = threading.Lock()

  @property
  def in_waiting(self):
    return self.rx.qsize()

  def read(self, n=1):
    try:
      out = self.rx.get(timeout=0.05)
    except queue.Empty:
      return b''
    return out

  def write(self, data):
    with self.lock:
      for cmd, body in self.decoder.feed(data):
        self.command(cmd, body)
    return len(data)

  def reply(self, cmd, body=b''):
    self.rx.put(kiss.frame(cmd, body))

  def command(self, cmd, body):
    if cmd == R.CMD_DETECT and body == bytes([R.DETECT_REQ]):
      self.reply(R.CMD_DETECT, bytes([R.DETECT_RESP]))
    elif cmd == R.CMD_FW_VERSION:
      self.reply(R.CMD_FW_VERSION, bytes([1, 80]))
    elif cmd == R.CMD_PLATFORM:
      self.reply(R.CMD_PLATFORM, bytes([0x80]))
    elif cmd == R.CMD_MCU:
      self.reply(R.CMD_MCU, bytes([0x81]))
    elif cmd in (R.CMD_FREQUENCY, R.CMD_BANDWIDTH, R.CMD_TXPOWER, R.CMD_SF, R.CMD_CR):
      self.state[cmd] = body
      self.reply(cmd, body)
    elif cmd == R.CMD_RADIO_STATE:
      self.on = body == bytes([R.RADIO_STATE_ON])
      self.reply(R.CMD_RADIO_STATE, body)
    elif cmd == R.CMD_DATA and self.on:
      assert len(body) <= R.HW_MTU
      for other in self.air.radios:
        if other is not self and other.on and other.state == self.state:
          other.reply(R.CMD_STAT_RSSI, bytes([157 - 42]))
          other.reply(R.CMD_STAT_SNR, bytes([40]))
          other.reply(R.CMD_DATA, body)


def lora(air, frequency=868_000_000):
  return R.RNodeRoad(FakeRNode(air), frequency=frequency, sf=9, boot_delay=0, timeout=2)


def test_rnode_pq_message_over_emulated_lora():
  async def main():
    air = Air()
    ra, rb = lora(air), lora(air)
    a = Node(rebroadcast_delay=0)
    b = Node(rebroadcast_delay=0)
    a.add_road(ra)
    b.add_road(rb)
    async with a, b:
      assert ra.firmware == (1, 80)
      assert ra.reported == ra.config
      m = await exchange(a, b, 'post-quantum over LoRa')
      assert rb.rssi == -42 and rb.snr == 10.0
    assert m.content == 'post-quantum over LoRa'

  run(main())


def test_rnode_radios_on_other_frequency_hear_nothing():
  async def main():
    air = Air()
    ra, rb = lora(air), lora(air, frequency=915_000_000)
    a = Node(Identity.generate('prequantum'), rebroadcast_delay=0, quantum_safe_only=False)
    b = Node(Identity.generate('prequantum'), rebroadcast_delay=0, quantum_safe_only=False)
    a.add_road(ra)
    b.add_road(rb)
    async with a, b:
      await b.announce()
      await asyncio.sleep(0.2)
      assert b.address not in a.paths

  run(main())


def test_lora_and_udp_bridged_by_transport_node():
  """a (LoRa) -> gateway (LoRa + UDP) -> b (UDP): one message, two roads."""

  async def main():
    air = Air()
    ug, ub = UDPRoad(('127.0.0.1', 0), peers=[]), UDPRoad(('127.0.0.1', 0), peers=[])
    a = Node(rebroadcast_delay=0)
    a.add_road(lora(air))
    gw = Node(transport=True, rebroadcast_delay=0)
    gw.add_road(lora(air))
    gw.add_road(ug)
    b = Node(rebroadcast_delay=0)
    b.add_road(ub)
    async with a, gw, b:
      ug.peers = [('127.0.0.1', ub.port)]
      ub.peers = [('127.0.0.1', ug.port)]
      m = await exchange(a, b, 'lora to udp')
      assert b.paths[a.address].via == gw.address
    assert m.content == 'lora to udp'

  run(main())
