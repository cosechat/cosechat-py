"""
RNode road: LoRa through an RNode (https://unsigned.io/rnode) on a serial
port, speaking the RNode KISS host protocol (from Reticulum's RNodeInterface).
Needs `pyserial`, unless you pass your own serial-like object.

The radio carries up to 508 bytes per frame (the firmware splits it over two
LoRa packets); Node fragments anything bigger.
"""

import asyncio
import threading
import time

from . import Road, kiss, log

CMD_DATA = 0x00
CMD_FREQUENCY = 0x01
CMD_BANDWIDTH = 0x02
CMD_TXPOWER = 0x03
CMD_SF = 0x04
CMD_CR = 0x05
CMD_RADIO_STATE = 0x06
CMD_RADIO_LOCK = 0x07
CMD_DETECT = 0x08
CMD_LEAVE = 0x0A
CMD_ST_ALOCK = 0x0B
CMD_LT_ALOCK = 0x0C
CMD_READY = 0x0F
CMD_STAT_RX = 0x21
CMD_STAT_TX = 0x22
CMD_STAT_RSSI = 0x23
CMD_STAT_SNR = 0x24
CMD_PLATFORM = 0x48
CMD_MCU = 0x49
CMD_FW_VERSION = 0x50
CMD_RESET = 0x55
CMD_ERROR = 0x90

DETECT_REQ = 0x73
DETECT_RESP = 0x46
RADIO_STATE_OFF = 0x00
RADIO_STATE_ON = 0x01

ERRORS = {
  0x01: 'radio initialisation failed',
  0x02: 'transmit failed',
  0x03: 'EEPROM locked',
  0x04: 'queue full',
  0x05: 'memory low',
  0x06: 'modem timeout',
}

RSSI_OFFSET = 157
REQUIRED_FIRMWARE = (1, 52)
HW_MTU = 508


def _u32(v: int) -> bytes:
  return v.to_bytes(4, 'big')


class RNodeError(Exception):
  pass


class RNodeRoad(Road):
  mtu = HW_MTU

  def __init__(
    self,
    port,
    frequency: int,
    bandwidth: int = 125000,
    txpower: int = 7,
    sf: int = 8,
    cr: int = 5,
    st_alock: float | None = None,
    lt_alock: float | None = None,
    flow_control: bool = False,
    baudrate: int = 115200,
    boot_delay: float = 2.0,
    timeout: float = 5.0,
    name: str | None = None,
  ):
    """`port` is a device path, or an open serial-like object (read/write/in_waiting)."""
    super().__init__(name or f'rnode:{port if isinstance(port, str) else "custom"}', HW_MTU)
    if not 137_000_000 <= frequency <= 3_000_000_000:
      raise ValueError('frequency out of range')
    if not 7_800 <= bandwidth <= 1_625_000:
      raise ValueError('bandwidth out of range')
    if not 5 <= sf <= 12 or not 5 <= cr <= 8 or not 0 <= txpower <= 37:
      raise ValueError('sf, cr or txpower out of range')
    self.port = port
    self.config = {
      'frequency': frequency,
      'bandwidth': bandwidth,
      'txpower': txpower,
      'sf': sf,
      'cr': cr,
    }
    # LoRa air bitrate (same formula as Reticulum), for the announce budget
    self.bitrate = sf * ((4.0 / cr) / (2**sf / (bandwidth / 1000))) * 1000
    self.st_alock = st_alock
    self.lt_alock = lt_alock
    self.flow_control = flow_control
    self.baudrate = baudrate
    self.boot_delay = boot_delay
    self.timeout = timeout

    self.serial = None
    self.detected = False
    self.firmware = None
    self.platform = None
    self.mcu = None
    self.reported: dict = {}
    self.radio_state = None
    self.rssi = None
    self.snr = None
    self.errors: list[str] = []

    self._decoder = kiss.Decoder(max_size=HW_MTU * 2 + 8)
    self._loop = None
    self._reader = None
    self._changed = asyncio.Event()
    self._ready = True
    self._queue: list[bytes] = []

  # --- lifecycle ---

  async def start(self):
    self._loop = asyncio.get_running_loop()
    if isinstance(self.port, str):
      try:
        import serial
      except ImportError as e:  # pragma: no cover
        raise ImportError('RNode road needs: pip install cosiechat[rnode]') from e
      self.serial = serial.Serial(self.port, self.baudrate, timeout=0.1, write_timeout=None)
    else:
      self.serial = self.port
    self._reader = threading.Thread(target=self._read_loop, daemon=True, name=self.name)
    self._reader.start()
    if self.boot_delay:
      await asyncio.sleep(self.boot_delay)

    await self._write(
      bytes(
        [
          kiss.FEND,
          CMD_DETECT,
          DETECT_REQ,
          kiss.FEND,
          CMD_FW_VERSION,
          0x00,
          kiss.FEND,
          CMD_PLATFORM,
          0x00,
          kiss.FEND,
          CMD_MCU,
          0x00,
          kiss.FEND,
        ]
      )
    )
    await self._wait(lambda: self.detected and self.firmware, 'device did not answer detect')
    if self.firmware < REQUIRED_FIRMWARE:
      raise RNodeError(f'firmware {self.firmware} too old, need {REQUIRED_FIRMWARE}')

    c = self.config
    await self._command(CMD_FREQUENCY, _u32(c['frequency']))
    await self._command(CMD_BANDWIDTH, _u32(c['bandwidth']))
    await self._command(CMD_TXPOWER, bytes([c['txpower']]))
    await self._command(CMD_SF, bytes([c['sf']]))
    await self._command(CMD_CR, bytes([c['cr']]))
    if self.st_alock is not None:
      await self._command(CMD_ST_ALOCK, int(self.st_alock * 100).to_bytes(2, 'big'))
    if self.lt_alock is not None:
      await self._command(CMD_LT_ALOCK, int(self.lt_alock * 100).to_bytes(2, 'big'))
    await self._command(CMD_RADIO_STATE, bytes([RADIO_STATE_ON]))
    await self._wait(
      lambda: self.radio_state == RADIO_STATE_ON and self.reported == self.config,
      'radio did not confirm configuration',
    )
    await super().start()

  async def stop(self):
    await super().stop()
    if self.serial:
      try:
        await self._write(kiss.frame(CMD_LEAVE, b'\xff'))
      except Exception:
        pass
      if isinstance(self.port, str):
        self.serial.close()
      self.serial = None

  # --- io ---

  async def send(self, frame: bytes):
    if len(frame) > HW_MTU:
      raise ValueError(f'{self}: frame of {len(frame)} bytes exceeds {HW_MTU}')
    if self.flow_control and not self._ready:
      self._queue.append(frame)
      return
    if self.flow_control:
      self._ready = False
    await self._write(kiss.frame(CMD_DATA, frame))

  async def _command(self, cmd: int, data: bytes):
    await self._write(kiss.frame(cmd, data))

  async def _write(self, data: bytes):
    await self._loop.run_in_executor(None, self.serial.write, data)

  async def _wait(self, cond, err: str):
    end = time.monotonic() + self.timeout
    while not cond():
      if self.errors:
        raise RNodeError(self.errors[-1])
      left = end - time.monotonic()
      if left <= 0:
        raise RNodeError(f'{self}: {err}')
      self._changed.clear()
      try:
        await asyncio.wait_for(self._changed.wait(), left)
      except TimeoutError:
        pass

  def _read_loop(self):
    while self.serial is not None:
      try:
        waiting = getattr(self.serial, 'in_waiting', 1)
        data = self.serial.read(max(1, waiting))
      except Exception as e:
        log.error('%s: serial read failed: %s', self, e)
        break
      if data:
        self._loop.call_soon_threadsafe(self._on_bytes, data)

  def _on_bytes(self, data: bytes):
    for cmd, body in self._decoder.feed(data):
      self._on_command(cmd, body)
    self._changed.set()

  def _on_command(self, cmd: int, d: bytes):
    if cmd == CMD_DATA:
      if d:
        self._deliver(d)
    elif cmd == CMD_DETECT:
      self.detected = d[:1] == bytes([DETECT_RESP])
    elif cmd == CMD_FW_VERSION and len(d) >= 2:
      self.firmware = (d[0], d[1])
    elif cmd == CMD_PLATFORM and d:
      self.platform = d[0]
    elif cmd == CMD_MCU and d:
      self.mcu = d[0]
    elif cmd == CMD_FREQUENCY and len(d) >= 4:
      self.reported['frequency'] = int.from_bytes(d[:4], 'big')
    elif cmd == CMD_BANDWIDTH and len(d) >= 4:
      self.reported['bandwidth'] = int.from_bytes(d[:4], 'big')
    elif cmd == CMD_TXPOWER and d:
      self.reported['txpower'] = d[0]
    elif cmd == CMD_SF and d:
      self.reported['sf'] = d[0]
    elif cmd == CMD_CR and d:
      self.reported['cr'] = d[0]
    elif cmd == CMD_RADIO_STATE and d:
      self.radio_state = d[0]
    elif cmd == CMD_STAT_RSSI and d:
      self.rssi = d[0] - RSSI_OFFSET
    elif cmd == CMD_STAT_SNR and d:
      self.snr = int.from_bytes(d[:1], 'big', signed=True) * 0.25
    elif cmd == CMD_READY:
      self._ready = True
      if self._queue:
        self._loop.create_task(self.send(self._queue.pop(0)))
    elif cmd == CMD_ERROR and d:
      err = ERRORS.get(d[0], f'hardware error 0x{d[0]:02x}')
      log.error('%s: %s', self, err)
      self.errors.append(err)
    elif cmd == CMD_RESET and d[:1] == b'\xf8' and self.online:
      log.error('%s: device reset while online', self)
      self.online = False
