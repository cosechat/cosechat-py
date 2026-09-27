"""
Packets: what travels on a road.

  packet   = [version, type, hops, dest, via, payload]
    version  protocol version, VERSION (0 while the spec is a draft); receivers
             drop frames with a version they do not implement
    type     0 ANNOUNCE, 1 DATA, 2 PATH_REQUEST, 4 RECEIPT,
             5 LINK_REQUEST, 6 LINK_ACCEPT, 7 LINK_DATA,
             8 KEEPALIVE, 9 KEYSET_REQUEST, 10 KEYSET
    hops     hops already travelled (originator sends 0)
    dest     16-byte destination address
    via      16-byte address of the transport node that should forward this, or null
    payload  bstr: announce (COSE_Sign1/Sign), sealed message (COSE_Encrypt0/Encrypt),
             a random tag for path requests, or receipt tag || nonce

  fragment = [version, 3, id, index, count, chunk]
    Roads with a small MTU (LoRa) carry big packets (PQ keys and signatures
    are kilobytes) as fragments. Fragments of one packet share an 8-byte id.

  road frame = packet | fragment, optionally wrapped in COSE_Mac0 or
               COSE_Encrypt0 under a road key (see RoadAuth).

The packet hash (for duplicate suppression) covers only the immutable parts:
SHA-256(CBOR [version, type, dest, payload]).
"""

import hashlib
import os
import time
from dataclasses import dataclass

from . import cbor, cose
from .identity import ADDRESS_SIZE
from .keys import A256GCM, HMAC_256_256, CoseError, Key, get_alg

VERSION = 0

ANNOUNCE = 0
DATA = 1
PATH_REQUEST = 2
FRAGMENT = 3
RECEIPT = 4
LINK_REQUEST = 5
LINK_ACCEPT = 6
LINK_DATA = 7
KEEPALIVE = 8
KEYSET_REQUEST = 9
KEYSET = 10

TYPES = {
  ANNOUNCE: 'ANNOUNCE',
  DATA: 'DATA',
  PATH_REQUEST: 'PATH_REQUEST',
  RECEIPT: 'RECEIPT',
  LINK_REQUEST: 'LINK_REQUEST',
  LINK_ACCEPT: 'LINK_ACCEPT',
  LINK_DATA: 'LINK_DATA',
  KEEPALIVE: 'KEEPALIVE',
  KEYSET_REQUEST: 'KEYSET_REQUEST',
  KEYSET: 'KEYSET',
}
# addressed to a node and routed like DATA
ROUTED = {DATA, RECEIPT, LINK_REQUEST, LINK_ACCEPT, LINK_DATA}

FRAGMENT_ID_SIZE = 8
# array(1) + version(1) + type(1) + id(1+8) + index(3) + count(3) + chunk header(3)
FRAGMENT_OVERHEAD = 21


class PacketError(Exception):
  pass


@dataclass
class Packet:
  type: int
  hops: int
  dest: bytes
  via: bytes | None
  payload: bytes

  def encode(self) -> bytes:
    return cbor.dumps([VERSION, self.type, self.hops, self.dest, self.via, self.payload])

  @property
  def hash(self) -> bytes:
    return hashlib.sha256(cbor.dumps([VERSION, self.type, self.dest, self.payload])).digest()

  def __repr__(self):
    via = self.via.hex()[:8] if self.via else '-'
    return f'<{TYPES.get(self.type, self.type)} dest={self.dest.hex()[:8]} hops={self.hops} via={via} {len(self.payload)}B>'


def _check_addr(a, nullable=False):
  if a is None and nullable:
    return
  if not isinstance(a, bytes) or len(a) != ADDRESS_SIZE:
    raise PacketError('bad address')


def decode(frame: bytes):
  """Returns a Packet, or a Fragment tuple (id, index, count, chunk)."""
  try:
    arr = cbor.loads(frame)
  except Exception as e:
    raise PacketError(f'bad CBOR: {e}') from None
  if not isinstance(arr, list) or len(arr) < 2 or not all(isinstance(x, int) for x in arr[:2]):
    raise PacketError('not a packet')
  if arr[0] != VERSION:
    raise PacketError(f'unsupported protocol version {arr[0]}')
  arr = arr[1:]
  if arr[0] == FRAGMENT:
    if len(arr) != 5:
      raise PacketError('bad fragment')
    _, fid, index, count, chunk = arr
    if not (isinstance(fid, bytes) and isinstance(chunk, bytes) and 0 <= index < count):
      raise PacketError('bad fragment')
    return (fid, index, count, chunk)
  if arr[0] not in TYPES or len(arr) != 5:
    raise PacketError('unknown packet type')
  t, hops, dest, via, payload = arr
  _check_addr(dest)
  _check_addr(via, nullable=True)
  if not isinstance(hops, int) or hops < 0 or not isinstance(payload, bytes):
    raise PacketError('bad packet')
  return Packet(t, hops, dest, via, payload)


def fragment(frame: bytes, chunk_size: int) -> list[bytes]:
  if chunk_size <= 0:
    raise PacketError('road MTU too small to fragment into')
  fid = os.urandom(FRAGMENT_ID_SIZE)
  chunks = [frame[i : i + chunk_size] for i in range(0, len(frame), chunk_size)]
  return [cbor.dumps([VERSION, FRAGMENT, fid, i, len(chunks), c]) for i, c in enumerate(chunks)]


class Reassembler:
  """Collects fragments per (source key, fragment id). Incomplete sets expire."""

  def __init__(self, timeout: float = 60.0, max_sets: int = 256, max_size: int = 1 << 20):
    self.timeout = timeout
    self.max_sets = max_sets
    self.max_size = max_size
    self._sets: dict = {}

  def add(self, source, frag) -> bytes | None:
    fid, index, count, chunk = frag
    now = time.monotonic()
    self._expire(now)
    key = (source, fid)
    entry = self._sets.get(key)
    if entry is None:
      if len(self._sets) >= self.max_sets:
        self._sets.pop(next(iter(self._sets)))
      entry = self._sets[key] = {'count': count, 'chunks': {}, 'size': 0, 'time': now}
    if entry['count'] != count:
      self._sets.pop(key)
      return None
    if index not in entry['chunks']:
      entry['chunks'][index] = chunk
      entry['size'] += len(chunk)
    if entry['size'] > self.max_size:
      self._sets.pop(key)
      return None
    if len(entry['chunks']) == count:
      self._sets.pop(key)
      return b''.join(entry['chunks'][i] for i in range(count))
    return None

  def _expire(self, now):
    for key in [k for k, e in self._sets.items() if now - e['time'] > self.timeout]:
      self._sets.pop(key)


class RoadAuth:
  """
  Optional per-road protection with a shared road key (like Reticulum IFAC):
    mode 'mac'      frames are COSE_Mac0 (outsiders can read headers, cannot inject)
    mode 'encrypt'  frames are COSE_Encrypt0 (outsiders cannot even see addresses)
  """

  def __init__(self, key: Key, mode: str = 'mac'):
    if mode not in ('mac', 'encrypt'):
      raise ValueError('mode must be mac or encrypt')
    self.key = key
    self.mode = mode
    probe = self.wrap(b'')
    self.overhead = len(probe) + 3

  @classmethod
  def from_passphrase(cls, passphrase: str, mode: str = 'mac') -> 'RoadAuth':
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    alg = HMAC_256_256 if mode == 'mac' else A256GCM
    size = get_alg(alg).key_size
    k = HKDF(hashes.SHA256(), size, b'cosiechat road key', mode.encode()).derive(
      passphrase.encode()
    )
    return cls(Key(alg, priv=k), mode)

  def wrap(self, frame: bytes) -> bytes:
    if self.mode == 'mac':
      return cose.mac0(frame, self.key)
    return cose.encrypt0(frame, self.key)

  def unwrap(self, data: bytes) -> bytes:
    try:
      if self.mode == 'mac':
        return cose.verify_mac0(data, self.key)
      return cose.decrypt0(data, self.key)
    except CoseError as e:
      raise PacketError(f'road auth failed: {e}') from None
    except Exception as e:
      raise PacketError(f'road auth failed: {e!r}') from None
