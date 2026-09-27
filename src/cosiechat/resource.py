"""
Resources: large transfers over a link (like Reticulum's Resources).

A resource is split into parts that each fit one road frame. The receiver
pulls them in windows, so it controls the pace and asks again for anything
that went missing. Everything travels as link messages, so it is encrypted
and authenticated by the link keys. Link body fields used:

  8   advertise  {1: resource id (16), 2: size, 3: part count, 4: SHA-256 of all, 5: meta}
  9   request    [resource id, [part index, ...]]
  10  part       [resource id, index, bytes]
  11  done       resource id

resource id = SHA-256(data)[0:16]
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import cbor
from .keys import CoseError

R_ADVERTISE = 8
R_REQUEST = 9
R_PART = 10
R_DONE = 11

RESOURCE_ID_SIZE = 16
PART_SIZE = 320  # bytes of data per part: a part link message fits a 508-byte LoRa frame
WINDOW = 8  # parts asked for at a time
MAX_RESOURCE = 16 << 20  # receivers refuse anything bigger


@dataclass
class Resource:
  peer: bytes
  id: bytes
  data: bytes
  meta: Any = None


@dataclass
class Outgoing:
  """Sender side: the data, split, until the receiver says done."""

  id: bytes
  peer: bytes
  parts: list[bytes]
  digest: bytes
  meta: Any
  size: int
  active: float = float('-inf')  # when we last heard the receiver (event-loop clock)

  @classmethod
  def of(cls, peer: bytes, data: bytes, meta: Any = None, part_size: int = PART_SIZE):
    parts = [data[i : i + part_size] for i in range(0, len(data), part_size)] or [b'']
    digest = hashlib.sha256(data).digest()
    return cls(digest[:RESOURCE_ID_SIZE], peer, parts, digest, meta, len(data))

  def advertisement(self) -> dict:
    ad = {1: self.id, 2: self.size, 3: len(self.parts), 4: self.digest}
    if self.meta is not None:
      ad[5] = self.meta
    return ad


@dataclass
class Incoming:
  """Receiver side: parts collected so far."""

  id: bytes
  peer: bytes
  size: int
  count: int
  digest: bytes
  meta: Any
  parts: dict[int, bytes] = field(default_factory=dict)

  @classmethod
  def from_advertisement(cls, peer: bytes, ad: dict, max_size: int = MAX_RESOURCE):
    try:
      rid, size, count, digest = ad[1], ad[2], ad[3], ad[4]
    except (KeyError, TypeError):
      raise CoseError('bad resource advertisement') from None
    if not (
      isinstance(rid, bytes)
      and len(rid) == RESOURCE_ID_SIZE
      and isinstance(size, int)
      and isinstance(count, int)
      and isinstance(digest, bytes)
      and len(digest) == 32
      and digest[:RESOURCE_ID_SIZE] == rid
    ):
      raise CoseError('bad resource advertisement')
    if size > max_size or count < 1 or count > size + 1:
      raise CoseError(f'resource of {size} bytes refused')
    return cls(rid, peer, size, count, digest, ad.get(5))

  def add(self, index: int, data: bytes):
    if 0 <= index < self.count and isinstance(data, bytes):
      self.parts.setdefault(index, data)

  def missing(self, limit: int = WINDOW) -> list[int]:
    out = []
    for i in range(self.count):
      if i not in self.parts:
        out.append(i)
        if len(out) == limit:
          break
    return out

  @property
  def complete(self) -> bool:
    return len(self.parts) == self.count

  def assemble(self) -> bytes:
    data = b''.join(self.parts[i] for i in range(self.count))
    if len(data) != self.size or hashlib.sha256(data).digest() != self.digest:
      raise CoseError('resource does not match its hash')
    return data


def body(field_id: int, value) -> dict:
  return {field_id: value}


def encode(field_id: int, value) -> bytes:
  return cbor.dumps(body(field_id, value))
