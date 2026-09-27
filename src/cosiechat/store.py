"""
Store-and-forward storage for propagation nodes.

A propagation node keeps packets for destinations it has no path to, and
forwards them when the destination announces. What it keeps is only ever
ciphertext (sealed messages, link messages, receipts) plus the packet type.
Where and how long it is kept is the application's storage policy; the node
only needs a provider with:

  put(dest, kind, payload) -> bool      keep one; False if there is no room
  take(dest) -> list[(kind, payload)]   everything held for dest, oldest first, removed

MemoryStore is the default: bounded, and gone on restart. examples/storage.py
has a file-backed one.
"""

from collections import OrderedDict
from typing import Protocol


class Store(Protocol):
  def put(self, dest: bytes, kind: int, payload: bytes) -> bool: ...

  def take(self, dest: bytes) -> list[tuple[int, bytes]]: ...


class MemoryStore:
  def __init__(self, per_dest: int = 64, max_dests: int = 1024):
    self.per_dest = per_dest
    self.max_dests = max_dests
    self._held: OrderedDict[bytes, list[tuple[int, bytes]]] = OrderedDict()

  def __contains__(self, dest: bytes) -> bool:
    return dest in self._held

  def put(self, dest: bytes, kind: int, payload: bytes) -> bool:
    q = self._held.get(dest)
    if q is None:
      if len(self._held) >= self.max_dests:
        return False
      q = self._held[dest] = []
    if len(q) >= self.per_dest:
      return False
    q.append((kind, payload))
    return True

  def take(self, dest: bytes) -> list[tuple[int, bytes]]:
    return self._held.pop(dest, [])
