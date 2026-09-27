"""
Ratchets: extra KEM keys that give forward secrecy (like Reticulum's).

A ratchet is a fresh HPKE KEM key with the identity's KEM (X-Wing for the pq
suite). A node announces its current ratchet inside its signed announce;
senders seal to it instead of the long-term identity key. Once the ratchet's
private key is gone, messages sealed to it cannot be opened by anyone, even
with the identity's private keys.

This module is mechanism only. *When* to rotate and *how long* to keep old
ratchets is a storage policy for the application (see examples/storage.py for
a suggested one). The library never expires keys by time, and never trusts
dates from peers.

A ratchet provider is anything with:

  current() -> Key         the ratchet to announce (with private key)
  get(rid) -> Key | None   the private ratchet with this id, if still held
  keys() -> list[Key]      held ratchets, newest first
"""

import hashlib
from typing import Protocol

from .keys import CoseError, Key, hpke_variant

RATCHET_ID_SIZE = 8


def ratchet_id(pub: bytes) -> bytes:
  return hashlib.sha256(pub).digest()[:RATCHET_ID_SIZE]


def new_ratchet(alg: int) -> Key:
  """A fresh ratchet for an identity whose KEM is `alg`; kid = ratchet id."""
  k = Key.generate(alg)
  k.kid = ratchet_id(k.pub)
  return k


def check_ratchet(ratchet: Key, identity_kem: Key):
  """A ratchet must use the identity's KEM and carry its own id as kid."""
  if hpke_variant(ratchet, True).id != hpke_variant(identity_kem, True).id:
    raise CoseError('ratchet uses a different KEM than the identity')
  if ratchet.kid != ratchet_id(ratchet.pub):
    raise CoseError('ratchet kid does not match its key')


class Ratchets(Protocol):
  def current(self) -> Key: ...

  def get(self, rid: bytes) -> Key | None: ...

  def keys(self) -> list[Key]: ...


class MemoryRatchets:
  """
  Ratchets held in memory only: forward secrecy across restarts, and
  whenever the application calls rotate()/discard(). Nothing happens on a timer.
  """

  def __init__(self, alg: int, keys: list[Key] | None = None, keep: int | None = None):
    self.alg = alg
    self.keep = keep  # optional cap on how many old ratchets to hold
    self._keys: list[Key] = list(keys or [])

  def __len__(self):
    return len(self._keys)

  def current(self) -> Key:
    if not self._keys:
      self.rotate()
    return self._keys[0]

  def rotate(self) -> Key:
    self._keys.insert(0, new_ratchet(self.alg))
    if self.keep is not None:
      del self._keys[self.keep :]
    return self._keys[0]

  def discard(self, rid: bytes):
    self._keys = [k for k in self._keys if k.kid != rid]

  def get(self, rid: bytes) -> Key | None:
    return next((k for k in self._keys if k.kid == rid), None)

  def keys(self) -> list[Key]:
    return list(self._keys)
