"""
Suggested storage for a cosiechat application: key files, encryption at
rest, and a ratchet rotation/retention policy.

The library deliberately does none of this. Where keys live, how they are
protected, and how long they are kept depends on the device and the threat
model. This is one reasonable choice for a desktop or server:

  * Identity and ratchet files are written atomically with mode 0600.
  * With a passphrase they are encrypted at rest: the file holds a
    COSE_Encrypt0 (A256GCM) under a key from scrypt(passphrase, random salt).
  * Ratchets rotate every 30 minutes and are deleted 10 days after they were
    made. Both are measured with this device's own clock, never a peer's.
    Deleting a ratchet is what gives forward secrecy, so keep_for is the
    window during which a stolen ratchet file can open recorded messages.
  * Old key material is gone from the file, but flash, SSDs, backups and swap
    may keep copies. Use full-disk encryption, and on embedded devices a
    secure element or a flash layout you can really erase.

On a microcontroller you might keep ratchets in RAM only (forward secrecy
across reboots), rotate on every Nth announce, or store them in a secure
element. Any object with current()/get()/keys() works as a ratchet provider.
"""

import asyncio
import hashlib
import os
import time
from pathlib import Path

from cosiechat import Identity, cbor, cose
from cosiechat.keys import A256GCM, Key
from cosiechat.ratchet import new_ratchet

HOME = Path(os.environ.get('COSIECHAT_HOME', Path.home() / '.cosiechat'))
ROTATE_EVERY = 30 * 60
KEEP_FOR = 10 * 86400

_LOCKED = 'cosiechat-locked-v1'
_SCRYPT = {'n': 2**15, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024, 'dklen': 32}


def _key_from(passphrase: str, salt: bytes) -> Key:
  return Key(A256GCM, priv=hashlib.scrypt(passphrase.encode(), salt=salt, **_SCRYPT))


def write_private(path: Path, data: bytes, passphrase: str | None = None):
  """Atomic write, mode 0600, optionally encrypted with a passphrase."""
  if passphrase:
    salt = os.urandom(16)
    data = cbor.dumps([_LOCKED, salt, cose.encrypt0(data, _key_from(passphrase, salt))])
  path.parent.mkdir(parents=True, exist_ok=True)
  tmp = path.with_name(path.name + '.tmp')
  fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, 'wb') as f:
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
  os.replace(tmp, path)


def read_private(path: Path, passphrase: str | None = None) -> bytes:
  raw = path.read_bytes()
  try:
    obj = cbor.loads(raw)
  except Exception:
    obj = None
  if isinstance(obj, list) and len(obj) == 3 and obj[0] == _LOCKED:
    if not passphrase:
      raise PermissionError(f'{path} is encrypted; a passphrase is needed')
    try:
      return cose.decrypt0(obj[2], _key_from(passphrase, obj[1]))
    except cose.CoseError:
      raise PermissionError(f'wrong passphrase for {path}') from None
  return raw


def load_identity(
  path: Path, suite: str = 'pq', passphrase: str | None = None, create: bool = True
) -> Identity:
  if path.exists():
    return Identity.from_bytes(read_private(path, passphrase))
  if not create:
    raise FileNotFoundError(path)
  ident = Identity.generate(suite)
  write_private(path, ident.to_bytes(), passphrase)
  return ident


class FileRatchets:
  """
  A ratchet provider backed by a file, with a time-based policy run by
  maintain() (call it before announcing). Only the local clock is used.
  """

  def __init__(
    self,
    alg: int,
    path: Path,
    rotate_every: float = ROTATE_EVERY,
    keep_for: float = KEEP_FOR,
    passphrase: str | None = None,
    clock=time.time,
  ):
    self.alg = alg
    self.path = Path(path)
    self.rotate_every = rotate_every
    self.keep_for = keep_for
    self.passphrase = passphrase
    self.clock = clock
    self._items: list[tuple[float, Key]] = []  # (made at, key), newest first
    if self.path.exists():
      for made, m in cbor.loads(read_private(self.path, passphrase)):
        k = Key.from_cose(m)
        if k.alg == alg:
          self._items.append((made, k))
      self._items.sort(key=lambda x: -x[0])

  # ratchet provider interface
  def current(self) -> Key:
    if not self._items:
      self.rotate()
    return self._items[0][1]

  def get(self, rid: bytes) -> Key | None:
    return next((k for _, k in self._items if k.kid == rid), None)

  def keys(self) -> list[Key]:
    return [k for _, k in self._items]

  # policy
  def rotate(self) -> Key:
    self._items.insert(0, (self.clock(), new_ratchet(self.alg)))
    self._save()
    return self._items[0][1]

  def maintain(self) -> bool:
    """Delete expired ratchets and rotate if due. True if a new ratchet was made."""
    now = self.clock()
    kept = [(t, k) for t, k in self._items if now - t < self.keep_for]
    changed = len(kept) != len(self._items)
    self._items = kept
    rotated = not self._items or now - self._items[0][0] >= self.rotate_every
    if rotated:
      self.rotate()
    elif changed:
      self._save()
    return rotated

  def _save(self):
    data = cbor.dumps([[t, k.to_cose(private=True)] for t, k in self._items])
    write_private(self.path, data, self.passphrase)


def ratchets_for(identity_path: Path, identity: Identity, passphrase: str | None = None, **kw):
  """Ratchets live next to their identity: <identity>.ratchets"""
  path = identity_path.with_name(identity_path.name + '.ratchets')
  return FileRatchets(identity.kem_key.alg, path, passphrase=passphrase, **kw)


async def announce_forever(node, interval: float, ratchets: FileRatchets | None = None):
  """Apply the ratchet policy, then announce, every `interval` seconds."""
  while True:
    if ratchets is not None:
      ratchets.maintain()
    await node.announce()
    await asyncio.sleep(interval)
