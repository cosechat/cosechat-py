"""
Sharing contacts.

Address text: the 16-byte address in base32 (RFC 4648, lowercase, no padding)
plus a 4-character checksum, in groups of 5 for reading aloud:

  address_text(a) -> 'mfrgg-zdfmz-tsnjx-gc3dm-nzsgm-3j5hu'   (26 + 4 = 30 characters)

A contact card: an address is enough to *find* someone on a mesh (a path
request brings their announce), but to message them you need their keyset and
ratchet, which their signed announce carries. A card is a full announce:

  card_uri(announce) -> 'cosechat:' + base64url(announce)

A pq card is ~6.6 KB (too big for one QR code: use a file, NFC, or share the
address text and let the mesh do the rest); a prequantum card is ~280 bytes.
"""

import base64
import hashlib

from .identity import ADDRESS_SIZE
from .keys import CoseError

URI_PREFIX = 'cosechat:'
CHECK_SIZE = 4  # base32 characters of checksum (20 bits)


def _b32(data: bytes) -> str:
  return base64.b32encode(data).decode().rstrip('=').lower()


def _check(address: bytes) -> str:
  return _b32(hashlib.sha256(b'cosechat address' + address).digest())[:CHECK_SIZE]


def address_text(address: bytes) -> str:
  if len(address) != ADDRESS_SIZE:
    raise ValueError('an address is 16 bytes')
  s = _b32(address) + _check(address)
  return '-'.join(s[i : i + 5] for i in range(0, len(s), 5))


def parse_address(text: str) -> bytes:
  """Address text (checksum verified) or plain hex, to the 16-byte address."""
  t = text.strip().lower().replace('-', '').replace(' ', '')
  if len(t) == ADDRESS_SIZE * 2:
    try:
      return bytes.fromhex(t)
    except ValueError:
      pass
  if len(t) != 26 + CHECK_SIZE:
    raise CoseError('not an address')
  body, check = t[:26], t[26:]
  try:
    address = base64.b32decode(body.upper() + '======')
  except Exception:
    raise CoseError('not an address') from None
  if len(address) != ADDRESS_SIZE or _check(address) != check:
    raise CoseError('address checksum does not match (typo?)')
  return address


def card_uri(announce: bytes) -> str:
  return URI_PREFIX + base64.urlsafe_b64encode(announce).decode().rstrip('=')


def card_from_uri(uri: str) -> bytes:
  u = uri.strip()
  if not u.startswith(URI_PREFIX):
    raise CoseError('not a cosechat contact card')
  b = u[len(URI_PREFIX) :]
  try:
    return base64.urlsafe_b64decode(b + '=' * (-len(b) % 4))
  except Exception:
    raise CoseError('bad contact card') from None
