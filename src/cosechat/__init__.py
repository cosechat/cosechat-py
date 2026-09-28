"""
cosechat: post-quantum mesh messaging over COSE/CBOR (Python reference).

The public API is what this module exports, plus the modules named below:

  Node                 a mesh node: roads, routing, messages, links, resources
  Identity, SUITES     signing identities and their algorithm suites
  Message, Announce    what on_message / on_announce hand you
  Resource             what on_resource hands you
  MemoryRatchets       default ratchet provider (see ratchet.Ratchets)
  MemoryStore          default store-and-forward provider (see store.Store)
  RoadAuth             per-road key (Mac0 / Encrypt0 per frame)
  Key, CoseError       COSE keys; the error for anything cryptographically wrong

  cosechat.message    seal / unseal / announces without a node
  cosechat.cose       COSE Sign1, Sign, Mac0, Mac, Encrypt0, Encrypt
  cosechat.link       link handshake and link messages without a node
  cosechat.contact    address text and contact cards
  cosechat.roads.*    memory, udp, websocket, rnode, shared, wifi_raw, ble

Everything else (names starting with `_`, and module internals not listed)
may change without notice.
"""

from importlib.metadata import PackageNotFoundError, version

from . import contact
from .identity import SUITES, Identity
from .keys import CoseError, Key
from .message import Announce, Message
from .node import Node, Path
from .packet import RoadAuth
from .ratchet import MemoryRatchets
from .resource import Resource
from .store import MemoryStore, Store

try:
  __version__ = version('cosechat')
except PackageNotFoundError:  # pragma: no cover
  __version__ = '0+unknown'

__all__ = [
  'SUITES',
  'Announce',
  'CoseError',
  'Identity',
  'Key',
  'MemoryRatchets',
  'MemoryStore',
  'Message',
  'Node',
  'Path',
  'Resource',
  'RoadAuth',
  'Store',
  '__version__',
  'contact',
]
