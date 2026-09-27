"""
Node: identity + roads + routing. The road-agnostic transport, like
Reticulum's Transport, reduced to its core ideas:

  * An announce floods the mesh (transport nodes rebroadcast it, setting
    `via` to themselves). Each node records a path: the road it arrived on,
    the transport node to hand packets to (`via`), and the hop count.
  * DATA packets carry only the destination address. The originator sets
    `via` from its path; each transport node that is named in `via` forwards
    along its own path, rewriting `via`. Nobody but the recipient can read
    the payload.
  * PATH_REQUEST asks the mesh for a path; the destination re-announces, or a
    transport node that knows the path answers with the cached announce.
  * Propagation nodes (propagate=True) keep DATA for destinations they have
    no path to, and forward it once the destination announces. What they keep
    is the sealed COSE message, so it is encrypted at rest.
  * Delivery: each message carries a random receipt secret. The recipient
    answers with a tiny RECEIPT (an HMAC only someone who opened the message
    can make). Until then the sender re-seals and resends with backoff.
    Receivers hand each message id to the application once.
"""

import asyncio
import inspect
import logging
import os
import random
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import cbor, cose
from . import link as L
from . import message as msg
from . import propagation as PR
from . import resource as R
from .identity import Identity, address_of, signer_of
from .keys import QUANTUM_SAFE_KEM, Key
from .packet import (
  ANNOUNCE,
  DATA,
  FRAGMENT_ID_SIZE,
  FRAGMENT_OVERHEAD,
  KEYSET,
  KEYSET_REQUEST,
  LINK_ACCEPT,
  LINK_DATA,
  LINK_REQUEST,
  PATH_REQUEST,
  RECEIPT,
  RECEIPT_NONCE_SIZE,
  REQUEST_TAG_SIZE,
  ROUTED,
  Nack,
  Packet,
  PacketError,
  Reassembler,
  RoadAuth,
  decode,
  fragment,
  nack,
)
from .ratchet import MemoryRatchets, Ratchets
from .roads import Road
from .store import MemoryStore, Store

log = logging.getLogger('cosiechat.node')

# bounds on in-memory state (local policy, not protocol)
SEEN_CACHE = 50000  # packet hashes remembered for duplicate filtering
DELIVERED_CACHE = 10000  # message ids handed to the application
DELIVERY_RESULTS = 1000  # sent messages whose delivery can be awaited
ACCEPT_CACHE = 256  # link accepts kept to answer repeated requests
WAITING_PER_SENDER = 16  # messages held while fetching an unknown sender's keyset
WAITING_SENDERS = 256
FRAGMENT_CACHE_SETS = 32  # sent fragment sets kept for NACKs
FRAGMENT_CACHE_TIME = 60.0  # s
NACK_BASE_DELAY = 0.2  # s, added to two frame-times before asking for fragments
RESOURCE_STALLS = 8  # times a resource receiver re-asks without progress
ANNOUNCE_QUEUE = 256  # destinations waiting in one road's announce queue
TIMER_TABLE = 4096  # per-address timers (rate limits) remembered
KEYSET_WAITS = 256  # short announces / forwarded requests waiting on a keyset

# ingress: per road, (per second, burst) for work that costs CPU or airtime
INGRESS = {
  'announce': (5, 20),  # signature verifications
  'link': (2, 10),  # link requests: HPKE + signature
  'message': (50, 200),  # messages for us: HPKE
  'request': (10, 30),  # path and keyset requests: we may transmit an answer
}


@dataclass
class Path:
  lane: '_Lane'
  via: bytes | None
  hops: int
  sequence: int  # the announce's sequence (ordering only)
  expires: float  # local monotonic clock

  @property
  def road(self) -> Road:
    return self.lane.road


@dataclass
class _Outgoing:
  message: msg.Message
  address: bytes
  future: asyncio.Future
  reseal: Callable[[], tuple[bytes, int]]  # fresh (payload, packet type) for each (re)send
  attempts: int
  fallback: Callable | None = None  # async () -> bool, tried when attempts run out
  secret: bytes | None = None  # the receipt secret this send is confirmed with


class _Lane:
  """
  A road attached to a node, plus that road's auth wrapper and announce budget.

  On a road with a bitrate, announces may use at most `announce_cap` of it
  (like Reticulum's 2%): after an announce of S bytes the next waits
  S*8 / (bitrate*cap) seconds. Waiting announces go fewest-hops first, only
  the newest per destination is kept, and stale ones are dropped. Timing is
  the local clock only.
  """

  def __init__(self, road: Road, auth: RoadAuth | None, cap: float, max_age: float):
    self.road = road
    self.auth = auth
    self.cap = cap
    self.max_age = max_age
    # fragments we sent, kept briefly so a receiver can ask for missing ones
    self._sent: OrderedDict[bytes, tuple[list[bytes], float]] = OrderedDict()
    self.fragment_cache_time = FRAGMENT_CACHE_TIME
    self._buckets: dict[str, list[float]] = {}  # kind -> [tokens, last refill]
    self.queue: dict[bytes, tuple[int, float, Packet]] = {}  # dest -> (hops, queued at, packet)
    self._ready_at = 0.0
    self._wake = asyncio.Event()

  def allow(self, kind: str, limits: dict) -> bool:
    """Token bucket per road and kind of incoming work (local clock)."""
    rate, burst = limits[kind]
    now = time.monotonic()
    b = self._buckets.setdefault(kind, [burst, now])
    b[0] = min(burst, b[0] + (now - b[1]) * rate)
    b[1] = now
    if b[0] < 1:
      return False
    b[0] -= 1
    return True

  @property
  def max_frame(self) -> int:
    return self.road.mtu - (self.auth.overhead if self.auth else 0)

  @property
  def budgeted(self) -> bool:
    return bool(self.road.bitrate and self.cap)

  async def send(self, packet: Packet) -> int:
    """Send now; returns the bytes put on the road."""
    frame = packet.encode()
    if len(frame) <= self.max_frame:
      frames = [frame]
    else:
      fid = os.urandom(FRAGMENT_ID_SIZE)
      frames = fragment(frame, self.max_frame - FRAGMENT_OVERHEAD, fid)
      self._sent[fid] = (frames, time.monotonic() + self.fragment_cache_time)
      while len(self._sent) > FRAGMENT_CACHE_SETS:
        self._sent.popitem(last=False)
    total = 0
    for f in frames:
      total += await self.send_frame(f)
    return total

  async def send_frame(self, frame: bytes) -> int:
    wire = self.auth.wrap(frame) if self.auth else frame
    await self.road.send(wire)
    return len(wire)

  @property
  def frame_time(self) -> float:
    """Seconds to put one full frame on this road (0 if it is fast)."""
    return self.road.mtu * 8 / self.road.bitrate if self.road.bitrate else 0.0

  async def resend(self, n: Nack):
    entry = self._sent.get(n.fid)
    if entry is None or time.monotonic() > entry[1]:
      return
    frames = entry[0]
    for i in dict.fromkeys(n.missing):  # in order, no repeats
      if i < len(frames):
        await self.send_frame(frames[i])

  async def announce(self, packet: Packet):
    if not self.budgeted:
      await self.send(packet)
      return
    if packet.dest not in self.queue and len(self.queue) >= ANNOUNCE_QUEUE:
      worst = max(self.queue, key=lambda d: self.queue[d][:2])  # most hops, then oldest
      if self.queue[worst][0] <= packet.hops:
        return
      del self.queue[worst]
    self.queue[packet.dest] = (packet.hops, time.monotonic(), packet)
    self._wake.set()

  async def run_announces(self):
    while True:
      if not self.queue:
        self._wake.clear()
        await self._wake.wait()
        continue
      delay = self._ready_at - time.monotonic()
      if delay > 0:
        await asyncio.sleep(delay)
      now = time.monotonic()
      for dest in [d for d, (_, t, _) in self.queue.items() if now - t > self.max_age]:
        del self.queue[dest]
      if not self.queue:
        continue
      dest = min(self.queue, key=lambda d: self.queue[d][:2])
      _, _, packet = self.queue.pop(dest)
      size = await self.send(packet)
      self._ready_at = time.monotonic() + size * 8 / (self.road.bitrate * self.cap)


class Node:
  def __init__(
    self,
    identity: Identity | None = None,
    transport: bool = False,
    propagate: bool = False,
    app_data: Any = None,
    max_hops: int = 16,
    rebroadcast_delay: float = 0.25,
    announce_interval: float | None = None,
    quantum_safe_only: bool = True,
    ratchets: Ratchets | None = None,
    retry_after: float = 30.0,
    retry_max: float = 600.0,
    max_attempts: int = 4,
    accept_links: bool = True,
    link_attempts: int = 3,
    link_idle: float = 3600.0,
    nack_attempts: int = 3,
    store: Store | None = None,
    max_links: int = 256,
    path_ttl: float = 7 * 86400,
    max_peers: int = 10000,
    max_resource: int = R.MAX_RESOURCE,
    propagation_node: bytes | None = None,
    auto_propagate: bool = True,
    ingress: dict | None = None,
    announce_cap: float = 0.02,
    announce_queue_age: float = 3600.0,
    rebroadcast_min_interval: float = 60.0,
    name: str | None = None,
  ):
    self.identity = identity or Identity.generate()
    if not self.identity.has_private:
      raise ValueError('node identity needs private keys')
    self.transport = transport or propagate
    self.propagate = propagate
    self.app_data = app_data
    self.max_hops = max_hops
    self.rebroadcast_delay = rebroadcast_delay
    self.announce_interval = announce_interval
    # announce flood control (local policy, local clock): the share of a slow
    # road's bitrate announces may use, how long one may wait in a queue, and
    # how often a transport node rebroadcasts any one identity
    self.announce_cap = announce_cap
    self.announce_queue_age = announce_queue_age
    self.rebroadcast_min_interval = rebroadcast_min_interval
    self._rebroadcast_at: dict[bytes, float] = {}
    self._rediscover_at: dict[bytes, float] = {}
    # On by default: refuse peers whose keys a quantum attacker could break
    # (ignore their announces, refuse to send to them, drop what they send).
    # Pre-quantum peers need an explicit quantum_safe_only=False.
    self.quantum_safe_only = quantum_safe_only
    if quantum_safe_only and not self.identity.quantum_safe:
      raise ValueError(
        'identity is not quantum-safe; use the pq or hybrid suite, '
        'or pass quantum_safe_only=False to accept pre-quantum crypto'
      )
    # Messages are always sealed to ratchets (identities have no KEM key).
    # `ratchets` is where ours live (see ratchet.py). The default keeps them in
    # memory only; when to rotate or discard them is the application's storage
    # policy (rotate_ratchet(), examples/storage.py). Never rotating = no
    # forward secrecy beyond restarts.
    self.ratchets = ratchets if ratchets is not None else MemoryRatchets(self.identity.kem_alg)
    self.peer_ratchets: dict[bytes, Key] = {}
    # short announces waiting for a keyset, and keyset requests we forwarded
    self._need_keyset: dict[bytes, tuple[_Lane, Packet]] = {}
    self._waiting_messages: dict[bytes, list[Packet]] = {}  # sender -> messages to retry
    self._keyset_asked: dict[bytes, set] = {}
    self._keyset_requested_at: dict[bytes, float] = {}
    self._announced = False
    self._sequence = 0  # our announce sequence: Unix ms, but never going backwards
    # delivery: resend after retry_after, doubling up to retry_max, max_attempts
    # sends in all (timed by the local event loop clock only)
    self.retry_after = retry_after
    self.retry_max = retry_max
    self.max_attempts = max_attempts
    self._outbox: dict[bytes, _Outgoing] = {}  # receipt tag -> pending send
    self._deliveries: OrderedDict[bytes, list[asyncio.Future]] = OrderedDict()
    self._delivered: OrderedDict[bytes, None] = OrderedDict()  # message ids we handed over
    # links (sessions, see link.py): live in memory only, closed explicitly
    self.accept_links = accept_links
    # a link message unanswered after link_attempts sends means the peer has
    # probably lost the link (restart): drop it and send the content sealed
    self.link_attempts = link_attempts
    # a link unused this long is forgotten, keys and all (forward secrecy; no
    # keepalive traffic: a peer still using it falls back to sealed messages)
    self.link_idle = link_idle
    self._link_used: dict[bytes, float] = {}  # link id -> last use (monotonic)
    # fragment resume: a receiver asks for missing fragments this many times
    self.nack_attempts = nack_attempts
    self._nack_timers: dict = {}  # (lane id, fragment id) -> [timer, tries, delay]
    self.max_links = max_links
    # a path is forgotten this long after the announce that made it (local
    # monotonic clock; Reticulum uses a week). Any valid announce refreshes it.
    self.path_ttl = path_ttl
    # peers remembered (identity, announce, path, ratchet); the least recently
    # heard is forgotten first
    self.max_peers = max_peers
    # resources (large transfers over links): the biggest we accept
    self.max_resource = max_resource
    # propagation: where to deposit for offline peers (None: the nearest one
    # known from announces), and whether to do so when direct delivery fails
    self.propagation_node = propagation_node
    self.auto_propagate = auto_propagate
    self.propagation_nodes: OrderedDict[bytes, None] = OrderedDict()
    self._batches: dict[bytes, list] = {}  # (propagation node) peer -> batch handed out
    self._fetching: dict[bytes, list] = {}  # (client) propagation node -> [items, future]
    self._res_out: dict[bytes, tuple[R.Outgoing, asyncio.Future]] = {}
    self._res_in: dict[
      tuple[bytes, bytes], list
    ] = {}  # (peer, id) -> [Incoming, timer, stalls, asked]
    self._res_done: OrderedDict[tuple[bytes, bytes], None] = OrderedDict()
    self._resource_handlers: list[Callable] = []
    self._peers: OrderedDict[bytes, None] = OrderedDict()
    self.ingress = {**INGRESS, **(ingress or {})}
    self.links: OrderedDict[bytes, L.LinkKeys] = OrderedDict()  # link id -> keys, LRU order
    self._link_to: dict[bytes, bytes] = {}  # peer address -> link id
    self._pending_links: dict[bytes, tuple[L.PendingLink, asyncio.Future]] = {}
    self._accepts: OrderedDict[bytes, tuple[bytes, bytes]] = OrderedDict()  # id -> (peer, accept)
    self.name = name or self.identity.address.hex()[:8]

    self.lanes: list[_Lane] = []
    self.identities: dict[bytes, Identity] = {self.address: self.identity.public()}
    self.announces: dict[bytes, tuple[bytes, msg.Announce]] = {}
    self.paths: dict[bytes, Path] = {}
    # propagation nodes keep ciphertext for unreachable destinations here;
    # where and how long is the application's storage policy (store.py)
    self.store = store if store is not None else MemoryStore()

    self._seen: OrderedDict[bytes, None] = OrderedDict()
    self._reassembler = Reassembler()
    self._message_handlers: list[Callable] = []
    self._announce_handlers: list[Callable] = []
    self._receipt_handlers: list[Callable] = []
    self._waiters: dict[bytes, list[asyncio.Future]] = {}
    self._tasks: set[asyncio.Task] = set()
    self._running = False

  def __repr__(self):
    return f'<Node {self.name} {self.address.hex()}>'

  @property
  def address(self) -> bytes:
    return self.identity.address

  # --- lifecycle ---

  def add_road(self, road: Road, auth: RoadAuth | None = None) -> Road:
    lane = _Lane(road, auth, self.announce_cap, self.announce_queue_age)
    road.on_frame = lambda frame, lane=lane: self._on_frame(lane, frame)
    self.lanes.append(lane)
    if self._running:
      self._spawn(road.start())
      self._spawn(lane.run_announces())
    return road

  async def start(self):
    self._running = True
    for lane in self.lanes:
      await lane.road.start()
      self._spawn(lane.run_announces())
    if self.announce_interval:
      self._spawn(self._announce_loop())

  async def stop(self):
    self._running = False
    for t in list(self._tasks):
      t.cancel()
    for lane in self.lanes:
      await lane.road.stop()

  async def __aenter__(self):
    await self.start()
    return self

  async def __aexit__(self, *exc):
    await self.stop()

  # --- public API ---

  def on_message(self, cb: Callable[[msg.Message], Any]):
    self._message_handlers.append(cb)
    return cb

  def on_announce(self, cb: Callable[[msg.Announce, Path], Any]):
    self._announce_handlers.append(cb)
    return cb

  def on_resource(self, cb: Callable[[R.Resource], Any]):
    """cb(resource) when a large transfer from a peer has arrived whole."""
    self._resource_handlers.append(cb)
    return cb

  async def send_resource(self, to, data: bytes, meta: Any = None, timeout: float = 600.0) -> bool:
    """
    Send `data` (any size up to the peer's limit) over a link, opening one if
    needed. True once the peer confirms it has all of it, intact.
    """
    addr = to.address if isinstance(to, Identity) else to
    keys = self.link_to(addr) or await self.open_link(to, timeout)
    out = R.Outgoing.of(addr, data, meta)
    fut = asyncio.get_running_loop().create_future()
    self._res_out[out.id] = (out, fut)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
      quiet = self.retry_after  # silence before we advertise again (backs off)
      while True:
        # (re)advertise when the receiver has not been heard from for a while:
        # at the start, and if our last part or its `done` got lost
        if loop.time() - out.active >= quiet:
          live = self.link_to(addr)
          if live is None or live.link_id != keys.link_id:
            return False
          ad = R.encode(R.R_ADVERTISE, out.advertisement())
          await self._send_data(addr, L.seal(live, ad), LINK_DATA)
          if out.active != float('-inf'):
            quiet = min(quiet * 2, self.retry_max)
          out.active = loop.time()
        left = deadline - loop.time()
        if left <= 0:
          return False
        try:
          return await asyncio.wait_for(asyncio.shield(fut), min(self.retry_after, left))
        except TimeoutError:
          pass
    finally:
      self._res_out.pop(out.id, None)

  def on_receipt(self, cb: Callable[[msg.Message, bytes], Any]):
    """cb(message, recipient address) when a recipient confirms it opened a message."""
    self._receipt_handlers.append(cb)
    return cb

  async def delivered(self, m: msg.Message, timeout: float | None = None) -> bool:
    """True once every recipient sent a receipt; False if any gave up (or timeout)."""
    futs = self._deliveries.get(m.id)
    if not futs:
      raise LookupError('not a message this node sent with receipts')
    try:
      results = await asyncio.wait_for(asyncio.gather(*futs), timeout)
    except TimeoutError:
      return False
    return all(results)

  def known(self, address: bytes) -> Identity | None:
    return self.identities.get(address)

  async def announce(self, app_data: Any = None, full: bool | None = None):
    """
    Signed announce with our current ratchet.
    full: include our keyset. Default: only the first time since start (and
    when answering a path request for us); later announces are short.
    """
    if full is None:
      full = not self._announced
    self._announced = True
    self._sequence = max(msg.now_ms(), self._sequence + 1)
    data = msg.make_announce(
      self.identity,
      self.ratchets.current(),
      app_data if app_data is not None else self.app_data,
      sequence=self._sequence,
      full=full,
      services=PR.SERVICE_PROPAGATION if self.propagate else 0,
    )
    p = Packet(ANNOUNCE, 0, self.address, None, data)
    self._mark_seen(p.hash)
    await self._broadcast(p)

  async def _broadcast_announce(self, p: Packet):
    for lane in self.lanes:
      if lane.road.online:
        await lane.announce(p)

  def contact_card(self) -> bytes:
    """A signed full announce to share out of band (see contact.py for a URI form)."""
    self._sequence = max(msg.now_ms(), self._sequence + 1)
    return msg.make_announce(
      self.identity,
      self.ratchets.current(),
      self.app_data,
      sequence=self._sequence,
      services=PR.SERVICE_PROPAGATION if self.propagate else 0,
    )

  def add_contact(self, card: bytes) -> msg.Announce:
    """
    Take someone's contact card: their keyset and ratchet become known, so we
    can message them (the mesh still has to find a path). Pinning and the
    quantum-safe policy apply as for announces.
    """
    ann = msg.verify_announce(card)
    known = self.identities.get(ann.address)
    if known is not None and known.public_bytes != ann.identity.public_bytes:
      raise PermissionError('a different keyset is already pinned to that address')
    if self.quantum_safe_only and not (
      ann.identity.quantum_safe and ann.ratchet.alg in QUANTUM_SAFE_KEM
    ):
      raise PermissionError('contact is not quantum-safe')
    prev = self.announces.get(ann.address)
    if prev is None or ann.sequence >= prev[1].sequence:
      self.identities[ann.address] = ann.identity
      self.announces[ann.address] = (card, ann)
      self.peer_ratchets[ann.address] = ann.ratchet
      self._heard(ann.address)
    return ann

  def path(self, dest: bytes) -> Path | None:
    """The current path to `dest`, or None (unknown, or expired: then it is forgotten)."""
    p = self.paths.get(dest)
    if p is not None and time.monotonic() >= p.expires:
      del self.paths[dest]
      return None
    return p

  def peer_ratchet(self, address: bytes) -> Key | None:
    """The ratchet in the newest announce we accepted from `address`."""
    return self.peer_ratchets.get(address)

  async def rotate_ratchet(self, announce: bool = True) -> Key:
    """Start using a new ratchet (the provider decides what happens to old ones)."""
    k = self.ratchets.rotate()
    if announce:
      await self.announce()
    return k

  async def request_path(
    self, address: bytes, timeout: float = 10.0, fresh: bool = False
  ) -> Identity | None:
    """Ask the mesh for `address`; resolves once its announce arrives (a new one if fresh)."""
    if not fresh and self.path(address) and address in self.identities:
      return self.identities[address]
    fut = asyncio.get_running_loop().create_future()
    self._waiters.setdefault(address, []).append(fut)
    p = Packet(PATH_REQUEST, 0, address, None, random.randbytes(REQUEST_TAG_SIZE))
    self._mark_seen(p.hash)
    await self._broadcast(p)
    try:
      return await asyncio.wait_for(fut, timeout)
    except TimeoutError:
      return self.identities.get(address)
    finally:
      ws = self._waiters.get(address, [])
      if fut in ws:
        ws.remove(fut)

  async def send(
    self,
    to,
    content: Any = '',
    title: str = '',
    fields: dict | None = None,
    attach_identity: bool = False,
    timeout: float = 10.0,
    receipt: bool = True,
    propagate: bool = False,
  ) -> msg.Message:
    """
    Seal a message for one or more recipients (addresses or Identities) and
    send it. Unknown recipients are looked up with a path request first.
    With receipt=True (default) it is resent until each recipient confirms;
    await node.delivered(message) to find out. propagate=True hands it to a
    propagation node instead (delivered then means "the node has it"); with
    auto_propagate, that also happens when direct delivery gives up.
    """
    targets = to if isinstance(to, (list, tuple)) else [to]
    if len(targets) == 1 and not propagate:
      addr = targets[0].address if isinstance(targets[0], Identity) else targets[0]
      if addr in self._link_to:
        return await self._send_on_link(addr, content, title, fields, receipt)
    recipients = [await self._resolve(t, timeout, need_path=not propagate) for t in targets]
    m = msg.sign_message(
      self.identity,
      recipients,
      content,
      title,
      fields,
      attach_identity=attach_identity,
      receipt_secret=os.urandom(msg.RECEIPT_SECRET_SIZE) if receipt else None,
    )
    for r in recipients:
      # every (re)send is a fresh envelope around the same signed message: a new
      # packet hash gets past duplicate filters, and the newest ratchet is used
      def reseal(r=r):
        return msg.envelope(m.signed, self.peer_ratchet(r.address)), DATA

      if propagate:
        dm = await self._deposit(m, r, receipt)
        if receipt:  # delivered(m) then means "a propagation node has it"
          self._deliveries.setdefault(m.id, []).extend(self._deliveries.get(dm.id, []))
        continue

      async def fallback(r=r):
        # direct delivery gave up: leave it with a propagation node
        self.paths.pop(r.address, None)
        if not self.auto_propagate or self._propagation_node(exclude=r.address) is None:
          return False
        dm = await self._deposit(m, r, True)
        return dm is not None and await self.delivered(dm)

      await self._dispatch(m, r.address, reseal, receipt, fallback=fallback)
    return m

  def _propagation_node(self, exclude: bytes | None = None) -> bytes | None:
    """The configured propagation node, or the nearest one we know a path to."""
    if self.propagation_node:
      return self.propagation_node
    known = [a for a in self.propagation_nodes if a != exclude and self.path(a)]
    return min(known, key=lambda a: self.path(a).hops) if known else None

  async def _deposit(self, m: msg.Message, r: Identity, receipt: bool) -> msg.Message | None:
    """Hand `m` (sealed to r's ratchet) to a propagation node, over a link to it."""
    node_addr = self._propagation_node(exclude=r.address)
    if node_addr is None:
      raise LookupError('no propagation node known')
    keys = self.link_to(node_addr) or await self.open_link(node_addr)
    lid = keys.link_id
    secret = os.urandom(msg.RECEIPT_SECRET_SIZE)
    dm = msg.Message(self.address, [r.address], m.timestamp, id=m.id + b'd', receipt_secret=secret)

    def reseal():
      live = self.link_to(node_addr)
      if live is None or live.link_id != lid:
        raise LookupError('link closed')
      item = [r.address, DATA, msg.envelope(m.signed, self.peer_ratchet(r.address))]
      body = {PR.P_DEPOSIT: item}
      if receipt:
        body[msg.M_RECEIPT] = secret
      return L.seal(live, cbor.dumps(body)), LINK_DATA

    await self._dispatch(dm, node_addr, reseal, receipt, secret=secret)
    return dm

  async def _resolve(self, t, timeout: float, need_path: bool = True) -> Identity:
    """A recipient we may send to: known identity, quantum-safe, with a ratchet."""
    if isinstance(t, Identity):
      self.identities.setdefault(t.address, t.public())
      t = t.address
    if need_path and self.path(t) is None:
      # no route yet: ask the mesh; without one we still flood to neighbours
      # and propagation nodes
      await self.request_path(t, timeout)
    ident = self.identities.get(t)
    if ident is None:
      raise LookupError(f'no identity known for {t.hex()}')
    if self.quantum_safe_only and not ident.quantum_safe:
      raise PermissionError(f'{t.hex()} is not quantum-safe; refusing to send')
    if self.peer_ratchet(t) is None and need_path:
      # no ratchet from this peer yet: ask for a fresh announce
      await self.request_path(t, timeout, fresh=True)
    if self.peer_ratchet(t) is None:
      raise LookupError(f'no ratchet for {t.hex()}: it must announce first')
    if self.quantum_safe_only and self.peer_ratchet(t).alg not in QUANTUM_SAFE_KEM:
      raise PermissionError(f'{t.hex()} announced a ratchet that is not quantum-safe')
    return ident

  async def _dispatch(
    self,
    m: msg.Message,
    addr: bytes,
    reseal,
    receipt: bool,
    attempts=None,
    fallback=None,
    secret: bytes | None = None,
  ):
    payload, kind = reseal()
    await self._send_data(addr, payload, kind)
    if not receipt:
      return
    o = _Outgoing(
      m,
      addr,
      asyncio.get_running_loop().create_future(),
      reseal,
      attempts or self.max_attempts,
      fallback,
      secret or m.receipt_secret,
    )
    self._outbox[msg.receipt_tag(o.secret, addr)] = o
    self._deliveries.setdefault(m.id, []).append(o.future)
    while len(self._deliveries) > DELIVERY_RESULTS:
      self._deliveries.popitem(last=False)
    self._spawn(self._retry(o))

  # --- links ---

  def link_to(self, address: bytes) -> L.LinkKeys | None:
    self._expire_links()
    lid = self._link_to.get(address)
    return self.links.get(lid) if lid else None

  def _expire_links(self):
    cutoff = time.monotonic() - self.link_idle
    for lid in [lid for lid in self.links if self._link_used.get(lid, 0.0) < cutoff]:
      log.debug('%s: forgetting idle link %s', self, lid.hex()[:8])
      self._drop_link(lid)

  async def open_link(self, to, timeout: float = 30.0) -> L.LinkKeys:
    """
    Set up a session with a peer (one PQ handshake), after which send() to it
    costs tens of bytes per message. Either side's send() uses it until closed.
    """
    peer = await self._resolve(to, timeout)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    wait = self.retry_after
    while True:
      # a fresh request per attempt (each has its own link id and packet hash)
      pending = L.make_request(self.identity, peer, self.peer_ratchet(peer.address))
      fut = loop.create_future()
      self._pending_links[pending.link_id] = (pending, fut)
      await self._send_data(peer.address, pending.request, LINK_REQUEST)
      left = deadline - loop.time()
      try:
        return await asyncio.wait_for(fut, min(wait, left))
      except TimeoutError:
        self._pending_links.pop(pending.link_id, None)
        if loop.time() >= deadline:
          raise TimeoutError(f'no link accept from {peer.address.hex()}') from None
        wait = min(wait * 2, self.retry_max)

  async def close_link(self, address: bytes):
    keys = self.link_to(address)
    if keys is None:
      return
    body = L.message_body(close=True)
    await self._send_data(address, L.seal(keys, body), LINK_DATA)
    self._drop_link(keys.link_id)

  def _drop_link(self, lid: bytes):
    self._link_used.pop(lid, None)
    keys = self.links.pop(lid, None)
    if keys and self._link_to.get(keys.peer) == lid:
      del self._link_to[keys.peer]

  def _add_link(self, keys: L.LinkKeys):
    old = self._link_to.get(keys.peer)
    if old and old != keys.link_id:
      self.links.pop(old, None)
    self.links[keys.link_id] = keys
    self._link_to[keys.peer] = keys.link_id
    self._link_used[keys.link_id] = time.monotonic()
    while len(self.links) > self.max_links:
      self._drop_link(next(iter(self.links)))  # least recently used

  def _used_link(self, lid: bytes):
    if lid in self.links:
      self.links.move_to_end(lid)
      self._link_used[lid] = time.monotonic()

  async def _send_on_link(self, addr, content, title, fields, receipt) -> msg.Message:
    keys = self.link_to(addr)
    secret = os.urandom(msg.RECEIPT_SECRET_SIZE) if receipt else None
    body = L.message_body(content, title, fields, secret)
    m, _ = L.read_message(keys, addr, body)
    m.sender = self.address

    lid = keys.link_id

    def reseal():
      live = self.link_to(addr)
      if live is None or live.link_id != lid:
        raise LookupError('link closed')
      self._used_link(lid)
      return L.seal(live, body), LINK_DATA  # fresh IV each time

    async def fallback():
      # the peer did not answer on the link: it has probably lost it
      log.debug('%s: link to %s seems dead, sending sealed', self, addr.hex())
      self._drop_link(lid)
      try:
        sealed = await self.send(addr, content, title, fields)
      except (LookupError, PermissionError):
        return False
      return await self.delivered(sealed)

    await self._dispatch(m, addr, reseal, receipt, self.link_attempts, fallback)
    return m

  async def _retry(self, o: _Outgoing):
    tag = msg.receipt_tag(o.secret, o.address)
    wait = self.retry_after
    try:
      for attempt in range(1, o.attempts + 1):
        try:
          await asyncio.wait_for(asyncio.shield(o.future), wait)
          return
        except TimeoutError:
          pass
        if attempt == o.attempts:
          break
        log.debug('%s: resending %s to %s', self, o.message.id.hex()[:8], o.address.hex())
        if attempt == 2:
          # twice unanswered: the path may be dead; ask the mesh again meanwhile
          self._rediscover(o.address)
        try:
          payload, kind = o.reseal()
        except LookupError:
          break
        await self._send_data(o.address, payload, kind)
        wait = min(wait * 2, self.retry_max)
      self._outbox.pop(tag, None)
      if o.fallback is None:
        self.paths.pop(o.address, None)  # it did not work: find a new one next time
      result = await o.fallback() if o.fallback else False
      if not o.future.done():
        o.future.set_result(result)
    finally:
      self._outbox.pop(tag, None)

  # --- sending ---

  def _spawn(self, coro):
    t = asyncio.get_running_loop().create_task(coro)
    self._tasks.add(t)
    t.add_done_callback(self._task_done)
    return t

  def _task_done(self, t: asyncio.Task):
    self._tasks.discard(t)
    if not t.cancelled() and t.exception():
      log.error('%s: task failed', self, exc_info=t.exception())

  async def _broadcast(self, p: Packet, exclude: _Lane | None = None):
    if p.type == ANNOUNCE:
      await self._broadcast_announce(p)
      return
    for lane in self.lanes:
      if lane is not exclude and lane.road.online:
        await lane.send(p)

  async def _send_data(self, dest: bytes, payload: bytes, type: int = DATA):
    path = self.path(dest)
    p = Packet(type, 0, dest, path.via if path else None, payload)
    self._mark_seen(p.hash)
    if path:
      await path.lane.send(p)
    else:
      await self._broadcast(p)

  async def _delayed(self, coro_fn, *args):
    if self.rebroadcast_delay:
      await asyncio.sleep(random.random() * self.rebroadcast_delay)
    await coro_fn(*args)

  async def _announce_loop(self):
    while self._running:
      await self.announce()
      await asyncio.sleep(self.announce_interval)

  # --- receiving ---

  def _mark_seen(self, h: bytes) -> bool:
    """Record a packet hash; True if it was new."""
    if h in self._seen:
      return False
    self._seen[h] = None
    if len(self._seen) > SEEN_CACHE:
      self._seen.popitem(last=False)
    return True

  def _on_frame(self, lane: _Lane, frame: bytes):
    try:
      if lane.auth:
        frame = lane.auth.unwrap(frame)
      item = decode(frame)
      if isinstance(item, Nack):
        self._spawn(lane.resend(item))
        return
      if isinstance(item, tuple):
        whole = self._reassembler.add(id(lane), item)
        self._watch_fragments(lane, item[0], whole is not None)
        if whole is None:
          return
        item = decode(whole)
        if not isinstance(item, Packet):
          raise PacketError('nested fragment')
    except PacketError as e:
      log.debug('%s: dropped frame on %s: %s', self, lane.road, e)
      return
    if not self._mark_seen(item.hash):
      if item.type == ANNOUNCE:
        self._seen_announce_again(lane, item)
      return
    log.debug('%s: %r on %s', self, item, lane.road)
    if item.type == ANNOUNCE:
      self._handle_announce(lane, item)
    elif item.type in ROUTED:
      self._handle_data(lane, item)
    elif item.type == PATH_REQUEST:
      self._handle_path_request(lane, item)
    elif item.type == KEYSET_REQUEST:
      self._handle_keyset_request(lane, item)
    elif item.type == KEYSET:
      self._handle_keyset(lane, item)

  def _precheck_announce(self, p: Packet) -> bool:
    """Cheap checks before the (costly) signature verification."""
    try:
      sm = cose.decode(p.payload)
      if signer_of(sm) != p.dest:
        return False
      body = cbor.loads(sm.content)
      pub = body.get(msg.A_IDENTITY)
      known = self.identities.get(p.dest)
      if pub is not None:
        if address_of(pub) != p.dest or (known is not None and known.public_bytes != pub):
          return False  # pinned to another keyset
        known = Identity.from_bytes(pub)
      if self.quantum_safe_only:
        if known is not None and not known.quantum_safe:
          return False
        if body.get(msg.A_RATCHET, {}).get(3) not in QUANTUM_SAFE_KEM:
          return False
      return True
    except Exception:
      return False

  def _nack_delay(self, lane: _Lane) -> float:
    # a gap of about two frame-times means fragments went missing
    return 2 * lane.frame_time + NACK_BASE_DELAY

  def _watch_fragments(self, lane: _Lane, fid: bytes, complete: bool):
    """(Re)start the stall timer of an incomplete fragment set; stop it when complete."""
    key = (id(lane), fid)
    entry = self._nack_timers.pop(key, None)
    if entry:
      entry[0].cancel()
    if complete:
      return
    tries = entry[1] if entry else 0
    delay = self._nack_delay(lane)
    timer = asyncio.get_running_loop().call_later(delay, self._stalled, lane, fid)
    self._nack_timers[key] = [timer, tries, delay]

  def _stalled(self, lane: _Lane, fid: bytes):
    key = (id(lane), fid)
    entry = self._nack_timers.pop(key, None)
    missing = self._reassembler.missing(id(lane), fid)
    if entry is None or not missing or entry[1] >= self.nack_attempts:
      return
    log.debug('%s: asking for %d missing fragment(s) on %s', self, len(missing), lane.road)
    self._spawn(lane.send_frame(nack(fid, missing)))
    delay = entry[2] * 2 + lane.frame_time * len(missing)
    timer = asyncio.get_running_loop().call_later(delay, self._stalled, lane, fid)
    self._nack_timers[key] = [timer, entry[1] + 1, delay]

  def _handle_announce(self, lane: _Lane, p: Packet):
    if p.dest == self.address or not self._precheck_announce(p):
      return
    if not lane.allow('announce', self.ingress):
      log.debug('%s: announce rate limit on %s', self, lane.road)
      return
    try:
      ann = msg.verify_announce(p.payload, p.dest, self.identities.get)
    except msg.KeysetNeeded:
      # a short announce from someone we have not met: fetch the keyset (from
      # anyone; it is self-authenticating), then look at this announce again
      if p.dest in self._need_keyset or len(self._need_keyset) < KEYSET_WAITS:
        self._need_keyset[p.dest] = (lane, p)
        self._request_keyset(p.dest)
      return
    except Exception as e:  # anything malformed from the network is just dropped
      log.debug('%s: invalid announce: %r', self, e)
      return
    prev = self.announces.get(p.dest)
    # an identity's sequence only goes up: an older (replayed) announce must not
    # bring back an old path or ratchet. This compares the peer with itself,
    # never with our clock.
    if prev and ann.sequence < prev[1].sequence:
      return
    self.identities[p.dest] = ann.identity
    self.announces[p.dest] = (p.payload, ann)
    self.peer_ratchets[p.dest] = ann.ratchet
    self._heard(p.dest)
    if ann.services & PR.SERVICE_PROPAGATION:
      self.propagation_nodes[p.dest] = None
    else:
      self.propagation_nodes.pop(p.dest, None)
    path = self._update_path(lane, p, ann.sequence)
    for cb in self._announce_handlers:
      self._call(cb, ann, path)
    self._rebroadcast(p)

  def _heard(self, address: bytes):
    """Note activity from a peer; forget the least recent ones beyond max_peers."""
    self._peers[address] = None
    self._peers.move_to_end(address)
    while len(self._peers) > self.max_peers:
      old, _ = self._peers.popitem(last=False)
      if old == self.address:
        continue
      for table in (self.identities, self.announces, self.paths, self.peer_ratchets):
        table.pop(old, None)

  def _prune(self, table: dict):
    """Keep a per-address timer table bounded: drop entries whose time has passed."""
    if len(table) > TIMER_TABLE:
      now = time.monotonic()
      for k in [k for k, t in table.items() if t <= now]:
        del table[k]
      while len(table) > TIMER_TABLE:
        table.pop(next(iter(table)))

  def _seen_announce_again(self, lane: _Lane, p: Packet):
    """
    A copy of an announce we already accepted (same bytes, so no need to verify
    again): take it if it came over fewer hops, or if we asked for this path
    (a transport answers a path request with the announce it cached).
    """
    cached = self.announces.get(p.dest)
    if cached is None or cached[0] != p.payload:
      return
    path = self.path(p.dest)
    if path is None or p.dest in self._waiters or p.hops + 1 < path.hops:
      self._update_path(lane, p, cached[1].sequence)

  def _update_path(self, lane: _Lane, p: Packet, sequence: int) -> Path:
    path = Path(lane, p.via, p.hops + 1, sequence, time.monotonic() + self.path_ttl)
    self.paths[p.dest] = path
    for fut in self._waiters.pop(p.dest, []):
      if not fut.done():
        fut.set_result(self.identities.get(p.dest))
    for kind, payload in self.store.take(p.dest):
      self._spawn(path.lane.send(Packet(kind, 0, p.dest, path.via, payload)))
    return path

  def _rebroadcast(self, p: Packet):
    """Transport nodes pass announces on, at most once per interval per identity."""
    if not self.transport or p.hops + 1 >= self.max_hops:
      return
    now = time.monotonic()
    if now < self._rebroadcast_at.get(p.dest, 0.0):
      log.debug('%s: not rebroadcasting %s again so soon', self, p.dest.hex())
      return
    self._rebroadcast_at[p.dest] = now + self.rebroadcast_min_interval
    self._prune(self._rebroadcast_at)
    fwd = Packet(ANNOUNCE, p.hops + 1, p.dest, self.address, p.payload)
    self._spawn(self._delayed(self._broadcast, fwd))

  async def _send_all(self, p: Packet):
    for lane in self.lanes:
      if lane.road.online:
        await lane.send(p)

  def _request_keyset(self, address: bytes):
    now = time.monotonic()
    if now < self._keyset_requested_at.get(address, 0.0):
      return
    self._keyset_requested_at[address] = now + self.retry_after
    self._prune(self._keyset_requested_at)
    p = Packet(KEYSET_REQUEST, 0, address, None, random.randbytes(REQUEST_TAG_SIZE))
    self._mark_seen(p.hash)
    self._spawn(self._send_all(p))

  def _handle_keyset_request(self, lane: _Lane, p: Packet):
    if not lane.allow('request', self.ingress):
      return
    ident = self.identities.get(p.dest)
    if ident is not None:
      # we are it, or we know it: the keyset proves itself by hashing to the address
      resp = Packet(KEYSET, 0, p.dest, None, ident.public_bytes)
      self._spawn(self._delayed(lane.send, resp))
      return
    if self.transport and p.hops + 1 < self.max_hops:
      if p.dest not in self._keyset_asked and len(self._keyset_asked) >= KEYSET_WAITS:
        return
      self._keyset_asked.setdefault(p.dest, set()).add(lane)
      fwd = Packet(KEYSET_REQUEST, p.hops + 1, p.dest, None, p.payload)
      self._spawn(self._delayed(self._send_all, fwd))

  def _handle_keyset(self, lane: _Lane, p: Packet):
    asked = self._keyset_asked.pop(p.dest, set())
    waiting = self._need_keyset.pop(p.dest, None)
    messages = self._waiting_messages.pop(p.dest, [])
    if not asked and waiting is None and not messages:
      return  # nobody here asked for it
    if address_of(p.payload) != p.dest:
      return
    known = self.identities.get(p.dest)
    if known is not None and known.public_bytes != p.payload:
      return
    try:
      ident = Identity.from_bytes(p.payload)
    except Exception:
      return
    if self.quantum_safe_only and not ident.quantum_safe:
      return
    self.identities.setdefault(p.dest, ident)
    for other in asked:
      if other is not lane:
        self._spawn(other.send(p))
    if waiting is not None:
      self._handle_announce(*waiting)
    for m in messages:
      if m.type == LINK_REQUEST:
        self._handle_link_request(m)
      else:
        self._deliver(m)

  def _handle_data(self, lane: _Lane, p: Packet):
    """DATA and RECEIPT: take it if it is ours, else forward like any payload."""
    if p.dest == self.address:
      if p.type == DATA:
        self._deliver(p, lane)
        return
      handler = {
        RECEIPT: self._handle_receipt,
        LINK_REQUEST: lambda p: self._handle_link_request(p, lane),
        LINK_ACCEPT: self._handle_link_accept,
        LINK_DATA: self._handle_link_data,
      }[p.type]
      handler(p)
      return
    if not self.transport:
      return
    if p.via == self.address:
      self._forward(p)
    elif p.via is None and self.propagate:
      path = self.path(p.dest)
      if path and path.lane is lane and path.via is None:
        return  # destination is a neighbour on this road and already heard it
      self._forward(p)

  def _forward(self, p: Packet):
    path = self.path(p.dest)
    if path is None:
      if self.propagate:
        if self.store.put(p.dest, p.type, p.payload):
          log.debug('%s: holding %r for later', self, p)
      return
    if p.hops + 1 >= self.max_hops:
      return
    self._spawn(path.lane.send(Packet(p.type, p.hops + 1, p.dest, path.via, p.payload)))

  def _handle_path_request(self, lane: _Lane, p: Packet):
    if not lane.allow('request', self.ingress):
      return
    if p.dest == self.address:
      # whoever asks may not know us yet: include the keyset
      self._spawn(self._delayed(self.announce, None, True))
      return
    if not self.transport:
      return
    cached = self.announces.get(p.dest)
    path = self.path(p.dest)
    if cached and path:
      resp = Packet(ANNOUNCE, path.hops, p.dest, self.address, cached[0])
      self._spawn(self._delayed(lane.announce, resp))
    elif p.hops + 1 < self.max_hops:
      fwd = Packet(PATH_REQUEST, p.hops + 1, p.dest, None, p.payload)
      self._spawn(self._delayed(self._broadcast, fwd))

  def _deliver(self, p: Packet, lane: _Lane | None = None):
    if lane is not None and not lane.allow('message', self.ingress):
      return
    try:
      m = msg.unseal(
        self.identity,
        p.payload,
        self.identities.get,
        ratchets=self.ratchets,
      )
    except msg.SenderUnknown as e:
      # e.g. we restarted and forgot them: fetch their keyset, then try again
      self._wait_for_keyset(e.address, p)
      return
    except Exception as e:
      log.debug('%s: could not open message: %r', self, e)
      return
    sender = self.identities.get(m.sender) or msg.attached_identity(m.signed)
    if self.quantum_safe_only and not (sender and sender.quantum_safe):
      log.debug('%s: dropped message from non-quantum-safe %s', self, m.sender.hex())
      return
    self.identities.setdefault(m.sender, sender)
    if m.recipients == [self.address] and m.sender in self._link_to:
      # a one-to-one sealed message means the peer has no link to us any more
      # (it would have used it): ours is dead weight
      self._drop_link(self._link_to[m.sender])
    self._accept_message(m)

  def _accept_message(self, m: msg.Message):
    """Receipt (always), then hand to the application once per message id."""
    if m.receipt_secret is not None:
      # always answer, even for a repeat: our last receipt may have been lost
      tag = msg.receipt_tag(m.receipt_secret, self.address)
      self._spawn(self._send_data(m.sender, tag + os.urandom(RECEIPT_NONCE_SIZE), RECEIPT))
    if m.id in self._delivered:
      # a repeat means our receipt did not arrive: the way back may be dead
      self._rediscover(m.sender)
      return
    self._delivered[m.id] = None
    if len(self._delivered) > DELIVERED_CACHE:
      self._delivered.popitem(last=False)
    for cb in self._message_handlers:
      self._call(cb, m)

  def _wait_for_keyset(self, address: bytes, p: Packet):
    """Hold a message or link request from an unknown sender; fetch its keyset."""
    q = self._waiting_messages.setdefault(address, [])
    if len(q) < WAITING_PER_SENDER and len(self._waiting_messages) <= WAITING_SENDERS:
      q.append(p)
    self._request_keyset(address)

  def _rediscover(self, address: bytes):
    """Ask for a fresh path to `address`, at most once per retry_after."""
    now = time.monotonic()
    if now < self._rediscover_at.get(address, 0.0):
      return
    self._rediscover_at[address] = now + self.retry_after
    self._prune(self._rediscover_at)
    self._spawn(self.request_path(address, self.retry_after, fresh=True))

  # --- propagation nodes ---

  async def fetch(self, timeout: float = 30.0, node: bytes | None = None) -> int:
    """
    Collect what a propagation node holds for us (over a link, so it knows it
    is really us). Returns how many items came; they are handled as if they
    had just arrived (messages go to on_message, receipts to on_receipt).
    """
    node = node or self._propagation_node()
    if node is None:
      raise LookupError('no propagation node known')
    keys = self.link_to(node) or await self.open_link(node, timeout)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    fut = loop.create_future()
    self._fetching[node] = [{}, fut]
    try:
      while True:
        await self._send_data(node, L.seal(keys, cbor.dumps({PR.P_FETCH: True})), LINK_DATA)
        left = deadline - loop.time()
        if left <= 0:
          raise TimeoutError('propagation node did not answer')
        try:
          return await asyncio.wait_for(asyncio.shield(fut), min(self.retry_after, left))
        except TimeoutError:
          pass  # ask again: the node resends the same batch
    finally:
      self._fetching.pop(node, None)

  def _handle_propagation(self, keys: L.LinkKeys, body: dict):
    peer = keys.peer
    send = self._resource_send  # (keys, field, value) -> seal and send over the link
    if PR.P_DEPOSIT in body and self.propagate:
      item = body[PR.P_DEPOSIT]
      if not (isinstance(item, list) and len(item) == 3):
        return
      dest, kind, payload = item
      if kind not in (DATA, RECEIPT) or not isinstance(payload, bytes):
        return
      if self.store.put(dest, kind, payload):
        secret = body.get(msg.M_RECEIPT)
        if isinstance(secret, bytes) and len(secret) == msg.RECEIPT_SECRET_SIZE:
          tag = msg.receipt_tag(secret, self.address)
          self._spawn(self._send_data(peer, tag + os.urandom(RECEIPT_NONCE_SIZE), RECEIPT))
    elif PR.P_FETCH in body and self.propagate:
      # the link authenticated the peer: hand over what we hold for it
      batch = self._batches.get(peer)
      if batch is None:
        batch = self.store.take(peer)[: PR.BATCH]
        self._batches[peer] = batch
      for i, (kind, payload) in enumerate(batch):
        send(keys, PR.P_ITEM, [i, kind, payload])
      send(keys, PR.P_END, len(batch))
    elif PR.P_ACK in body:
      batch = self._batches.get(peer)
      if batch is not None and body[PR.P_ACK] == len(batch):
        del self._batches[peer]
    elif PR.P_ITEM in body:
      entry = self._fetching.get(peer)
      if entry and isinstance(body[PR.P_ITEM], list) and len(body[PR.P_ITEM]) == 3:
        i, kind, payload = body[PR.P_ITEM]
        entry[0][i] = (kind, payload)
    elif PR.P_END in body:
      entry = self._fetching.get(peer)
      n = body[PR.P_END]
      if entry is None or entry[1].done() or not isinstance(n, int):
        return
      items, fut = entry
      if any(i not in items for i in range(n)):
        return  # something got lost: fetch() asks again and gets the same batch
      send(keys, PR.P_ACK, n)
      for i in range(n):
        kind, payload = items[i]
        p = Packet(kind, 0, self.address, None, payload)
        if kind == DATA:
          self._deliver(p)
        elif kind == RECEIPT:
          self._handle_receipt(p)
      fut.set_result(n)

  # --- resources ---

  def _resource_send(self, keys: L.LinkKeys, field_id: int, value):
    self._spawn(self._send_data(keys.peer, L.seal(keys, R.encode(field_id, value)), LINK_DATA))

  def _handle_resource(self, keys: L.LinkKeys, body: dict):
    peer = keys.peer
    if R.R_ADVERTISE in body:
      ad = body[R.R_ADVERTISE]
      rid = ad.get(1) if isinstance(ad, dict) else None
      if (peer, rid) in self._res_done:
        self._resource_send(keys, R.R_DONE, rid)  # our done was lost
        return
      if (peer, rid) not in self._res_in:
        try:
          inc = R.Incoming.from_advertisement(peer, ad, self.max_resource)
        except Exception as e:
          log.debug('%s: refused resource: %r', self, e)
          return
        self._res_in[(peer, inc.id)] = [inc, None, 0, []]
      self._resource_ask(keys, rid)
    elif R.R_REQUEST in body:
      rid, want = body[R.R_REQUEST]
      entry = self._res_out.get(rid)
      if entry is None or entry[0].peer != peer:
        return
      out = entry[0]
      out.active = asyncio.get_running_loop().time()
      for i in list(dict.fromkeys(want))[: 2 * R.WINDOW]:
        if isinstance(i, int) and 0 <= i < len(out.parts):
          self._resource_send(keys, R.R_PART, [rid, i, out.parts[i]])
    elif R.R_PART in body:
      rid, index, data = body[R.R_PART]
      entry = self._res_in.get((peer, rid))
      if entry is None:
        return
      inc = entry[0]
      inc.add(index, data)
      entry[2] = 0  # progress: reset the stall count
      if inc.complete:
        self._resource_finish(keys, entry)
      elif all(i in inc.parts for i in entry[3]):
        self._resource_ask(keys, rid)  # this window is in: ask for the next
    elif R.R_DONE in body:
      entry = self._res_out.get(body[R.R_DONE])
      if entry and entry[0].peer == peer and not entry[1].done():
        entry[1].set_result(True)

  def _resource_ask(self, keys: L.LinkKeys, rid: bytes):
    entry = self._res_in.get((keys.peer, rid))
    if entry is None:
      return
    want = entry[0].missing(R.WINDOW)
    entry[3] = want
    self._resource_send(keys, R.R_REQUEST, [rid, want])
    if entry[1]:
      entry[1].cancel()
    path = self.path(keys.peer)
    frame = path.lane.frame_time if path else 0.0
    delay = max(0.3, 2 * R.WINDOW * frame)
    entry[1] = asyncio.get_running_loop().call_later(delay, self._resource_stalled, keys, rid)

  def _resource_stalled(self, keys: L.LinkKeys, rid: bytes):
    entry = self._res_in.get((keys.peer, rid))
    if entry is None:
      return
    entry[2] += 1
    if entry[2] > RESOURCE_STALLS:
      log.debug('%s: giving up on resource %s', self, rid.hex())
      self._res_in.pop((keys.peer, rid), None)
      return
    self._resource_ask(keys, rid)

  def _resource_finish(self, keys: L.LinkKeys, entry: list):
    inc = entry[0]
    if entry[1]:
      entry[1].cancel()
    self._res_in.pop((keys.peer, inc.id), None)
    try:
      data = inc.assemble()
    except Exception as e:
      log.debug('%s: resource failed its hash: %r', self, e)
      return
    self._res_done[(keys.peer, inc.id)] = None
    while len(self._res_done) > DELIVERED_CACHE:
      self._res_done.popitem(last=False)
    self._resource_send(keys, R.R_DONE, inc.id)
    res = R.Resource(keys.peer, inc.id, data, inc.meta)
    for cb in self._resource_handlers:
      self._call(cb, res)

  def _handle_receipt(self, p: Packet):
    o = self._outbox.pop(p.payload[: msg.RECEIPT_TAG_SIZE], None)
    if o is None or o.future.done():
      return
    o.future.set_result(True)
    for cb in self._receipt_handlers:
      self._call(cb, o.message, o.address)

  def _handle_link_request(self, p: Packet, lane: _Lane | None = None):
    if not self.accept_links:
      return
    lid = L.link_id(p.payload)
    if lid in self._accepts:  # a repeat: our accept may have been lost
      peer, accept = self._accepts[lid]
      self._spawn(self._send_data(peer, accept, LINK_ACCEPT))
      return
    if lane is not None and not lane.allow('link', self.ingress):
      return
    try:
      peer, accept, keys = L.accept_request(
        self.identity,
        p.payload,
        self.identities.get,
        ratchets=self.ratchets,
        quantum_safe_only=self.quantum_safe_only,
      )
    except msg.SenderUnknown as e:
      self._wait_for_keyset(e.address, p)
      return
    except Exception as e:
      log.debug('%s: bad link request: %r', self, e)
      return
    if self.quantum_safe_only and not peer.quantum_safe:
      return
    self.identities.setdefault(peer.address, peer)
    self._add_link(keys)
    self._accepts[lid] = (peer.address, accept)
    while len(self._accepts) > ACCEPT_CACHE:
      self._accepts.popitem(last=False)
    self._spawn(self._send_data(peer.address, accept, LINK_ACCEPT))

  def _handle_link_accept(self, p: Packet):
    entry = self._pending_links.pop(p.payload[: L.LINK_ID_SIZE], None)
    if entry is None:
      return
    pending, fut = entry
    try:
      keys = L.finish(pending, p.payload)
    except Exception as e:
      log.debug('%s: bad link accept: %r', self, e)
      return
    self._add_link(keys)
    if not fut.done():
      fut.set_result(keys)

  def _handle_link_data(self, p: Packet):
    self._expire_links()
    keys = self.links.get(p.payload[: L.LINK_ID_SIZE])
    if keys is None:
      return
    try:
      plain = L.unseal(keys, p.payload)
      body = cbor.loads(plain)
      if isinstance(body, dict) and body.keys() & {R.R_ADVERTISE, R.R_REQUEST, R.R_PART, R.R_DONE}:
        self._used_link(keys.link_id)
        self._handle_resource(keys, body)
        return
      if isinstance(body, dict) and body.keys() & PR.FIELDS:
        self._used_link(keys.link_id)
        self._handle_propagation(keys, body)
        return
      m, close = L.read_message(keys, self.address, plain)
    except Exception as e:
      log.debug('%s: bad link message: %r', self, e)
      return
    if close:
      self._drop_link(keys.link_id)
      return
    self._used_link(keys.link_id)
    self._accept_message(m)

  def _call(self, cb, *args):
    try:
      r = cb(*args)
      if inspect.isawaitable(r):
        self._spawn(r)
    except Exception:
      log.exception('%s: handler failed', self)
