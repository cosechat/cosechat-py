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
from .identity import Identity, address_of, signer_of
from .keys import QUANTUM_SAFE_KEM, Key
from .packet import (
  ANNOUNCE,
  DATA,
  FRAGMENT_OVERHEAD,
  KEYSET,
  KEYSET_REQUEST,
  LINK_ACCEPT,
  LINK_DATA,
  LINK_REQUEST,
  PATH_REQUEST,
  RECEIPT,
  ROUTED,
  Packet,
  PacketError,
  Reassembler,
  RoadAuth,
  decode,
  fragment,
)
from .ratchet import MemoryRatchets, Ratchets
from .roads import Road
from .store import MemoryStore, Store

log = logging.getLogger('cosiechat.node')


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
    self.queue: dict[bytes, tuple[int, float, Packet]] = {}  # dest -> (hops, queued at, packet)
    self._ready_at = 0.0
    self._wake = asyncio.Event()

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
      frames = fragment(frame, self.max_frame - FRAGMENT_OVERHEAD)
    total = 0
    for f in frames:
      wire = self.auth.wrap(f) if self.auth else f
      total += len(wire)
      await self.road.send(wire)
    return total

  async def announce(self, packet: Packet):
    if not self.budgeted:
      await self.send(packet)
      return
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
    store: Store | None = None,
    max_links: int = 256,
    path_ttl: float = 7 * 86400,
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
    self.max_links = max_links
    # a path is forgotten this long after the announce that made it (local
    # monotonic clock; Reticulum uses a week). Any valid announce refreshes it.
    self.path_ttl = path_ttl
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
    )
    p = Packet(ANNOUNCE, 0, self.address, None, data)
    self._mark_seen(p.hash)
    await self._broadcast(p)

  async def _broadcast_announce(self, p: Packet):
    for lane in self.lanes:
      if lane.road.online:
        await lane.announce(p)

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
    p = Packet(PATH_REQUEST, 0, address, None, random.randbytes(8))
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
  ) -> msg.Message:
    """
    Seal a message for one or more recipients (addresses or Identities) and
    send it. Unknown recipients are looked up with a path request first.
    With receipt=True (default) it is resent until each recipient confirms;
    await node.delivered(message) to find out.
    """
    targets = to if isinstance(to, (list, tuple)) else [to]
    if len(targets) == 1:
      addr = targets[0].address if isinstance(targets[0], Identity) else targets[0]
      if addr in self._link_to:
        return await self._send_on_link(addr, content, title, fields, receipt)
    recipients = [await self._resolve(t, timeout) for t in targets]
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

      await self._dispatch(m, r.address, reseal, receipt)
    return m

  async def _resolve(self, t, timeout: float) -> Identity:
    """A recipient we may send to: known identity, quantum-safe, with a ratchet."""
    if isinstance(t, Identity):
      self.identities.setdefault(t.address, t.public())
      t = t.address
    if self.path(t) is None:
      # no route yet: ask the mesh; without one we still flood to neighbours
      # and propagation nodes
      await self.request_path(t, timeout)
    ident = self.identities.get(t)
    if ident is None:
      raise LookupError(f'no identity known for {t.hex()}')
    if self.quantum_safe_only and not ident.quantum_safe:
      raise PermissionError(f'{t.hex()} is not quantum-safe; refusing to send')
    if self.peer_ratchet(t) is None:
      # no ratchet from this peer yet: ask for a fresh announce
      await self.request_path(t, timeout, fresh=True)
      if self.peer_ratchet(t) is None:
        raise LookupError(f'no ratchet for {t.hex()}: it must announce first')
    if self.quantum_safe_only and self.peer_ratchet(t).alg not in QUANTUM_SAFE_KEM:
      raise PermissionError(f'{t.hex()} announced a ratchet that is not quantum-safe')
    return ident

  async def _dispatch(
    self, m: msg.Message, addr: bytes, reseal, receipt: bool, attempts=None, fallback=None
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
    )
    self._outbox[msg.receipt_tag(m.receipt_secret, addr)] = o
    self._deliveries.setdefault(m.id, []).append(o.future)
    while len(self._deliveries) > 1000:
      self._deliveries.popitem(last=False)
    self._spawn(self._retry(o))

  # --- links ---

  def link_to(self, address: bytes) -> L.LinkKeys | None:
    lid = self._link_to.get(address)
    return self.links.get(lid) if lid else None

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
    keys = self.links.pop(lid, None)
    if keys and self._link_to.get(keys.peer) == lid:
      del self._link_to[keys.peer]

  def _add_link(self, keys: L.LinkKeys):
    old = self._link_to.get(keys.peer)
    if old and old != keys.link_id:
      self.links.pop(old, None)
    self.links[keys.link_id] = keys
    self._link_to[keys.peer] = keys.link_id
    while len(self.links) > self.max_links:
      self._drop_link(next(iter(self.links)))  # least recently used

  def _used_link(self, lid: bytes):
    if lid in self.links:
      self.links.move_to_end(lid)

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
    tag = msg.receipt_tag(o.message.receipt_secret, o.address)
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
        try:
          payload, kind = o.reseal()
        except LookupError:
          break
        await self._send_data(o.address, payload, kind)
        wait = min(wait * 2, self.retry_max)
      self._outbox.pop(tag, None)
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
    if len(self._seen) > 50000:
      self._seen.popitem(last=False)
    return True

  def _on_frame(self, lane: _Lane, frame: bytes):
    try:
      if lane.auth:
        frame = lane.auth.unwrap(frame)
      item = decode(frame)
      if isinstance(item, tuple):
        whole = self._reassembler.add(id(lane), item)
        if whole is None:
          return
        item = decode(whole)
        if isinstance(item, tuple):
          raise PacketError('nested fragment')
    except PacketError as e:
      log.debug('%s: dropped frame on %s: %s', self, lane.road, e)
      return
    if not self._mark_seen(item.hash):
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

  def _handle_announce(self, lane: _Lane, p: Packet):
    if p.dest == self.address or not self._precheck_announce(p):
      return
    try:
      ann = msg.verify_announce(p.payload, p.dest, self.identities.get)
    except msg.KeysetNeeded:
      # a short announce from someone we have not met: fetch the keyset (from
      # anyone; it is self-authenticating), then look at this announce again
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
    path = self._update_path(lane, p, ann.sequence)
    for cb in self._announce_handlers:
      self._call(cb, ann, path)
    self._rebroadcast(p)

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
    p = Packet(KEYSET_REQUEST, 0, address, None, random.randbytes(8))
    self._mark_seen(p.hash)
    self._spawn(self._send_all(p))

  def _handle_keyset_request(self, lane: _Lane, p: Packet):
    ident = self.identities.get(p.dest)
    if ident is not None:
      # we are it, or we know it: the keyset proves itself by hashing to the address
      resp = Packet(KEYSET, 0, p.dest, None, ident.public_bytes)
      self._spawn(self._delayed(lane.send, resp))
      return
    if self.transport and p.hops + 1 < self.max_hops:
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
      self._deliver(m)

  def _handle_data(self, lane: _Lane, p: Packet):
    """DATA and RECEIPT: take it if it is ours, else forward like any payload."""
    if p.dest == self.address:
      handler = {
        DATA: self._deliver,
        RECEIPT: self._handle_receipt,
        LINK_REQUEST: self._handle_link_request,
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

  def _deliver(self, p: Packet):
    try:
      m = msg.unseal(
        self.identity,
        p.payload,
        self.identities.get,
        ratchets=self.ratchets,
      )
    except msg.SenderUnknown as e:
      # e.g. we restarted and forgot them: fetch their keyset, then try again
      q = self._waiting_messages.setdefault(e.address, [])
      if len(q) < 16 and len(self._waiting_messages) <= 256:
        q.append(p)
      self._request_keyset(e.address)
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
      self._spawn(self._send_data(m.sender, tag + os.urandom(8), RECEIPT))
    if m.id in self._delivered:
      return
    self._delivered[m.id] = None
    if len(self._delivered) > 10000:
      self._delivered.popitem(last=False)
    for cb in self._message_handlers:
      self._call(cb, m)

  def _handle_receipt(self, p: Packet):
    o = self._outbox.pop(p.payload[: msg.RECEIPT_TAG_SIZE], None)
    if o is None or o.future.done():
      return
    o.future.set_result(True)
    for cb in self._receipt_handlers:
      self._call(cb, o.message, o.address)

  def _handle_link_request(self, p: Packet):
    if not self.accept_links:
      return
    lid = L.link_id(p.payload)
    if lid in self._accepts:  # a repeat: our accept may have been lost
      peer, accept = self._accepts[lid]
      self._spawn(self._send_data(peer, accept, LINK_ACCEPT))
      return
    try:
      peer, accept, keys = L.accept_request(
        self.identity,
        p.payload,
        self.identities.get,
        ratchets=self.ratchets,
        quantum_safe_only=self.quantum_safe_only,
      )
    except Exception as e:
      log.debug('%s: bad link request: %r', self, e)
      return
    if self.quantum_safe_only and not peer.quantum_safe:
      return
    self.identities.setdefault(peer.address, peer)
    self._add_link(keys)
    self._accepts[lid] = (peer.address, accept)
    while len(self._accepts) > 256:
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
    keys = self.links.get(p.payload[: L.LINK_ID_SIZE])
    if keys is None:
      return
    try:
      m, close = L.read_message(keys, self.address, L.unseal(keys, p.payload))
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
