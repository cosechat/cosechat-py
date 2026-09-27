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

from . import message as msg
from .identity import Identity
from .keys import Key
from .packet import (
  ANNOUNCE,
  DATA,
  FRAGMENT_OVERHEAD,
  PATH_REQUEST,
  RECEIPT,
  Packet,
  PacketError,
  Reassembler,
  RoadAuth,
  decode,
  fragment,
)
from .ratchet import MemoryRatchets, Ratchets
from .roads import Road

log = logging.getLogger('cosiechat.node')


@dataclass
class Path:
  lane: '_Lane'
  via: bytes | None
  hops: int
  sequence: int  # the announce's sequence (ordering only)
  updated: float  # local monotonic clock, informational

  @property
  def road(self) -> Road:
    return self.lane.road


@dataclass
class _Outgoing:
  message: msg.Message
  recipient: Identity
  future: asyncio.Future


class _Lane:
  """A road attached to a node, plus that road's auth wrapper."""

  def __init__(self, road: Road, auth: RoadAuth | None):
    self.road = road
    self.auth = auth

  @property
  def max_frame(self) -> int:
    return self.road.mtu - (self.auth.overhead if self.auth else 0)

  async def send(self, packet: Packet):
    frame = packet.encode()
    if len(frame) <= self.max_frame:
      frames = [frame]
    else:
      frames = fragment(frame, self.max_frame - FRAGMENT_OVERHEAD)
    for f in frames:
      await self.road.send(self.auth.wrap(f) if self.auth else f)


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
    forward_secrecy: bool = True,
    ratchets: Ratchets | None = None,
    retry_after: float = 30.0,
    retry_max: float = 600.0,
    max_attempts: int = 4,
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
    # On by default: refuse peers whose keys a quantum attacker could break
    # (ignore their announces, refuse to send to them, drop what they send).
    # Pre-quantum peers need an explicit quantum_safe_only=False.
    self.quantum_safe_only = quantum_safe_only
    if quantum_safe_only and not self.identity.quantum_safe:
      raise ValueError(
        'identity is not quantum-safe; use the pq or hybrid suite, '
        'or pass quantum_safe_only=False to accept pre-quantum crypto'
      )
    # On by default too: we announce a ratchet, only accept messages sealed to
    # one of our ratchets, and only send to peers' announced ratchets.
    # forward_secrecy=False falls back to long-term keys.
    # `ratchets` is where our ratchet keys live (see ratchet.py). The default
    # keeps them in memory only; when to rotate or discard them is the
    # application's storage policy (rotate_ratchet(), examples/storage.py).
    self.forward_secrecy = forward_secrecy
    if forward_secrecy and ratchets is None:
      ratchets = MemoryRatchets(self.identity.kem_key.alg)
    self.ratchets = ratchets
    self.peer_ratchets: dict[bytes, Key] = {}
    self._sequence = 0  # our announce sequence: Unix ms, but never going backwards
    # delivery: resend after retry_after, doubling up to retry_max, max_attempts
    # sends in all (timed by the local event loop clock only)
    self.retry_after = retry_after
    self.retry_max = retry_max
    self.max_attempts = max_attempts
    self._outbox: dict[bytes, _Outgoing] = {}  # receipt tag -> pending send
    self._deliveries: OrderedDict[bytes, list[asyncio.Future]] = OrderedDict()
    self._delivered: OrderedDict[bytes, None] = OrderedDict()  # message ids we handed over
    self.name = name or self.identity.address.hex()[:8]

    self.lanes: list[_Lane] = []
    self.identities: dict[bytes, Identity] = {self.address: self.identity.public()}
    self.announces: dict[bytes, tuple[bytes, msg.Announce]] = {}
    self.paths: dict[bytes, Path] = {}
    self.pending: dict[bytes, list[bytes]] = {}
    self.max_pending = 64

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
    lane = _Lane(road, auth)
    road.on_frame = lambda frame, lane=lane: self._on_frame(lane, frame)
    self.lanes.append(lane)
    if self._running:
      self._spawn(road.start())
    return road

  async def start(self):
    self._running = True
    for lane in self.lanes:
      await lane.road.start()
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

  async def announce(self, app_data: Any = None):
    self._sequence = max(msg.now_ms(), self._sequence + 1)
    data = msg.make_announce(
      self.identity,
      app_data if app_data is not None else self.app_data,
      sequence=self._sequence,
      ratchet=self.ratchets.current() if self.ratchets is not None else None,
    )
    p = Packet(ANNOUNCE, 0, self.address, None, data)
    self._mark_seen(p.hash)
    await self._broadcast(p)

  def peer_ratchet(self, address: bytes) -> Key | None:
    """The ratchet in the newest announce we accepted from `address`."""
    return self.peer_ratchets.get(address)

  async def rotate_ratchet(self, announce: bool = True) -> Key:
    """Start using a new ratchet (the provider decides what happens to old ones)."""
    if self.ratchets is None:
      raise ValueError('forward secrecy is off; there are no ratchets')
    k = self.ratchets.rotate()
    if announce:
      await self.announce()
    return k

  async def request_path(
    self, address: bytes, timeout: float = 10.0, fresh: bool = False
  ) -> Identity | None:
    """Ask the mesh for `address`; resolves once its announce arrives (a new one if fresh)."""
    if not fresh and address in self.paths and address in self.identities:
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
    recipients = []
    for t in targets:
      if isinstance(t, Identity):
        self.identities.setdefault(t.address, t.public())
        t = t.address
      if t not in self.paths:
        # no route yet: ask the mesh; without one we still flood to neighbours
        # and propagation nodes
        await self.request_path(t, timeout)
      ident = self.identities.get(t)
      if ident is None:
        raise LookupError(f'no identity known for {t.hex()}')
      if self.quantum_safe_only and not ident.quantum_safe:
        raise PermissionError(f'{t.hex()} is not quantum-safe; refusing to send')
      if self.forward_secrecy and self.peer_ratchet(t) is None:
        # no ratchet from this peer yet: ask for a fresh announce
        await self.request_path(t, timeout, fresh=True)
        if self.peer_ratchet(t) is None:
          raise LookupError(
            f'no current ratchet for {t.hex()}; it must announce '
            '(or use forward_secrecy=False to send to its long-term key)'
          )
      recipients.append(ident)
    m = msg.sign_message(
      self.identity,
      recipients,
      content,
      title,
      fields,
      attach_identity=attach_identity,
      receipt_secret=os.urandom(msg.RECEIPT_SECRET_SIZE) if receipt else None,
    )
    futs = []
    for r in recipients:
      await self._send_data(r.address, self._envelope(m, r))
      if receipt:
        o = _Outgoing(m, r, asyncio.get_running_loop().create_future())
        self._outbox[msg.receipt_tag(m.receipt_secret, r.address)] = o
        futs.append(o.future)
        self._spawn(self._retry(o))
    if receipt:
      self._deliveries[m.id] = futs
      while len(self._deliveries) > 1000:
        self._deliveries.popitem(last=False)
    return m

  def _envelope(self, m: msg.Message, r: Identity) -> bytes:
    # every (re)send is a fresh envelope around the same signed message: a new
    # packet hash gets past duplicate filters, and the newest ratchet is used
    return msg.envelope(m.signed, r, self.peer_ratchet(r.address))

  async def _retry(self, o: _Outgoing):
    tag = msg.receipt_tag(o.message.receipt_secret, o.recipient.address)
    wait = self.retry_after
    try:
      for attempt in range(1, self.max_attempts + 1):
        try:
          await asyncio.wait_for(asyncio.shield(o.future), wait)
          return
        except TimeoutError:
          pass
        if attempt == self.max_attempts:
          break
        log.debug('%s: resending %s to %s', self, o.message.id.hex()[:8], o.recipient.address.hex())
        await self._send_data(o.recipient.address, self._envelope(o.message, o.recipient))
        wait = min(wait * 2, self.retry_max)
      if not o.future.done():
        o.future.set_result(False)
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
    for lane in self.lanes:
      if lane is not exclude and lane.road.online:
        await lane.send(p)

  async def _send_data(self, dest: bytes, payload: bytes, type: int = DATA):
    path = self.paths.get(dest)
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
    elif item.type in (DATA, RECEIPT):
      self._handle_data(lane, item)
    elif item.type == PATH_REQUEST:
      self._handle_path_request(lane, item)

  def _handle_announce(self, lane: _Lane, p: Packet):
    try:
      ann = msg.verify_announce(p.payload, p.dest)
    except Exception as e:  # anything malformed from the network is just dropped
      log.debug('%s: invalid announce: %r', self, e)
      return
    if p.dest == self.address:
      return
    known = self.identities.get(p.dest)
    if known is not None and known.public_bytes != ann.identity.public_bytes:
      # an address is pinned to the first keyset seen for it
      log.warning('%s: rejected announce with different keys for %s', self, p.dest.hex())
      return
    if self.quantum_safe_only and not ann.identity.quantum_safe:
      log.debug('%s: ignoring non-quantum-safe announce from %s', self, p.dest.hex())
      return
    prev = self.announces.get(p.dest)
    # an identity's sequence only goes up: an older (replayed) announce must not
    # bring back an old path or ratchet. This compares the peer with itself,
    # never with our clock.
    if prev and ann.sequence < prev[1].sequence:
      return
    self.identities[p.dest] = ann.identity
    self.announces[p.dest] = (p.payload, ann)
    if ann.ratchet is not None:
      self.peer_ratchets[p.dest] = ann.ratchet
    path = Path(lane, p.via, p.hops + 1, ann.sequence, time.monotonic())
    self.paths[p.dest] = path

    for fut in self._waiters.pop(p.dest, []):
      if not fut.done():
        fut.set_result(ann.identity)
    for cb in self._announce_handlers:
      self._call(cb, ann, path)

    if self.transport and p.hops + 1 < self.max_hops:
      fwd = Packet(ANNOUNCE, p.hops + 1, p.dest, self.address, p.payload)
      self._spawn(self._delayed(self._broadcast, fwd))

    for kind, payload in self.pending.pop(p.dest, []):
      self._spawn(path.lane.send(Packet(kind, 0, p.dest, path.via, payload)))

  def _handle_data(self, lane: _Lane, p: Packet):
    """DATA and RECEIPT: take it if it is ours, else forward like any payload."""
    if p.dest == self.address:
      if p.type == RECEIPT:
        self._handle_receipt(p)
      else:
        self._deliver(p)
      return
    if not self.transport:
      return
    if p.via == self.address:
      self._forward(p)
    elif p.via is None and self.propagate:
      path = self.paths.get(p.dest)
      if path and path.lane is lane and path.via is None:
        return  # destination is a neighbour on this road and already heard it
      self._forward(p)

  def _forward(self, p: Packet):
    path = self.paths.get(p.dest)
    if path is None:
      if self.propagate:
        q = self.pending.setdefault(p.dest, [])
        if len(q) < self.max_pending:
          q.append((p.type, p.payload))
          log.debug('%s: holding %r for later', self, p)
      return
    if p.hops + 1 >= self.max_hops:
      return
    self._spawn(path.lane.send(Packet(p.type, p.hops + 1, p.dest, path.via, p.payload)))

  def _handle_path_request(self, lane: _Lane, p: Packet):
    if p.dest == self.address:
      self._spawn(self._delayed(self.announce))
      return
    if not self.transport:
      return
    cached = self.announces.get(p.dest)
    path = self.paths.get(p.dest)
    if cached and path:
      resp = Packet(ANNOUNCE, path.hops, p.dest, self.address, cached[0])
      self._spawn(self._delayed(lane.send, resp))
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
        require_ratchet=self.forward_secrecy,
      )
    except Exception as e:
      log.debug('%s: could not open message: %r', self, e)
      return
    sender = self.identities.get(m.sender) or msg.attached_identity(m.signed)
    if self.quantum_safe_only and not (sender and sender.quantum_safe):
      log.debug('%s: dropped message from non-quantum-safe %s', self, m.sender.hex())
      return
    self.identities.setdefault(m.sender, sender)
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
      self._call(cb, o.message, o.recipient.address)

  def _call(self, cb, *args):
    try:
      r = cb(*args)
      if inspect.isawaitable(r):
        self._spawn(r)
    except Exception:
      log.exception('%s: handler failed', self)
