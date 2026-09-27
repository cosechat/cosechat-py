"""Smaller announces (signing-only keysets, short announces with keyset fetch) and path expiry."""

import asyncio

from test_node import inbox, make, run, until

from cosiechat.node import Node
from cosiechat.packet import KEYSET, KEYSET_REQUEST, Packet, decode
from cosiechat.roads.memory import MemoryHub


def spy(node):
  """Record (type, size) of packets a node puts on its first road, whole or fragmented."""
  seen = []
  road = node.lanes[0].road
  real = road.send

  async def send(frame):
    item = decode(frame)
    seen.append(('frag', len(frame)) if isinstance(item, tuple) else (item.type, len(frame)))
    await real(frame)

  road.send = send
  return seen


def test_first_announce_is_full_then_short():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    got = []
    b.on_announce(lambda ann, path: got.append(ann.full))
    async with a, b:
      await a.announce()
      await until(lambda: got)
      await a.announce()
      await until(lambda: len(got) == 2)
    assert got == [True, False]

  run(main())


def test_short_announce_triggers_keyset_fetch():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a:
      await a.announce(full=True)
      await a.announce()  # short, b is not listening yet
      async with b:
        sent_b = spy(b)
        await a.announce()  # short: b has never seen a's keyset
        await until(lambda: a.address in b.paths, timeout=5)
    assert b.known(a.address) == a.identity.public()
    assert KEYSET_REQUEST in [t for t, _ in sent_b]

  run(main())


def test_keyset_fetch_through_a_transport():
  async def main():
    h1, h2 = MemoryHub(), MemoryHub()
    a = make(h1)
    t = Node(transport=True, rebroadcast_delay=0.01, rebroadcast_min_interval=0)
    t.add_road(h1.road())
    t.add_road(h2.road())
    b = make(h2)
    async with a, t:
      await a.announce(full=True)
      await until(lambda: a.address in t.paths)
      async with b:
        await a.announce()  # short; t knows a's keyset, b does not
        await until(lambda: a.address in b.paths, timeout=5)
        assert b.paths[a.address].via == t.address

  run(main())


def test_path_request_answer_is_full():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a, b:
      await a.announce()  # full (first)
      await a.announce()  # short
      b2 = make(hub)
      async with b2:
        asked = spy(b2)
        assert await b2.request_path(a.address, timeout=5)
        await asyncio.sleep(0.05)
    # b2 learned a's keyset from the answer itself, without fetching it
    assert b2.known(a.address) == a.identity.public()
    assert KEYSET_REQUEST not in [t for t, _ in asked]

  run(main())


def test_keyset_answer_needs_a_matching_address():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    async with a, b:
      await a.announce(full=True)
      await until(lambda: a.address in b.paths)
      c = make(hub)
      async with c:
        # c pretends to have asked; a keyset that does not hash to the address is ignored
        c._keyset_asked[a.address] = set()
        c._handle_keyset(c.lanes[0], Packet(KEYSET, 0, a.address, None, b.identity.public_bytes))
        assert c.known(a.address) is None

  run(main())


def test_paths_expire_and_are_found_again():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub, path_ttl=0.2)
    box = inbox(a)
    async with a, b:
      await a.announce()
      await b.announce()
      await until(lambda: b.path(a.address) and a.path(b.address))
      await asyncio.sleep(0.25)
      assert b.path(a.address) is None  # forgotten on the local clock
      # sending asks the mesh again (a answers its path request)
      m = await b.send(a.address, 'still there?', timeout=5)
      assert await b.delivered(m, timeout=5)
      assert b.path(a.address) is not None and box[0].content == 'still there?'

  run(main())


def test_a_fresh_announce_refreshes_the_path():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub, path_ttl=0.3)
    async with a, b:
      await a.announce()
      await until(lambda: b.path(a.address))
      first = b.path(a.address).expires
      await asyncio.sleep(0.05)
      await a.announce()
      await until(lambda: b.path(a.address) and b.path(a.address).expires > first)

  run(main())
