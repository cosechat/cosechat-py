"""Resources: large transfers over links, pulled in windows."""

import os
import random

import pytest
from test_delivery import pair
from test_node import run

from cosiechat import link as L
from cosiechat import resource as R
from cosiechat.keys import CoseError
from cosiechat.packet import LINK_DATA, Packet


def test_split_and_assemble():
  data = os.urandom(10_000)
  out = R.Outgoing.of(b'\x01' * 16, data, {'name': 'x.bin'})
  inc = R.Incoming.from_advertisement(b'\x02' * 16, out.advertisement())
  assert inc.missing() == list(range(R.WINDOW))
  for i, part in reversed(list(enumerate(out.parts))):
    inc.add(i, part)
  assert inc.complete and inc.assemble() == data and inc.meta == {'name': 'x.bin'}


def test_wrong_parts_fail_the_hash():
  out = R.Outgoing.of(b'\x01' * 16, b'a' * 1000)
  inc = R.Incoming.from_advertisement(b'\x02' * 16, out.advertisement())
  for i in range(inc.count):
    inc.add(i, b'b' * len(out.parts[i]))
  with pytest.raises(CoseError):
    inc.assemble()


def test_oversize_and_malformed_advertisements_refused():
  out = R.Outgoing.of(b'\x01' * 16, b'x' * 5000)
  with pytest.raises(CoseError):
    R.Incoming.from_advertisement(b'\x02' * 16, out.advertisement(), max_size=1000)
  bad = {**out.advertisement(), 1: b'\x00' * 16}  # id does not match the hash
  with pytest.raises(CoseError):
    R.Incoming.from_advertisement(b'\x02' * 16, bad)


def test_a_part_fits_one_lora_frame():
  a_to_b = L.LinkKeys(b'\x00' * 16, b'\x01' * 16, True, *[None] * 2)
  from cosiechat.keys import CHACHA20_POLY1305, Key

  a_to_b.send_key = Key(CHACHA20_POLY1305, priv=b'\x00' * 32, kid=b'\x00' * 16)
  part = R.encode(R.R_PART, [b'\x00' * 16, 9999, b'\x00' * R.PART_SIZE])
  packet = Packet(LINK_DATA, 0, b'\x01' * 16, b'\x02' * 16, L.seal(a_to_b, part)).encode()
  assert len(packet) <= 508


def test_send_a_resource_over_a_link():
  async def main():
    hub = __import__('cosiechat.roads.memory', fromlist=['MemoryHub']).MemoryHub()
    a, b = await pair(hub, retry_after=0.2)
    got = []
    b.on_resource(got.append)
    data = os.urandom(50_000)
    assert await a.send_resource(b.address, data, meta={'name': 'photo.jpg'}, timeout=20)
    assert got[0].data == data and got[0].meta == {'name': 'photo.jpg'}
    assert got[0].peer == a.address
    await a.stop()
    await b.stop()

  run(main())


def test_resource_over_a_lossy_lora_road():
  async def main():
    from cosiechat.roads.memory import MemoryHub

    random.seed(5)
    hub = MemoryHub()
    a, b = await pair(hub, mtu=508, retry_after=0.2)
    got = []
    b.on_resource(got.append)
    await a.open_link(b.address, timeout=10)
    hub.loss = 0.1
    data = os.urandom(20_000)
    assert await a.send_resource(b.address, data, timeout=30)
    assert got and got[0].data == data
    await a.stop()
    await b.stop()

  run(main())


def test_receiver_refuses_what_is_too_big():
  async def main():
    from cosiechat.roads.memory import MemoryHub

    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.1, max_resource=10_000)
    assert not await a.send_resource(b.address, os.urandom(20_000), timeout=1.5)
    await a.stop()
    await b.stop()

  run(main())


def test_lost_done_is_answered_again():
  async def main():
    from cosiechat.roads.memory import MemoryHub

    hub = MemoryHub()
    a, b = await pair(hub, retry_after=0.2)
    got = []
    b.on_resource(got.append)
    real = b._resource_send
    dropped = []

    def drop_first_done(keys, field_id, value):
      if field_id == R.R_DONE and not dropped:
        dropped.append(value)
        return
      real(keys, field_id, value)

    b._resource_send = drop_first_done
    await a.open_link(b.address)
    data = os.urandom(3000)
    assert await a.send_resource(b.address, data, timeout=10)
    assert dropped and len(got) == 1  # delivered once, and a learned it despite the lost done
    await a.stop()
    await b.stop()

  run(main())
