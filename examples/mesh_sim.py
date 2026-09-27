"""
A whole mesh in one process, with no network or radio. It shows the three
promises: routing across different roads, routers that cannot read what they
carry, and pre-quantum peers being shut out by default.

  alice ──(LoRa-sized road, 508 B)── gateway ──(LAN road)── relay ──(LAN road)── bob

  uv run examples/mesh_sim.py
"""

import asyncio

from cosiechat import Identity, Node
from cosiechat.roads.memory import MemoryHub


async def main():
  lora, lan1, lan2 = MemoryHub(), MemoryHub(), MemoryHub()

  alice = Node(Identity.generate('pq'), app_data={'name': 'alice'})
  alice.add_road(lora.road('lora', mtu=508))

  gateway = Node(transport=True, app_data={'name': 'gateway'})
  gateway.add_road(lora.road('lora', mtu=508))
  gateway.add_road(lan1.road('lan1', mtu=1200))

  relay = Node(transport=True, propagate=True, app_data={'name': 'relay'})
  relay.add_road(lan1.road('lan1', mtu=1200))
  relay.add_road(lan2.road('lan2', mtu=1200))

  bob = Node(Identity.generate('hybrid'), app_data={'name': 'bob'})
  bob.add_road(lan2.road('lan2', mtu=1200))

  # a `prequantum`-suite node has to opt out of quantum safety, and the rest ignore it
  mallory = Node(Identity.generate('prequantum'), quantum_safe_only=False, app_data={'name': 'old'})
  mallory.add_road(lan2.road('lan2'))

  got = asyncio.Event()

  @bob.on_message
  def inbox(m):
    print(f'bob got {m.content!r} from {m.sender.hex()[:12]} (id {m.id.hex()[:12]})')
    got.set()

  for router in (gateway, relay):
    router.on_message(lambda m, r=router: print(f'!! {r.name} read a message'))

  nodes = [alice, gateway, relay, bob, mallory]
  for n in nodes:
    await n.start()
  for n in nodes:
    await n.announce()
  await asyncio.sleep(1.0)

  path = alice.paths[bob.address]
  print(f'alice -> bob: {path.hops} hops, first handoff to {path.via.hex()[:12]} (gateway)')
  print(f'bob knows mallory: {mallory.address in bob.paths}  (pre-quantum peers are ignored)')

  frames = lora.frames
  await alice.send(bob.address, 'hello across three roads', title='demo')
  await asyncio.wait_for(got.wait(), 5)
  print(f'that message took {lora.frames - frames} frames on the LoRa road (PQ is big)')

  for n in nodes:
    await n.stop()


if __name__ == '__main__':
  asyncio.run(main())
