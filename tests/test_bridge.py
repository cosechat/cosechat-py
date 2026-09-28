"""
The LoRa <-> WebSocket bridge, end to end: an emulated RNode on one side and a
real WebSocket room on the other. This is the wiring the examples use
(lora_gateway.py + echo_bot.py), with the serial port swapped for a fake.
"""

import argparse
import sys
from pathlib import Path

from test_node import inbox, run, until
from test_roads import Air as LoraAir
from test_roads import FakeRNode

from cosechat.node import Node
from cosechat.packet import DATA, LINK_DATA, decode
from cosechat.roads.websocket import WebSocketClientRoad, WebSocketServerRoad

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'
sys.path.insert(0, str(EXAMPLES))
import echo_bot  # noqa: E402
import lora_gateway  # noqa: E402
import room  # noqa: E402

JS_EXAMPLES = EXAMPLES.parent.parent / 'cosechat-js' / 'examples'
LORA = dict(freq=868_000_000, bw=125_000, sf=8, cr=5, txp=7)


def gateway_args(tmp_path, air, **kw):
  kw.setdefault('ws', None)
  kw.setdefault('udp', None)
  kw.setdefault('announce_cap', 0.02)
  return argparse.Namespace(
    port=FakeRNode(air), road_key=None, identity=tmp_path / 'gateway', interval=3600.0, **LORA, **kw
  )


def bot_args(tmp_path, air, **kw):
  kw.setdefault('rnode', None)
  kw.setdefault('listen', None)
  kw.setdefault('peer', None)
  kw.setdefault('announce_cap', 0.02)
  return argparse.Namespace(
    road_key=None, identity=tmp_path / 'bot', name='bob', interval=3600.0, **LORA, **kw
  )


def test_room_matches_the_js_examples():
  """All the websocket examples point at the same room as the web page."""
  assert room.ROOM == 'wss://signal.konsumer.workers.dev/ws/cosechat'
  for f in ('web/app.js', 'echo-bot.js'):
    path = JS_EXAMPLES / f
    if path.exists():
      assert f"'{room.ROOM}'" in path.read_text(), f'{f} uses a different room'


def test_gateway_defaults_to_the_room(tmp_path):
  """With no --ws and no --udp, the gateway bridges the shared web room."""
  air = LoraAir()
  node, radio, _ratchets, wss = lora_gateway.build_node(gateway_args(tmp_path, air))
  assert node.transport and node.propagate
  assert [w.url for w in wss] == [room.ROOM]
  assert radio.name.startswith('rnode:')


def test_udp_only_gateway_does_not_join_the_room(tmp_path):
  air = LoraAir()
  _node, _radio, _ratchets, wss = lora_gateway.build_node(gateway_args(tmp_path, air, udp=4242))
  assert wss == []


def test_bot_on_lora_does_not_open_udp(tmp_path):
  air = LoraAir()
  node, _ratchets = echo_bot.build_node(bot_args(tmp_path, air, rnode=[FakeRNode(air)]))
  assert node.lanes
  assert all(lane.road.name.startswith('rnode:') for lane in node.lanes)


def test_bot_needs_frequency_for_rnode(tmp_path):
  air = LoraAir()
  args = bot_args(tmp_path, air, rnode=[FakeRNode(air)])
  args.freq = None
  try:
    echo_bot.build_node(args)
  except SystemExit as e:
    assert '--freq' in str(e)
  else:
    raise AssertionError('expected SystemExit')


def test_browser_to_lora_bot_and_back(tmp_path):
  """alice (WebSocket) -> room -> gateway -> LoRa -> bob (echo) -> back to alice.

  announce_cap=0 turns off the LoRa airtime budget (SPEC 9.0) so announces
  relay at once; that budget is exercised in test_limits, not here.
  """

  async def main():
    air = LoraAir()
    hub_road = WebSocketServerRoad('127.0.0.1', 0)
    hub = Node(transport=True, rebroadcast_delay=0)
    hub.add_road(hub_road)
    async with hub:
      url = f'ws://127.0.0.1:{hub_road.port}'
      gw_node, _radio, _gw_ratchets, wss = lora_gateway.build_node(
        gateway_args(tmp_path, air, ws=[url], announce_cap=0)
      )
      bob_node, _bob_ratchets = echo_bot.build_node(bot_args(tmp_path, air, rnode=[FakeRNode(air)]))
      alice = Node(rebroadcast_delay=0)
      alice_ws = WebSocketClientRoad(url)
      alice.add_road(alice_ws)
      box = inbox(alice)

      async with gw_node, bob_node, alice:
        await wss[0].connected.wait()
        await alice_ws.connected.wait()
        await gw_node.announce()
        await bob_node.announce()
        await alice.announce()
        # a path each way, across the room and the radio
        await until(lambda: alice.path(bob_node.address) is not None)
        await until(lambda: bob_node.path(alice.address) is not None)
        assert bob_node.path(alice.address).via == gw_node.address
        await alice.send(bob_node.address, 'hi bob, from the browser')
        await until(lambda: box)
      assert box[0].content == 'hi bob, from the browser'
      assert box[0].sender == bob_node.address

  run(main())


def test_an_open_link_makes_messages_one_fragment(tmp_path):
  """The chat path for a slow radio: open a link, then each message is one frame.

  Without a link every message is a ~10-fragment sealed packet, which on LoRa is
  ~13 s of air and collides with the peer's own transmissions.
  """

  async def main():
    air = LoraAir()
    hub_road = WebSocketServerRoad('127.0.0.1', 0)
    hub = Node(transport=True, rebroadcast_delay=0)
    hub.add_road(hub_road)
    async with hub:
      url = f'ws://127.0.0.1:{hub_road.port}'
      gw_node, radio, _gw_ratchets, wss = lora_gateway.build_node(
        gateway_args(tmp_path, air, ws=[url], announce_cap=0)
      )
      bob_node, _bob_ratchets = echo_bot.build_node(
        bot_args(tmp_path, air, rnode=[FakeRNode(air)], announce_cap=0)
      )
      alice = Node(rebroadcast_delay=0)
      alice_ws = WebSocketClientRoad(url)
      alice.add_road(alice_ws)
      box = inbox(alice)

      frames = []
      original = radio.send

      async def counted(frame):
        frames.append(frame)
        return await original(frame)

      radio.send = counted
      async with gw_node, bob_node, alice:
        await wss[0].connected.wait()
        await alice_ws.connected.wait()
        await gw_node.announce()
        await bob_node.announce()
        await alice.announce()
        await until(lambda: alice.path(bob_node.address) and bob_node.path(alice.address))

        link = await alice.open_link(bob_node.address, timeout=20)
        # the responder has the link too, so its replies also go over it
        await until(lambda: bob_node.link_to(alice.address) is not None)
        assert bob_node.link_to(alice.address).link_id == link.link_id

        frames.clear()
        for i in range(3):
          await alice.send(bob_node.address, f'over the link {i}')
        await until(lambda: len(box) >= 3)
        assert [m.content for m in box] == [f'over the link {i}' for i in range(3)]

      kinds = [decode(f).type for f in frames]
      # every radio frame is a link record, not a sealed multi-fragment message
      assert kinds.count(LINK_DATA) >= 3
      assert kinds.count(DATA) == 0, f'went out sealed: {kinds}'
      # and at most a couple of frames per message (itself, plus its receipt)
      assert len(frames) <= 2 * 3 + 2, f'{len(frames)} frames for 3 messages: {kinds}'

  run(main())
