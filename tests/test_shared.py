"""Several identities on one device, sharing one road."""

from test_node import inbox, run, until

from cosiechat.node import Node
from cosiechat.roads.memory import MemoryHub
from cosiechat.roads.shared import SharedRoad


def test_two_identities_share_a_road():
  async def main():
    hub = MemoryHub()
    shared = SharedRoad(hub.road('radio'))
    chat, bot = Node(rebroadcast_delay=0.01), Node(rebroadcast_delay=0.01)
    chat.add_road(shared.branch())
    bot.add_road(shared.branch())
    far = Node(rebroadcast_delay=0.01)
    far.add_road(hub.road())
    boxes = {n: inbox(n) for n in (chat, bot, far)}
    async with chat, bot, far:
      for n in (chat, bot, far):
        await n.announce()
      await until(lambda: far.path(chat.address) and far.path(bot.address))
      await until(lambda: chat.path(bot.address) and bot.path(far.address))
      assert await far.delivered(await far.send(chat.address, 'to chat'), timeout=5)
      assert await far.delivered(await far.send(bot.address, 'to bot'), timeout=5)
      assert await chat.delivered(await chat.send(bot.address, 'next door'), timeout=5)
    assert [m.content for m in boxes[chat]] == ['to chat']
    assert sorted(m.content for m in boxes[bot]) == ['next door', 'to bot']
    assert shared.road.online is False  # stopped once the last branch stopped

  run(main())
