"""Address text with a checksum, and contact cards."""

import pytest
from test_node import inbox, make, run

from cosechat import contact as C
from cosechat.identity import Identity
from cosechat.keys import CoseError
from cosechat.roads.memory import MemoryHub


def test_address_text_roundtrip_and_checksum():
  a = Identity.generate('prequantum').address
  t = C.address_text(a)
  assert len(t.replace('-', '')) == 30 and t == t.lower()
  assert C.parse_address(t) == a
  assert C.parse_address(t.upper().replace('-', ' ')) == a  # forgiving about case/spaces
  assert C.parse_address(a.hex()) == a  # plain hex still works
  typo = t[:3] + ('a' if t[3] != 'a' else 'b') + t[4:]
  with pytest.raises(CoseError, match='checksum'):
    C.parse_address(typo)


def test_card_uri_roundtrip():
  card = b'\x00\x01\xfe\xff' * 50
  uri = C.card_uri(card)
  assert uri.startswith('cosechat:') and '=' not in uri
  assert C.card_from_uri(uri) == card
  with pytest.raises(CoseError):
    C.card_from_uri('https://example.com')


def test_message_someone_from_their_card_without_hearing_their_announce():
  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    b._handle_path_request = lambda lane, p: None  # b stays silent: only the card helps
    async with a, b:
      a.add_contact(C.card_from_uri(C.card_uri(b.contact_card())))
      assert a.peer_ratchet(b.address) is not None  # no announce was heard
      m = await a.send(b.address, 'from your card', timeout=2)
      assert await a.delivered(m, timeout=5)
    assert box[0].content == 'from your card'

  run(main())


def test_card_respects_pinning_and_policy():
  async def main():
    hub = MemoryHub()
    a = make(hub)
    pre = make(hub, 'prequantum')
    async with a, pre:
      with pytest.raises(PermissionError, match='quantum'):
        a.add_contact(pre.contact_card())
      b = make(hub)
      async with b:
        a.add_contact(b.contact_card())
        a.identities[b.address] = Identity.generate().public()  # pretend another is pinned
        with pytest.raises(PermissionError, match='pinned'):
          a.add_contact(b.contact_card())

  run(main())


def test_card_sizes():
  async def main():
    hub = MemoryHub()
    pq, pre = make(hub), make(hub, 'prequantum')
    async with pq, pre:
      assert 6000 < len(pq.contact_card()) < 7000
      assert len(pre.contact_card()) < 300

  run(main())
