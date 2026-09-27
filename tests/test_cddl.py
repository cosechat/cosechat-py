"""cosiechat.cddl describes what actually goes on the wire (validated with pycddl)."""

import json
from pathlib import Path

import pycddl
import pytest
from test_delivery import pair
from test_node import run

from cosiechat import cbor, cose
from cosiechat import link as L
from cosiechat import message as M
from cosiechat import packet as P
from cosiechat.identity import SUITES, Identity
from cosiechat.ratchet import new_ratchet
from cosiechat.roads.memory import MemoryHub

ROOT = Path(__file__).resolve().parents[1]
SPEC_SOURCE = (ROOT / 'cosiechat.cddl').read_text()
# pycddl 0.6 (cddl-rs) applies a `.cbor` control inside an array to every
# later item too, so it cannot check COSE's protected header in place. We
# loosen that one rule for the tool and check protected headers ourselves
# (check_protected) against the same `header_map` rule.
PROT = 'prot = bstr .size 0 / bstr .cbor header_map'
assert PROT in SPEC_SOURCE
SOURCE = SPEC_SOURCE.replace(PROT, 'prot = bstr')
_schemas = {}

PAYLOAD_RULE = {
  P.ANNOUNCE: 'announce-payload',
  P.DATA: 'data-payload',
  P.PATH_REQUEST: 'path-request-payload',
  P.RECEIPT: 'receipt-payload',
  P.LINK_REQUEST: 'link-request-payload',
  P.LINK_ACCEPT: 'link-accept-payload',
  P.LINK_DATA: 'link-data-payload',
  P.KEYSET_REQUEST: 'keyset-request-payload',
  P.KEYSET: 'keyset-payload',
}


def valid(rule: str, data: bytes):
  if rule not in _schemas:
    _schemas[rule] = pycddl.Schema(f'root = {rule}\n' + SOURCE)
  _schemas[rule].validate_cbor(data)


def check_protected(data: bytes):
  """Every protected header in a COSE object is empty or a serialized header_map."""
  m = cose.decode(data)
  layers = [m.raw_protected] + [lay.raw_protected for lay, _ in m.signers + m.recipients]
  for raw in layers:
    if raw:
      valid('header_map', raw)


def bstr(payload: bytes) -> bytes:
  """Payload rules describe the bstr, so validate the payload wrapped as one."""
  return cbor.dumps(payload)


def test_validator_is_not_a_rubber_stamp():
  with pytest.raises(pycddl.ValidationError):
    valid('packet', cbor.dumps([0, 1, 0, b'short', None, b'']))
  with pytest.raises(pycddl.ValidationError):
    valid('message-body', cbor.dumps({2: 1}))  # no `to`
  with pytest.raises(pycddl.ValidationError):
    valid('header_map', cbor.dumps([1, 2]))  # a protected header must be a map


@pytest.mark.parametrize('suite', SUITES)
def test_keysets_and_announce_bodies(suite):
  i = Identity.generate(suite)
  valid('keyset', i.public_bytes)
  r = new_ratchet(i.kem_alg)
  valid('ratchet-key', cbor.dumps(r.public().to_cose()))
  for full in (True, False):
    signed = M.make_announce(i, r, {'name': 'x'}, full=full)
    valid('signed', signed)
    check_protected(signed)
    valid('announce-body', cose.decode(signed).content)
    valid('packet', P.Packet(P.ANNOUNCE, 0, i.address, None, signed).encode())


def test_message_and_link_bodies():
  a, b = Identity.generate(), Identity.generate()
  rb = new_ratchet(b.kem_alg)
  sealed, m = M.seal(
    a, [b.public()], 'hi', 'title', {1: b'x'}, ratchets={b.address: rb.public()},
    receipt_secret=b'\x00' * 16,
  )  # fmt: skip
  valid('sealed', sealed)
  check_protected(sealed)
  valid('signed', m.signed)
  check_protected(m.signed)
  valid('message-body', cose.decode(m.signed).content)
  pending = L.make_request(a, b.public(), rb.public())
  valid('sealed', pending.request)
  inner = cose.decode(cose.decrypt0(pending.request, rb))
  valid('link-request-body', inner.content)
  _, accept, kb = L.accept_request(b, pending.request, {a.address: a.public()}.get, ratchets=[rb])
  valid('link-accept-payload', bstr(accept))
  valid('COSE_Encrypt0_Tagged', accept[L.LINK_ID_SIZE :])
  body = L.message_body('hi', receipt_secret=b'\x00' * 16)
  valid('link-body', body)
  valid('link-body', L.message_body(close=True))
  valid('link-data-payload', bstr(L.seal(kb, body)))


def test_every_frame_a_live_mesh_sends():
  """Announces, keyset fetch, path requests, messages, receipts, links, fragments, NACKs."""

  async def main():
    hub = MemoryHub()
    frames = []
    a, b = await pair(hub, mtu=255)
    for n in (a, b):
      road = n.lanes[0].road
      real = road.send

      async def spy(frame, real=real):
        frames.append(frame)
        await real(frame)

      road.send = spy
    await a.announce()  # short
    m = await a.send(b.address, 'hello')
    assert await a.delivered(m, timeout=5)
    await a.open_link(b.address)
    m = await a.send(b.address, 'over the link')
    assert await a.delivered(m, timeout=5)
    await a.close_link(b.address)
    a._request_keyset(b.address)
    await a.request_path(b.address, timeout=1, fresh=True)
    a.lanes[0]._sent.clear()
    await a.lanes[0].send_frame(P.nack(b'\x00' * 8, [1, 2]))
    await a.stop()
    await b.stop()
    return frames

  frames = run(main())
  seen = set()
  whole = P.Reassembler()
  for f in frames:
    valid('frame', f)
    item = P.decode(f)
    if isinstance(item, tuple):
      valid('fragment', f)
      seen.add('fragment')
      done = whole.add('x', item)
      if done is None:
        continue
      f, item = done, P.decode(done)  # check the packet it carried as well
    if isinstance(item, P.Packet):
      valid('packet', f)
      valid(PAYLOAD_RULE[item.type], bstr(item.payload))
      seen.add(item.type)
    elif isinstance(item, P.Nack):
      valid('nack', f)
      seen.add('nack')
  assert {P.ANNOUNCE, P.DATA, P.RECEIPT, P.LINK_DATA, 'fragment', 'nack'} <= seen


def test_road_auth_frames():
  frame = P.Packet(P.PATH_REQUEST, 0, b'\x01' * 16, None, b'\x02' * 8).encode()
  for mode, rule in (('mac', 'road-mac'), ('encrypt', 'road-encrypt')):
    wrapped = P.RoadAuth.from_passphrase('pw', mode).wrap(frame)
    valid(rule, wrapped)
    check_protected(wrapped)


def test_vector_packets():
  v = json.loads((ROOT / 'tests' / 'vectors' / 'vectors.json').read_text())
  for p in v['packets']:
    valid('packet', bytes.fromhex(p['data']))


def test_spec_embeds_the_current_cddl():
  spec = (ROOT / 'SPEC.md').read_text()
  inside = spec.split('<!-- cddl -->\n```cddl\n')[1].split('\n```\n<!-- /cddl -->')[0]
  assert inside == SPEC_SOURCE.rstrip('\n'), 'SPEC.md §15 is stale: paste cosiechat.cddl'
