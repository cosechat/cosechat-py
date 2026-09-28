"""The committed vectors keep verifying (so the wire format cannot drift silently)."""

import json
from pathlib import Path

from cosechat.vectors import check, generate

VECTORS = Path(__file__).parent / 'vectors' / 'vectors.json'


def test_committed_vectors_verify():
  assert check(json.loads(VECTORS.read_text())) == []


def test_fresh_vectors_verify():
  assert check(generate()) == []


def test_checker_notices_corruption():
  v = json.loads(VECTORS.read_text())
  d = bytearray.fromhex(v['messages'][0]['data'])
  d[-2] ^= 1
  v['messages'][0]['data'] = d.hex()
  assert len(check(v)) == 1


def _case(v, name):
  return next(c for c in v['reject'] if c['name'] == name)


def test_reject_vectors_fail_only_because_of_their_rule():
  """Relax just the rule a case tests and it must be accepted: the case is not broken otherwise."""
  from cosechat.vectors import _accepted

  v = json.loads(VECTORS.read_text())
  assert len(v['reject']) >= 20
  assert not any(_accepted(c) for c in v['reject'])
  assert _accepted(
    {**_case(v, 'pre-quantum sender under the default policy'), 'quantum_safe_only': False}
  )
  held = _case(v, 'tampered')['ratchets']
  assert _accepted({**_case(v, 'sealed to a ratchet we do not hold'), 'ratchets': held})
  older = _case(v, 'older sequence')
  assert _accepted({**older, 'previous': None})
  unknown = _case(v, 'unknown sender')
  sealed_ok = _case(v, 'pre-quantum sender under the default policy')
  assert _accepted({**unknown, 'known': sealed_ok['known']})


def test_spec_size_table_matches_the_code():
  from cosechat.sizes import table

  spec = (Path(__file__).parents[1] / 'SPEC.md').read_text()
  inside = spec.split('<!-- sizes -->\n')[1].split('\n<!-- /sizes -->')[0]
  assert inside == table(), 'SPEC.md sizes are stale: paste the output of `cosechat sizes`'


def test_spec_constants_table_matches_the_code():
  from cosechat.constants import table

  spec = (Path(__file__).parents[1] / 'SPEC.md').read_text()
  inside = spec.split('<!-- constants -->\n')[1].split('\n<!-- /constants -->')[0]
  assert inside == table(), 'SPEC.md §16 is stale: paste the output of `cosechat constants`'


def test_every_numeric_node_setting_is_documented():
  import inspect

  from cosechat.constants import NODE_NOTES
  from cosechat.node import Node

  for name, p in inspect.signature(Node.__init__).parameters.items():
    if isinstance(p.default, (bool, int, float)) or name == 'announce_interval':
      assert name in NODE_NOTES, f'Node({name}=...) needs a line in constants.NODE_NOTES'


def test_exact_vectors_are_byte_exact():
  v = json.loads(VECTORS.read_text())
  assert len(v['exact']) >= 10
  case = next(c for c in v['exact'] if c['name'] == 'COSE_Sign1 Ed25519')
  data = bytearray.fromhex(case['expect']['data'])
  data[-1] ^= 1
  case['expect']['data'] = data.hex()
  assert check(v) == ['exact COSE_Sign1 Ed25519: bytes differ']
