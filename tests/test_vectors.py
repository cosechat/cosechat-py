"""The committed vectors keep verifying (so the wire format cannot drift silently)."""

import json
from pathlib import Path

from cosiechat.vectors import check, generate

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
  from cosiechat.vectors import _accepted

  v = json.loads(VECTORS.read_text())
  assert len(v['reject']) >= 15
  assert not any(_accepted(c) for c in v['reject'])
  assert _accepted(
    {**_case(v, 'pre-quantum sender under the default policy'), 'quantum_safe_only': False}
  )
  assert _accepted({**_case(v, 'sealed to long-term key'), 'require_ratchet': False})
  older = _case(v, 'older sequence')
  assert _accepted({**older, 'previous': None})
  unknown = _case(v, 'unknown sender')
  sealed_ok = _case(v, 'pre-quantum sender under the default policy')
  assert _accepted({**unknown, 'known': sealed_ok['known']})
