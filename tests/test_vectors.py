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
