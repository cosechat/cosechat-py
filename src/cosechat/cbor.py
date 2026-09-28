"""
CBOR helpers. Everything we emit uses deterministic encoding (RFC 8949 4.2)
so other implementations produce byte-identical output for the same values.
"""

import cbor2

CBORTag = cbor2.CBORTag


def dumps(obj) -> bytes:
  return cbor2.dumps(obj, canonical=True)


def loads(data: bytes):
  return cbor2.loads(data)
