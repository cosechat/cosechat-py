"""
cosiechat developer tool.

  cosiechat keygen [--suite pq|hybrid|prequantum] -o FILE   new identity (plain COSE_KeySet)
  cosiechat info FILE                                        describe an identity
  cosiechat vectors [-o FILE]                                write interop test vectors
  cosiechat check FILE                                       verify vectors from any implementation
  cosiechat sizes                                            measured wire sizes (Markdown)
  cosiechat constants                                        every constant and default (Markdown)

Running a node, and how its keys are stored, is up to the application: see
examples/chat.py and examples/storage.py.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from . import cbor
from .identity import SUITES, Identity
from .keys import get_alg


def cmd_keygen(a):
  path = Path(a.output)
  if path.exists() and not a.force:
    raise SystemExit(f'{path} exists (use --force to replace it)')
  ident = Identity.generate(a.suite)
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, 'wb') as f:
    f.write(ident.to_bytes())
  print(ident.address.hex())


def cmd_info(a):
  raw = Path(a.file).read_bytes()
  try:
    obj = cbor.loads(raw)
  except Exception:
    obj = None
  if isinstance(obj, list) and obj and isinstance(obj[0], str):
    raise SystemExit(f'{a.file}: encrypted at rest ({obj[0]}, see examples/storage.py)')
  try:
    ident = Identity.from_bytes(raw)
  except Exception as e:
    raise SystemExit(f'{a.file}: not a plain identity keyset ({e})') from None
  print(f'address       {ident.address.hex()}')
  for k in ident.sign_keys:
    print(f'sign          {k.algorithm.name} ({len(k.pub)} byte public key)')
  print(f'ratchet KEM   {get_alg(ident.kem_alg).name} (announced, not part of the keyset)')
  print(f'keyset        {len(ident.public_bytes)} bytes public')
  print(f'private       {"yes" if ident.has_private else "no"}')
  print(f'quantum-safe  {"yes" if ident.quantum_safe else "no"}')


def cmd_vectors(a):
  from .vectors import generate

  data = json.dumps(generate(), indent=1)
  if a.output:
    Path(a.output).write_text(data)
  else:
    print(data)


def cmd_check(a):
  from .vectors import check

  fails = check(json.loads(Path(a.file).read_text()))
  for f in fails:
    print('FAIL', f)
  print('ok' if not fails else f'{len(fails)} failures')
  sys.exit(1 if fails else 0)


def main(argv=None):
  p = argparse.ArgumentParser(prog='cosiechat', description='cosiechat developer tool')
  sub = p.add_subparsers(dest='cmd', required=True)

  s = sub.add_parser('keygen', help='create an identity file')
  s.add_argument('--suite', choices=SUITES, default='pq')
  s.add_argument('-o', '--output', required=True)
  s.add_argument('--force', action='store_true')
  s.set_defaults(fn=cmd_keygen)

  s = sub.add_parser('info', help='describe an identity file')
  s.add_argument('file')
  s.set_defaults(fn=cmd_info)

  s = sub.add_parser('vectors', help='write interop test vectors')
  s.add_argument('-o', '--output')
  s.set_defaults(fn=cmd_vectors)

  s = sub.add_parser('check', help='verify a test vector file')
  s.add_argument('file')
  s.set_defaults(fn=cmd_check)

  s = sub.add_parser('constants', help='print every constant and default')
  s.set_defaults(fn=lambda a: print(__import__('cosiechat.constants', fromlist=['table']).table()))

  s = sub.add_parser('sizes', help='print measured wire sizes')
  s.set_defaults(fn=lambda a: print(__import__('cosiechat.sizes', fromlist=['table']).table()))

  a = p.parse_args(argv)
  a.fn(a)


if __name__ == '__main__':
  main()
