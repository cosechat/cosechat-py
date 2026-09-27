"""
Flatten tests/vectors/vectors.json into one-line cases for the wolfCOSE checker:

  name op key_hex[,key_hex...] aad_hex|- data_hex expect_hex

ops: sign1, sign (every signer must verify), mac0, enc0, hpke0, enc, mac.
Messages are split into their two COSE layers (envelope, then signature);
layers wolfCOSE has no algorithm for (X-Wing) are listed as skipped.
"""

import hashlib
import json
import sys
from pathlib import Path

from cosiechat import cbor, cose
from cosiechat import keys as K
from cosiechat.identity import Identity

ROOT = Path(__file__).resolve().parents[2]

# what stock wolfCOSE 2.x implements
WOLFCOSE_ALGS = {
  K.ED25519,
  K.EDDSA,
  K.ESP256,
  K.ES256,
  K.ML_DSA_44,
  K.ML_DSA_65,
  K.ML_DSA_87,
  K.HMAC_256_256,
  K.HMAC_384_384,
  K.HMAC_512_512,
  K.A128GCM,
  K.A256GCM,
  K.CHACHA20_POLY1305,
  K.HPKE_0,
  K.HPKE_0_KE,
}

OPS = {
  'verify_sign1': 'sign1',
  'verify_sign': 'sign',
  'verify_mac0': 'mac0',
  'verify_mac': 'mac',
  'decrypt': 'enc',
}


def keyhex(k: K.Key) -> str:
  return cbor.dumps(k.to_cose(private=True)).hex()


def main():
  v = json.loads((ROOT / 'tests' / 'vectors' / 'vectors.json').read_text())
  cases, skipped = [], []

  def add(name, op, keys, data, expect, aad=b''):
    cases.append(f'{name} {op} {",".join(keys)} {aad.hex() or "-"} {data.hex()} {expect.hex()}')

  for n, c in enumerate(v['cose']):
    name = f'cose[{n}]:{c["alg"].replace(" ", "")}'
    data = bytes.fromhex(c['data'])
    alg = cose.decode(data).alg
    if c['op'] == 'decrypt0':
      op = 'hpke0' if isinstance(K.get_alg(alg), K.HpkeAlg) else 'enc0'
    else:
      op = OPS[c['op']]
    keys = c.get('keys') or [c['key']]
    algs = {K.Key.from_cose(cbor.loads(bytes.fromhex(k))).alg for k in keys}
    if op in ('enc', 'mac'):
      algs = {K.get_alg(a).sibling for a in algs} | {alg}
    # wolfCOSE's COSE_Mac has no HPKE recipients (cosiechat only uses Mac0)
    if not algs <= WOLFCOSE_ALGS or op == 'mac':
      skipped.append(name)
      continue
    add(name, op, keys, data, bytes.fromhex(c['expect']), bytes.fromhex(c.get('external_aad', '')))

  ids = {
    (i['suite'], i['name']): Identity.from_bytes(bytes.fromhex(i['private']))
    for i in v['identities']
  }
  rks = {
    (i['suite'], i['name']): [
      K.Key.from_cose(cbor.loads(bytes.fromhex(h))) for h in i.get('ratchets', [])
    ]
    for i in v['identities']
  }
  for n, m in enumerate(v['messages']):
    alice = ids[(m['suite'], m['from'])]
    sealed = bytes.fromhex(m['data'])
    env = cose.decode(sealed)
    for who in m['to']:
      me = ids[(m['suite'], who)]
      name = f'message[{n}]:{m["suite"]}:{m["kind"]}->{who}'
      # the key that opens it: one of the recipient's ratchets, or its long-term KEM key
      opener = cose.decrypt0 if env.kind == 'Encrypt0' else cose.decrypt
      signed = key = None
      for k in [*rks[(m['suite'], who)], me.kem_key]:
        try:
          signed, key = opener(env, k), k
          break
        except K.CoseError:
          pass
      if key.alg in WOLFCOSE_ALGS:
        add(
          name + (':envelope(ratchet)' if key is not me.kem_key else ':envelope'),
          'hpke0' if env.kind == 'Encrypt0' else 'enc',
          [keyhex(key)],
          sealed,
          signed,
        )
      else:
        skipped.append(name + ':envelope')
      body = alice.verify(signed)
      op = 'sign1' if len(alice.sign_keys) == 1 else 'sign'
      add(name + ':signature', op, [keyhex(k) for k in alice.sign_keys], signed, body)

  for n, a in enumerate(v['announces']):
    alice = ids[(a['suite'], a['from'])]
    data = bytes.fromhex(a['data'])
    op = 'sign1' if len(alice.sign_keys) == 1 else 'sign'
    add(
      f'announce[{n}]:{a["suite"]}',
      op,
      [keyhex(k) for k in alice.sign_keys],
      data,
      alice.verify(data),
    )

  for n, lk in enumerate(v.get('links', [])):
    name = f'link[{n}]:{lk["suite"]}'
    request = bytes.fromhex(lk['request'])
    accept = bytes.fromhex(lk['accept'])
    eph = K.Key.from_cose(cbor.loads(bytes.fromhex(lk['initiator_ephemeral'])))
    transcript = hashlib.sha256(request).digest()
    if eph.alg in WOLFCOSE_ALGS:
      part_b = cose.decrypt0(accept[16:], eph, external_aad=transcript)
      add(name + ':accept', 'hpke0', [keyhex(eph)], accept[16:], part_b, transcript)
    else:
      skipped.append(name + ':accept')
    lid = bytes.fromhex(lk['expect']['link_id'])
    for i, lm in enumerate(lk['messages']):
      k = lk['expect']['key_a_to_b' if lm['from'] == 'initiator' else 'key_b_to_a']
      key = K.Key(K.CHACHA20_POLY1305, priv=bytes.fromhex(k))
      data = bytes.fromhex(lm['data'])[16:]
      add(f'{name}:message[{i}]', 'enc0', [keyhex(key)], data, cose.decrypt0(data, key, lid), lid)

  for r in v.get('road_auth', []):
    op = 'mac0' if r['mode'] == 'mac' else 'enc0'
    add(
      f'road_auth:{r["mode"]}', op, [r['key']], bytes.fromhex(r['data']), bytes.fromhex(r['expect'])
    )

  out = sys.stdout
  for c in cases:
    print(c, file=out)
  for s in skipped:
    print(f'skipped (no wolfCOSE algorithm): {s}', file=sys.stderr)


if __name__ == '__main__':
  main()
