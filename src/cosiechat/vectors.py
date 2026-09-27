"""
Generate interop test vectors for other implementations (JS, Arduino/wolfCOSE).

Signatures and HPKE are randomized, so the vectors are "must accept" cases:
another implementation must verify, decrypt and parse each one and get the
expected result. Keys are included in COSE_Key form (hex CBOR).

  cosiechat vectors > vectors.json
"""

import json

from . import cbor, cose
from . import keys as K
from . import link as L
from . import message as M
from . import packet as P
from .identity import SUITES, Identity
from .ratchet import new_ratchet


def _hex(b: bytes) -> str:
  return b.hex()


def _key(k: K.Key) -> str:
  return _hex(cbor.dumps(k.to_cose(private=True)))


def generate() -> dict:
  out = {
    'description': 'cosiechat interop vectors: every entry must verify / decrypt to `expect`',
    'cose': [],
    'identities': [],
    'messages': [],
    'announces': [],
    'packets': [],
  }
  payload = b'cosiechat test payload'
  c = out['cose']

  for alg in [K.ED25519, K.ESP256, K.ML_DSA_44, K.ML_DSA_65, K.ML_DSA_87]:
    k = K.Key.generate(alg, kid=b'signer')
    c.append(
      {
        'op': 'verify_sign1',
        'alg': K.get_alg(alg).name,
        'key': _key(k),
        'data': _hex(cose.sign1(payload, k, external_aad=b'aad')),
        'external_aad': _hex(b'aad'),
        'expect': _hex(payload),
      }
    )

  ks = [K.Key.generate(K.ED25519), K.Key.generate(K.ML_DSA_65)]
  c.append(
    {
      'op': 'verify_sign',
      'alg': 'Ed25519 + ML-DSA-65',
      'keys': [_key(k) for k in ks],
      'data': _hex(cose.sign(payload, ks)),
      'external_aad': '',
      'expect': _hex(payload),
    }
  )

  for alg in [K.HMAC_256_64, K.HMAC_256_256, K.HMAC_384_384, K.HMAC_512_512]:
    k = K.Key.generate(alg)
    c.append(
      {
        'op': 'verify_mac0',
        'alg': K.get_alg(alg).name,
        'key': _key(k),
        'data': _hex(cose.mac0(payload, k)),
        'external_aad': '',
        'expect': _hex(payload),
      }
    )

  for alg in [K.A128GCM, K.A256GCM, K.CHACHA20_POLY1305]:
    k = K.Key.generate(alg)
    c.append(
      {
        'op': 'decrypt0',
        'alg': K.get_alg(alg).name,
        'key': _key(k),
        'data': _hex(cose.encrypt0(payload, k)),
        'external_aad': '',
        'expect': _hex(payload),
      }
    )

  for alg in [K.HPKE_0, K.HPKE_4, K.HPKE_9, K.HPKE_12]:
    k = K.Key.generate(alg)
    c.append(
      {
        'op': 'decrypt0',
        'alg': K.get_alg(alg).name,
        'key': _key(k),
        'data': _hex(cose.encrypt0(payload, k.public())),
        'external_aad': '',
        'expect': _hex(payload),
      }
    )
    rs = [k, K.Key.generate(alg)]
    enc = cose.encrypt(payload, [r.public() for r in rs])
    macd = cose.mac(payload, [r.public() for r in rs])
    for r in rs:
      c.append(
        {
          'op': 'decrypt',
          'alg': f'A256GCM / {K.get_alg(K.get_alg(alg).sibling).name}',
          'key': _key(r),
          'data': _hex(enc),
          'external_aad': '',
          'expect': _hex(payload),
        }
      )
      c.append(
        {
          'op': 'verify_mac',
          'alg': f'HMAC 256/256 / {K.get_alg(K.get_alg(alg).sibling).name}',
          'key': _key(r),
          'data': _hex(macd),
          'external_aad': '',
          'expect': _hex(payload),
        }
      )

  for suite in SUITES:
    alice, bob, carol = (Identity.generate(suite) for _ in range(3))
    ratchets = {}
    for who, i in (('alice', alice), ('bob', bob), ('carol', carol)):
      rk = new_ratchet(i.kem_key.alg)
      ratchets[who] = rk
      out['identities'].append(
        {
          'suite': suite,
          'name': who,
          'private': _hex(i.to_bytes()),
          'public': _hex(i.public_bytes),
          'address': _hex(i.address),
          'ratchets': [_key(rk)],
        }
      )

    def message(
      kind, to, sealed, m, ratchet, title='', fields=None, suite=suite, alice=alice, rs=(bob, carol)
    ):
      return {
        'suite': suite,
        'kind': kind,
        'from': 'alice',
        'to': to,
        'ratchet': ratchet,
        'data': _hex(sealed),
        'expect': {
          'id': _hex(m.id),
          'sender': _hex(alice.address),
          'recipients': [_hex(r.address) for r in rs[: len(to)]],
          'timestamp': m.timestamp,
          'title': title,
          'content': m.content,
          'fields_cbor': _hex(cbor.dumps(fields or {})),
        },
      }

    fields = {1: b'\x00\x01\x02', 'k': 'v'}
    # the normal case: one recipient, sealed to their announced ratchet
    rks = {bob.address: ratchets['bob'].public(), carol.address: ratchets['carol'].public()}
    secret = bytes(range(16))
    sealed, m = M.seal(
      alice,
      [bob.public()],
      'hi bob',
      'one',
      fields,
      timestamp=1700000000000,
      ratchets=rks,
      receipt_secret=secret,
    )
    v = message('Encrypt0', ['bob'], sealed, m, True, 'one', fields)
    # bob answers with this 16-byte tag (in a RECEIPT packet, plus an 8-byte nonce)
    v['expect']['receipt_tags'] = {'bob': _hex(M.receipt_tag(secret, bob.address))}
    out['messages'].append(v)
    # forward_secrecy=False: sealed to the long-term identity key
    sealed, m = M.seal(alice, [bob.public()], 'long-term key', timestamp=1700000000001)
    out['messages'].append(message('Encrypt0', ['bob'], sealed, m, False))
    # extra: one shared COSE_Encrypt for two recipients
    sealed, m = M.seal(
      alice, [bob.public(), carol.public()], 'hi all', timestamp=1700000000002, ratchets=rks
    )
    out['messages'].append(message('Encrypt', ['bob', 'carol'], sealed, m, True))

    ann = M.make_announce(
      alice, {'name': 'alice'}, sequence=1700000000003, ratchet=ratchets['alice']
    )
    out['announces'].append(
      {
        'suite': suite,
        'from': 'alice',
        'data': _hex(ann),
        'expect': {
          'address': _hex(alice.address),
          'sequence': 1700000000003,
          'app_data_cbor': _hex(cbor.dumps({'name': 'alice'})),
          'ratchet_id': _hex(ratchets['alice'].kid),
        },
      }
    )
    pkt = P.Packet(P.ANNOUNCE, 0, alice.address, None, ann)
    out['packets'].append(
      {'suite': suite, 'data': _hex(pkt.encode()), 'hash': _hex(pkt.hash), 'type': 'ANNOUNCE'}
    )

  out['links'] = []
  for suite in ('pq', 'prequantum'):
    a, b = Identity.generate(suite), Identity.generate(suite)
    rb = new_ratchet(b.kem_key.alg)
    pending = L.make_request(a, b.public(), rb.public())
    eph = pending.ephemeral
    _, accept, kb = L.accept_request(
      b, pending.request, {a.address: a.public()}.get, ratchets=[rb], quantum_safe_only=False
    )
    ka = L.finish(pending, accept)
    out['links'].append(
      {
        'suite': suite,
        'initiator': _hex(a.to_bytes()),
        'responder': _hex(b.to_bytes()),
        'responder_ratchets': [_key(rb)],
        # normally deleted right after the accept; here so accept can be checked
        'initiator_ephemeral': _key(eph),
        'request': _hex(pending.request),
        'accept': _hex(accept),
        'expect': {
          'link_id': _hex(ka.link_id),
          'key_a_to_b': _hex(ka.send_key.priv),
          'key_b_to_a': _hex(ka.recv_key.priv),
        },
        'messages': [
          {
            'from': 'initiator',
            'data': _hex(L.seal(ka, L.message_body(b.address, 'hi over the link'))),
            'content': 'hi over the link',
          },
          {
            'from': 'responder',
            'data': _hex(L.seal(kb, L.message_body(a.address, 'and back'))),
            'content': 'and back',
          },
        ],
      }
    )

  frame = P.Packet(P.PATH_REQUEST, 0, b'\x11' * 16, None, b'\x22' * 8).encode()
  out['road_auth'] = [
    {
      'passphrase': 'cosiechat vectors',
      'mode': mode,
      'key': _key(P.RoadAuth.from_passphrase('cosiechat vectors', mode).key),
      'data': _hex(P.RoadAuth.from_passphrase('cosiechat vectors', mode).wrap(frame)),
      'expect': _hex(frame),
    }
    for mode in ('mac', 'encrypt')
  ]
  return out


def _k(h: str) -> K.Key:
  return K.Key.from_cose(cbor.loads(bytes.fromhex(h)))


_OPS = {
  'verify_sign1': lambda v, d, aad: cose.verify_sign1(d, _k(v['key']), aad),
  'verify_sign': lambda v, d, aad: cose.verify_sign(d, [_k(x) for x in v['keys']], aad),
  'verify_mac0': lambda v, d, aad: cose.verify_mac0(d, _k(v['key']), aad),
  'verify_mac': lambda v, d, aad: cose.verify_mac(d, _k(v['key']), aad),
  'decrypt0': lambda v, d, aad: cose.decrypt0(d, _k(v['key']), aad),
  'decrypt': lambda v, d, aad: cose.decrypt(d, _k(v['key']), aad),
}


def check(vectors: dict) -> list[str]:
  """Verify a vector file (ours, or one produced by another implementation). Returns failures."""
  fails = []

  def expect(ok, what):
    if not ok:
      fails.append(what)

  for i, v in enumerate(vectors.get('cose', [])):
    what = f'cose[{i}] {v["op"]} {v.get("alg", "")}'
    try:
      got = _OPS[v['op']](v, bytes.fromhex(v['data']), bytes.fromhex(v.get('external_aad', '')))
      expect(got == bytes.fromhex(v['expect']), what)
    except Exception as e:
      fails.append(f'{what}: {e!r}')

  ids, rks = {}, {}
  for v in vectors.get('identities', []):
    i = Identity.from_bytes(bytes.fromhex(v['private']))
    ids[(v['suite'], v['name'])] = i
    rks[(v['suite'], v['name'])] = [_k(h) for h in v.get('ratchets', [])]
    pub = Identity.from_bytes(bytes.fromhex(v['public']))
    expect(
      pub.address.hex() == v['address'] == i.address.hex(), f'identity {v["suite"]}/{v["name"]}'
    )

  for n, v in enumerate(vectors.get('messages', [])):
    sender = ids[(v['suite'], v['from'])].public()
    for who in v['to']:
      what = f'message[{n}] {v["suite"]} {v["kind"]} -> {who}'
      try:
        m = M.unseal(
          ids[(v['suite'], who)],
          bytes.fromhex(v['data']),
          {sender.address: sender}.get,
          ratchets=rks[(v['suite'], who)],
          require_ratchet=v.get('ratchet', False),
        )
        e = v['expect']
        tags = e.get('receipt_tags', {})
        if who in tags:
          expect(
            m.receipt_secret is not None
            and M.receipt_tag(m.receipt_secret, ids[(v['suite'], who)].address).hex() == tags[who],
            what + ' receipt tag',
          )
        expect(
          (m.ratchet_id is not None) == v.get('ratchet', False)
          and m.id.hex() == e['id']
          and m.sender.hex() == e['sender']
          and [r.hex() for r in m.recipients] == e['recipients']
          and m.timestamp == e['timestamp']
          and m.title == e['title']
          and m.content == e['content']
          and cbor.dumps(m.fields) == bytes.fromhex(e['fields_cbor']),
          what,
        )
      except Exception as e:
        fails.append(f'{what}: {e!r}')

  for n, v in enumerate(vectors.get('announces', [])):
    what = f'announce[{n}] {v["suite"]}'
    try:
      a = M.verify_announce(bytes.fromhex(v['data']), bytes.fromhex(v['expect']['address']))
      expect(
        a.sequence == v['expect']['sequence']
        and (a.ratchet.kid.hex() if a.ratchet else None) == v['expect'].get('ratchet_id')
        and cbor.dumps(a.app_data) == bytes.fromhex(v['expect']['app_data_cbor']),
        what,
      )
    except Exception as e:
      fails.append(f'{what}: {e!r}')

  for n, v in enumerate(vectors.get('packets', [])):
    what = f'packet[{n}] {v["suite"]}'
    try:
      p = P.decode(bytes.fromhex(v['data']))
      expect(p.hash.hex() == v['hash'] and P.TYPES[p.type] == v['type'], what)
    except Exception as e:
      fails.append(f'{what}: {e!r}')

  for n, v in enumerate(vectors.get('links', [])):
    what = f'link[{n}] {v["suite"]}'
    try:
      a = Identity.from_bytes(bytes.fromhex(v['initiator']))
      b = Identity.from_bytes(bytes.fromhex(v['responder']))
      request = bytes.fromhex(v['request'])
      sender, _, part_a = L.read_request(
        b,
        request,
        {a.address: a.public()}.get,
        ratchets=[_k(h) for h in v['responder_ratchets']],
        quantum_safe_only=False,
      )
      pending = L.PendingLink(
        L.link_id(request), b.address, request, _k(v['initiator_ephemeral']), part_a
      )
      ka = L.finish(pending, bytes.fromhex(v['accept']))
      e = v['expect']
      expect(
        sender.address == a.address
        and ka.link_id.hex() == e['link_id']
        and ka.send_key.priv.hex() == e['key_a_to_b']
        and ka.recv_key.priv.hex() == e['key_b_to_a'],
        what + ' keys',
      )
      kb = L.LinkKeys(ka.link_id, a.address, False, ka.recv_key, ka.send_key)
      for i, lm in enumerate(v['messages']):
        keys, me = (kb, b.address) if lm['from'] == 'initiator' else (ka, a.address)
        got, _ = L.read_message(keys, me, L.unseal(keys, bytes.fromhex(lm['data'])))
        expect(got.content == lm['content'], f'{what} message[{i}]')
    except Exception as ex:
      fails.append(f'{what}: {ex!r}')

  for n, v in enumerate(vectors.get('road_auth', [])):
    what = f'road_auth[{n}] {v["mode"]}'
    try:
      auth = P.RoadAuth.from_passphrase(v['passphrase'], v['mode'])
      expect(_key(auth.key) == v['key'], what + ' key derivation')
      expect(auth.unwrap(bytes.fromhex(v['data'])) == bytes.fromhex(v['expect']), what)
    except Exception as e:
      fails.append(f'{what}: {e!r}')
  return fails


def main():
  print(json.dumps(generate(), indent=1))


if __name__ == '__main__':
  main()
