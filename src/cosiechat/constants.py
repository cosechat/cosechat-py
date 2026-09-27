"""
Every number an implementation needs, read from the code (SPEC.md §16
embeds the output of `cosiechat constants`; a test keeps them in step).

"protocol" values are part of the wire format: implementations MUST use them.
"node defaults" and "limits" are local policy: implementations MAY choose
others, but these are what the reference does.
"""

import inspect

from . import link, message, node, packet, ratchet, store
from .identity import ADDRESS_SIZE

PROTOCOL = [
  ('protocol version', packet.VERSION, 'first element of every frame'),
  ('address', ADDRESS_SIZE, 'bytes: SHA-256(keyset)[0:16]'),
  ('ratchet id', ratchet.RATCHET_ID_SIZE, 'bytes: SHA-256(ratchet pub)[0:8]'),
  ('link id', link.LINK_ID_SIZE, 'bytes: SHA-256(link request)[0:16]'),
  ('link key part', link.PART_SIZE, 'bytes, each of part_a and part_b'),
  ('fragment id', packet.FRAGMENT_ID_SIZE, 'bytes, random'),
  ('fragment overhead', packet.FRAGMENT_OVERHEAD, 'bytes a sender leaves for the fragment header'),
  ('request tag', packet.REQUEST_TAG_SIZE, 'random bytes in path and keyset requests'),
  ('receipt secret', message.RECEIPT_SECRET_SIZE, 'bytes, random, in message field 6'),
  ('receipt tag', message.RECEIPT_TAG_SIZE, 'bytes of HMAC-SHA-256'),
  ('receipt nonce', packet.RECEIPT_NONCE_SIZE, 'random bytes after the tag'),
  ('NACK indexes', packet.NACK_MAX_INDEXES, 'at most, in one NACK'),
]

LIMITS = [
  ('trial ratchets', message.MAX_TRIAL_RATCHETS, 'newest ratchets tried on a shared COSE_Encrypt'),
  (
    'reassembly timeout',
    packet.REASSEMBLY_TIMEOUT,
    's before an incomplete fragment set is dropped',
  ),
  ('reassembly sets', packet.REASSEMBLY_SETS, 'incomplete fragment sets held'),
  ('reassembly bytes', packet.REASSEMBLY_MAX_BYTES, 'largest packet reassembled'),
  ('completed sets remembered', packet.REASSEMBLY_DONE_CACHE, 'to ignore late resends'),
  ('fragment cache sets', node.FRAGMENT_CACHE_SETS, 'sent fragment sets kept for NACKs'),
  ('fragment cache time', node.FRAGMENT_CACHE_TIME, 's they are kept'),
  (
    'NACK delay',
    f'2 frame-times + {node.NACK_BASE_DELAY} s',
    'stall before asking; doubles per try',
  ),
  ('duplicate filter', node.SEEN_CACHE, 'packet hashes remembered'),
  ('delivered ids', node.DELIVERED_CACHE, 'message ids handed to the app (dedupe)'),
  ('delivery results', node.DELIVERY_RESULTS, 'sent messages whose delivery can be awaited'),
  ('link accepts kept', node.ACCEPT_CACHE, 'to answer a repeated link request'),
  ('messages waiting for a keyset', node.WAITING_PER_SENDER, 'per unknown sender'),
  ('senders waited on', node.WAITING_SENDERS, 'unknown senders at once'),
  ('store per destination', store.MemoryStore().per_dest, 'packets (MemoryStore)'),
  ('store destinations', store.MemoryStore().max_dests, 'destinations (MemoryStore)'),
]

NODE_NOTES = {
  'transport': 'route packets for others (rebroadcast announces, forward via)',
  'propagate': 'also hold packets for unreachable destinations (implies transport)',
  'max_hops': 'packets and announces are not forwarded beyond this',
  'rebroadcast_delay': 's, random jitter before a transport rebroadcast',
  'announce_interval': 's between automatic announces (None: only when asked)',
  'quantum_safe_only': 'ignore / refuse peers that are not quantum-safe',
  'retry_after': 's before the first resend of an unconfirmed message',
  'retry_max': 's, cap on the doubling resend gap',
  'max_attempts': 'sends of a sealed message before giving up',
  'accept_links': 'answer link requests',
  'link_attempts': 'sends on a link before falling back to sealed',
  'nack_attempts': 'NACKs per stalled fragment set',
  'max_links': 'links held (least recently used dropped)',
  'path_ttl': 's a path lives after the announce that set it',
  'announce_cap': 'share of a slow road announces may use',
  'announce_queue_age': 's an announce may wait in the queue',
  'rebroadcast_min_interval': 's between rebroadcasts of one identity',
}


def node_defaults():
  sig = inspect.signature(node.Node.__init__)
  for name, p in sig.parameters.items():
    if name in NODE_NOTES:
      yield name, p.default, NODE_NOTES[name]


def _fmt(v) -> str:
  if isinstance(v, bool) or v is None:
    return f'`{v}`'
  if isinstance(v, float) and v.is_integer():
    v = int(v)
  if isinstance(v, int) and v >= 10000:
    return f'{v:,}'
  return str(v)


def table() -> str:
  out = []
  for title, rows in (
    ('Protocol (MUST)', PROTOCOL),
    ('Node defaults (`Node(...)`, local policy)', list(node_defaults())),
    ('Limits (local policy)', LIMITS),
  ):
    out += [f'**{title}**', '', '| | value | |', '|---|---:|---|']
    out += [f'| {n} | {_fmt(v)} | {note} |' for n, v, note in rows]
    out.append('')
  return '\n'.join(out).rstrip()


def main():
  print(table())


if __name__ == '__main__':
  main()
