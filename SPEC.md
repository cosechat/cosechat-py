# cosiechat protocol, version 0 (draft)

cosiechat is a Reticulum/LXMF-style mesh messaging protocol rebuilt from
standard parts: **CBOR** (RFC 8949), **COSE** (RFC 9052/9053), **COSE-HPKE**
(draft-ietf-cose-hpke), **ML-DSA** (FIPS 204, draft-ietf-cose-dilithium) and
**X-Wing** (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem).
The Python package in this repo is the reference implementation and test
oracle for the JS and Arduino (wolfCOSE/wolfSSL) implementations.

The protocol has two halves that never touch each other's internals:

```
 ┌─────────────── data library (pure, testable without I/O) ───────────────┐
 │ keys      COSE_Key / algorithm registry                                 │
 │ cose      Sign1 · Sign · Mac0 · Mac · Encrypt0 · Encrypt                │
 │ identity  keyset → address                                              │
 │ message   seal / unseal (sign-then-encrypt), announces                  │
 │ packet    packet, fragment, road auth                                   │
 └──────────────────────────────────────────────────────────────────────────┘
 ┌─────────────── node (routing, road-agnostic) ───────────────────────────┐
 │ paths from announces · forwarding by `via` · path requests · store/fwd  │
 └──────────────────────────────────────────────────────────────────────────┘
 ┌─────────────── roads (move opaque frames, nothing else) ────────────────┐
 │ memory · UDP · WebSocket · RNode (LoRa over USB serial, KISS)           │
 └──────────────────────────────────────────────────────────────────────────┘
```

Key words MUST / SHOULD / MAY are as in RFC 2119.

## 1. Encoding

* Everything is CBOR. Encoders MUST use core deterministic encoding
  (RFC 8949 §4.2.1: shortest-form integers and lengths, definite lengths,
  sorted map keys).
* Receivers MUST NOT re-encode received data to check hashes or signatures;
  they hash and verify the exact bytes received.
* All COSE messages are tagged (16 Encrypt0, 17 Mac0, 18 Sign1, 96 Encrypt,
  97 Mac, 98 Sign).
* An empty protected header is the zero-length byte string `h''`.
* Timestamps are integer milliseconds since the Unix epoch. They are the
  sender's claim, for display. **Implementations MUST NOT accept, reject or
  expire anything by comparing a peer's timestamp with their own clock.**

## 2. Algorithms

| COSE id | name | used for | spec | wolfCOSE today |
|---:|---|---|---|---|
| -19 | Ed25519 | signatures | RFC 9864 | yes |
| -8 | EdDSA (Ed25519 only) | signatures, accepted for interop | RFC 9053 | yes |
| -9 / -7 | ESP256 / ES256 | signatures | RFC 9864 / 9053 | yes |
| -48 / -49 / -50 | ML-DSA-44 / 65 / 87 | signatures | draft-ietf-cose-dilithium | yes |
| 1 / 2 / 3 | A128GCM / A192GCM / A256GCM | content encryption | RFC 9053 | yes |
| 24 | ChaCha20/Poly1305 | content encryption | RFC 9053 | yes |
| 4 | HMAC 256/64 | MAC | RFC 9053 | no (truncate 5) |
| 5 / 6 / 7 | HMAC 256/256, 384/384, 512/512 | MAC | RFC 9053 | yes |
| 35 / 46 | HPKE-0 / HPKE-0-KE (P-256, HKDF-SHA256, AES-128-GCM) | encryption | draft-ietf-cose-hpke | yes (Encrypt0 + Encrypt; not in Mac) |
| 37/47, 39/48, 45/53 | HPKE-1, -2, -7 (P-384, P-521, P-256/AES-256) | encryption | draft-ietf-cose-hpke | no |
| 41/49, 42/50 | HPKE-3, HPKE-4 (X25519) | encryption | draft-ietf-cose-hpke | no |
| 56 / 57 | HPKE-9 / HPKE-9-KE (X-Wing, SHAKE256, AES-256-GCM) | encryption | draft-reddy-cose-hpke-pq-pqt | no (wolfCrypt glue) |
| 62/63, 64/65 | HPKE-12, HPKE-13 (ML-KEM-768 / -1024) | encryption | draft-reddy-cose-hpke-pq-pqt | no |

HPKE ids 56/57 and 62–65 are still *TBD* in their draft; they are the
values the draft suggests and may change before registration.

A KEM key advertised with an HPKE integrated id (e.g. 56) MAY be used with
its key-encryption sibling (57) and vice versa; both use the same KEM.
(wolfCOSE enforces the key's alg, so set the decoded key's alg to the
sibling before key-encryption use; see `interop/wolfcose/check.c`.)

"wolfCOSE today" is stock [wolfCOSE](https://www.wolfssl.com/products/wolfcose/)
2.x ([source](https://github.com/wolfSSL/wolfCOSE)) on wolfSSL, checked by
`interop/wolfcose` (§13). Rows marked "no" need glue code over wolfCrypt,
which already has the primitives (ML-KEM, X25519, SHAKE256, HPKE).

### 2.1 Suites

A suite is just a choice of algorithms for a new identity: its signing keys,
and the KEM of the ratchets it announces. Every message states its own
algorithms, so nodes with different suites talk to each other.

| suite | signing (the keyset) | ratchet KEM |
|---|---|---|
| `pq` (default) | ML-DSA-65 | HPKE-9 (X-Wing) |
| `hybrid` | Ed25519 **and** ML-DSA-65 | HPKE-9 (X-Wing) |
| `prequantum` | Ed25519 | HPKE-0 (P-256) |

Measured wire sizes for every suite are in §14.

`prequantum` is not quantum-safe (§2.2). It exists for airtime-starved LoRa
links and because every algorithm in it is native to wolfCOSE.

### 2.2 Quantum safety

The `pq` (default) and `hybrid` suites are designed to hold up against an
attacker with a large quantum computer, including one who records traffic
today and decrypts it later ("harvest now, decrypt later"):

| part | algorithm | why it holds |
|---|---|---|
| key encapsulation | X-Wing: ML-KEM-768 (FIPS 203, NIST level 3) + X25519 | stays secure if *either* part holds: ML-KEM against quantum, X25519 against a flaw in ML-KEM |
| signatures | ML-DSA-65 (FIPS 204, NIST level 3); `hybrid` adds Ed25519 and requires both | a forger must break ML-DSA |
| forward secrecy | messages are sealed to announced ratchets (§7.1), X-Wing for `pq`/`hybrid` | identities have no encryption key: stealing one opens nothing; deleted ratchets open nothing |
| content / MAC / KDF | AES-256-GCM, HMAC-SHA-256, SHAKE256, SHA-256 | Grover's algorithm only halves symmetric strength, leaving ≥ 128 bits |
| addresses | SHA-256 truncated to 128 bits | forging a keyset for an existing address is a second preimage: about 2⁶⁴ *sequential* quantum SHA-256 evaluations, far beyond reach; nodes also pin addresses (§9) |

An identity is **quantum-safe** when at least one of its signing keys is
ML-DSA; a ratchet is quantum-safe when its KEM is X-Wing or ML-KEM (HPKE-9,
-12, -13). The signing algorithms are part of the keyset, and so of the
address, so nobody can downgrade a quantum-safe identity; its ratchets are
signed by it.

What the suites do *not* protect (see [CAVEATS.md](CAVEATS.md) for the full list):

* **Mixed meshes.** A message is only as strong as its recipient's KEM, and a
  signature only as strong as its sender's keys. A `pq` node sending to a
  `prequantum` identity produces a message a quantum attacker can read later.
  Nodes MUST therefore run a *quantum-safe-only* policy **by default**:
  ignore announces from identities that are not quantum-safe or whose
  ratchet is not, refuse to send to them, and drop messages from them. Accepting pre-quantum peers MUST be an explicit
  opt-out (reference: `Node(quantum_safe_only=False)`,
  `examples/chat.py --allow-prequantum`). A node with a prequantum identity cannot
  start without that opt-out.
* **Road auth** (§8.2) is symmetric (HMAC-SHA-256 / AES-256-GCM), so it holds,
  but a road key from a weak passphrase can be guessed by anyone.
* **Forward secrecy lasts as long as your ratchet deletion policy** (§7.1).
  A thief who takes a node's held ratchets can read messages sealed to them.
* **Maturity.** ML-KEM and ML-DSA are NIST standards. X-Wing and the COSE
  ids for PQ HPKE are still Internet-Drafts, and nothing here has been audited.

## 3. Keys

COSE_Key maps (RFC 9052 §7). `alg` (3) MUST be present. Kinds used:

| kty | used for | public params | private params |
|---|---|---|---|
| 1 OKP | Ed25519 (crv 6), X25519 (crv 4) | -1 crv, -2 x | -4 d |
| 2 EC2 | P-256/384/521 (crv 1/2/3) | -1 crv, -2 x, -3 y | -4 d |
| 7 AKP | ML-DSA, X-Wing, ML-KEM | -1 pub | -2 priv |
| 4 Symmetric | AEAD / HMAC keys | — | -1 k |

AKP private keys are **seeds**:

* ML-DSA: the 32-byte FIPS 204 seed ξ.
* ML-KEM: the 64-byte FIPS 203 seed `d || z`.
* X-Wing: the 32-byte seed `sk`, expanded as in draft-connolly-cfrg-xwing-kem §5.2:
  `e = SHAKE256(sk, 96 bytes)`; ML-KEM-768 keypair from seed `e[0:32] || e[32:64]`;
  X25519 private key `e[64:96]`. The public key is `pk_M (1184) || pk_X (32)` = 1216 bytes.
  (Checked against the draft's test vector in `tests/test_core.py`.)

## 4. Identity and address

An identity is a CBOR array of COSE_Keys (a COSE_KeySet) holding **only its
signing keys**. It has no encryption key: to be reachable it announces a
ratchet (§7.1), which it signs. Keys in the public keyset carry no `kid` and
no private parameters. (The `pq` keyset is 1,963 bytes: one ML-DSA-65 key.)

```
address = SHA-256(public keyset bytes)[0:16]
```

The address is self-certifying: whoever has the keyset can check that it
hashes to the address. Signatures that "speak for" an address put the
address in the **protected** `kid` (4) header, so the sender is part of what
is signed.

An identity with several signing keys (the `hybrid` suite) signs with
COSE_Sign, and a verifier MUST require a valid signature from **every**
signing key in the keyset. An identity with one signing key uses COSE_Sign1.

## 5. COSE constructions

The to-be-signed / to-be-MAC'd / AAD structures are exactly RFC 9052's:

```
Sig_structure  = ["Signature1", body_protected, external_aad, payload]            ; Sign1
Sig_structure  = ["Signature", body_protected, sign_protected, external_aad, payload] ; Sign
MAC_structure  = ["MAC0" / "MAC", protected, external_aad, payload]
Enc_structure  = ["Encrypt0" / "Encrypt", protected, external_aad]
```

ML-DSA signs in pure mode with an empty context string. ECDSA signatures are
the fixed-width `r || s`.

### 5.1 Encrypt0 (one recipient or a shared key)

* **Shared key:** protected `{1: aead alg}`, unprotected `{5: 12-byte IV}`,
  ciphertext = AEAD(k, IV, plaintext, aad = Enc_structure).
* **HPKE integrated:** protected `{1: HPKE-n}`, unprotected `{-4: enc}`,
  ciphertext = HPKE Seal(pkR, info = h'', aad = Enc_structure, plaintext).

### 5.2 Encrypt and Mac (many recipients)

Layer 0 is encrypted (A256GCM by default, fresh random CEK and IV) or MAC'd
(HMAC 256/256 by default, fresh random key). Each recipient is

```
COSE_recipient = [ protected {1: HPKE-n-KE}, unprotected {-4: enc}, ciphertext ]
ciphertext     = HPKE Seal(pkR, info = Recipient_structure, aad = h'', CEK)
Recipient_structure = ["HPKE Recipient", layer-0 alg, recipient protected bytes, h'']
```

**Recipients carry no `kid` by default**, so a message does not name who it
is for. A receiver tries each recipient whose alg matches its KEM (at most
one HPKE Open per matching entry). A `kid` MAY be added when privacy does not
matter; if present, receivers only try entries whose kid matches.

## 6. Messages (the LXMF layer)

A message is **sign, then encrypt**, for **one recipient**. That is the
protocol's main path, as in LXMF.

```
body   = { 1: [recipient address, ...],   ; to (required)
           2: timestamp ms,               ; (required)
           3: title (tstr),               ; omitted when empty
           4: content (any, usually tstr),; omitted when empty
           5: fields (map),               ; omitted when empty (attachments etc.)
           6: receipt secret (bstr .size 16) } ; omitted when no receipt is wanted
signed = identity signature over bstr(body)   ; COSE_Sign1 or COSE_Sign, protected kid = sender address
sealed = COSE_Encrypt0, HPKE integrated, to the recipient's current ratchet (§7.1)
         unprotected kid = ratchet id
message id = SHA-256(signed)
```

Identities have no encryption key, so there is nothing else to seal to: a
peer can only be messaged once its announce (with a ratchet) is known.

What each party can see:

| | router | recipient |
|---|---|---|
| destination address (packet header) | yes | yes |
| ratchet id (Encrypt0 kid) | yes (links only to the destination, already visible) | yes |
| sender address | **no** | yes, in the signed protected header |
| full recipient list | **no** | yes, inside the signature |
| title, content, fields | **no** | yes |

Receivers MUST:

1. open the envelope with the ratchet named by the kid (drop the message if
   there is no kid, or the ratchet is not held any more),
2. read the sender from the protected `kid` of the signature,
3. find the sender's keyset (from announces, the attached identity below, or
   by fetching it by address with KEYSET_REQUEST, §7.2, and trying again),
   check it hashes to that kid, and verify the signature,
4. reject the message unless their own address is in `to`. Because `to` is
   signed, a recipient cannot re-encrypt someone else's signed message to a
   third party and pass it off as addressed to them.

**Attached identity.** A sender MAY put its public keyset in the
*unprotected* header `-65537` of the signature layer. A receiver that does not
know the sender MAY use it after checking it hashes to the signed kid.

**Storage.** Anything that holds `sealed` as-is (a store-and-forward node,
an outbox) holds only ciphertext that needs the recipient's ratchet key. How
an application stores keys and opened messages is outside this protocol (see
`examples/storage.py` for a suggested practice).

### 6.1 Several recipients (extra)

Reticulum/LXMF has no multi-recipient messages. cosiechat keeps two
optional forms, mainly as a demonstration of COSE:

* **Copies (what the reference node does for `send([a, b])`):** sign once,
  then one COSE_Encrypt0 per recipient, each to that recipient's ratchet, each
  sent as its own packet. Every copy has the same message id. Since each
  destination gets its own packet anyway, this is smaller on the wire than a
  shared envelope, and no copy names the other recipients (only the signed
  `to` list, which only recipients can read).
* **Shared COSE_Encrypt:** one ciphertext, one HPKE-KE recipient entry per
  recipient (to their ratchets), and **no kids**, so it does not name its
  recipients. A receiver trial-decrypts with its newest ratchets (the
  reference tries at most 16). Useful when one ciphertext really does reach
  everyone, such as storage or a future broadcast destination.

## 7. Announces

```
body     = { 1: public keyset (bstr)          ; only in a *full* announce (§7.2)
             2: sequence (uint),
             4: app data (any, optional),
             5: ratchet (public COSE_Key),   ; required (§7.1)
             7: services (uint, optional) }  ; bitmask: 1 = propagation node (§9.4)
announce = identity signature over bstr(body)       ; protected kid = address
```

A receiver MUST check that the signed kid equals the packet's `dest`, that
the keyset (from field 1, or the one it holds for that address) hashes to it,
and that the signature verifies with that keyset. App data is
application-defined; the examples send `{"name": ...}`.

The **sequence** MUST grow with every announce of an identity (so every
announce is also unique for duplicate filtering). A
receiver MUST ignore an announce whose sequence is lower than the last one it
accepted for that identity, so a replayed old announce cannot bring back an
old path or ratchet. The sequence only orders an identity's own announces,
and is never compared with the receiver's clock. The reference uses Unix ms
and never goes backwards; a device without a clock can use a persisted counter.

### 7.1 Ratchets

Like Reticulum's ratchets, but required and post-quantum. They are the only
keys messages are ever sealed to.

* A ratchet is an HPKE KEM key (X-Wing for `pq`/`hybrid`). Its public
  COSE_Key in announce field `5` has `kid` = ratchet id = `SHA-256(pub)[0:8]`,
  and no private parameters. Receivers MUST reject an announce whose ratchet
  is not an HPKE key, has a wrong kid, carries private parameters, or (by
  default) is not quantum-safe. The ratchet is inside the signed body, so only
  the identity can announce it.
* A sender MUST seal to the ratchet in the newest announce it accepted from
  the peer. With none, it sends a path request to get an announce, and MUST
  NOT send without one.
* A receiver opens a message with the ratchet named by its kid, if it still
  holds it.

**Lifetime is storage policy, not protocol.** When a node rotates and when it
deletes old ratchet private keys is up to the application and its storage.
Deleting a ratchet is what makes messages sealed to it unrecoverable, so it
sets the forward-secrecy window. Rules that do not depend on anyone's clock:

* announce the new ratchet whenever you rotate (the reference
  `Node.rotate_ratchet()` does);
* keep old ratchets long enough for messages still in flight, and for
  store-and-forward delays you want to allow;
* a message sealed to a ratchet you no longer hold simply fails to open.

A ratchet that is never rotated is simply a long-term key (no forward
secrecy). The reference library keeps ratchets in memory by default and never
rotates or deletes them by itself, so by default forward secrecy holds across
restarts. `examples/storage.py` shows one suggested policy: rotate every 30
minutes and delete after 10 days by the local clock, in files that can be
passphrase-encrypted at rest.

### 7.2 Full and short announces

A **full** announce carries the keyset (field 1); a **short** one does not,
which saves the size of the keyset (1,963 bytes for `pq`). A node sends a full
announce the first time after it starts and when it answers a path request
for itself; its later announces are short.

A receiver that holds the keyset for the address (pinned from an earlier
full announce or fetched) verifies a short announce with it. One that does
not MUST NOT accept it; it MAY fetch the keyset and then retry:

```
KEYSET_REQUEST  dest = address, payload = 8 random bytes    ; broadcast like a path request
KEYSET          dest = address, payload = public keyset      ; answer on the road the request came in on
```

Any node that holds the keyset MAY answer (the identity itself, or anyone who
learned it): it proves itself, since it must hash to `dest`. A receiver MUST
check that, and MUST ignore a keyset for an address pinned to another one.
A transport node without the keyset forwards the request (`hops + 1`) and
passes the answer back to the roads it forwarded from. Nodes only take
keysets they asked for.

## 8. Packets

```
packet = [ version, type, hops, dest, via, payload ]
  version uint, 0 for this draft
  type    0 ANNOUNCE | 1 DATA | 2 PATH_REQUEST | 4 RECEIPT
          (3 is a fragment and 10 a fragment NACK, §8.1: frames, not packets)
          | 5 LINK_REQUEST | 6 LINK_ACCEPT | 7 LINK_DATA
          | 8 KEYSET_REQUEST | 9 KEYSET
  hops    uint, hops travelled so far (originator sends 0)
  dest    bstr .size 16
  via     bstr .size 16 / null   the transport node that should forward it
  payload bstr   announce | sealed message | 8-byte random tag (path request)
                 | receipt tag (16) || random nonce (8)
                 | link request | link accept | link message (§9.2)
                 | 8-byte random tag (keyset request) | keyset (§7.2)

packet hash = SHA-256(CBOR [version, type, dest, payload])   ; hops and via excluded
```

Receivers MUST drop any frame whose version they do not implement. Every
frame, including fragments, starts with the version, so an incompatible
change (for example new COSE algorithm ids once the PQ HPKE drafts are
registered) bumps it and old and new nodes ignore each other cleanly.

### 8.1 Fragments

A road has an MTU. When an encoded packet (plus road-auth overhead) is larger,
it is sent as fragments:

```
fragment = [ version, 3, id (bstr .size 8, random), index, count, chunk (bstr) ]
```

Receivers reassemble per road and fragment id, in any order, and drop
incomplete sets after a timeout (reference: 60 s). Senders size chunks as
`mtu - road auth overhead - 21`.

**Resume.** A lost fragment should not cost the whole packet on a slow road:

```
nack = [ version, 10, id (the fragment id), [missing index, ...] ]
```

* A sender keeps the fragments of what it sent for a while (reference: the
  last 32 sets, for 60 s).
* A receiver whose incomplete set gets no new fragment for about two
  frame-times (`2 * mtu * 8 / bitrate + 0.2 s`; 0.2 s on fast roads) sends a
  NACK on that road listing the missing indexes, and asks again with growing
  gaps, a bounded number of times (reference: 3).
* A sender that holds that fragment id resends exactly the listed fragments,
  once each; anyone else ignores the NACK. Fragmenting is per hop, so NACKs
  never leave the road.
* A receiver ignores fragments of a set it already completed.

If every fragment is lost the receiver knows nothing; whole-message resends
(§9.1) cover that.

### 8.2 Road auth

A road MAY have a shared road key (like Reticulum's IFAC). Then every frame
(packet or fragment) is wrapped:

* mode `mac`: COSE_Mac0, HMAC 256/256. Outsiders can read headers but cannot inject.
* mode `encrypt`: COSE_Encrypt0, A256GCM. Outsiders cannot even see addresses.

Frames that fail are dropped silently. Keys from a passphrase:
`HKDF-SHA256(ikm = utf8(passphrase), salt = "cosiechat road key", info = "mac" | "encrypt")`,
32 bytes.

## 9. Routing (node behaviour)

Every node keeps a duplicate filter of packet hashes (it adds its own sends
too) and a path table `dest → (road, via, hops, announce sequence, expiry)`.

* **Pinning:** once a node holds a keyset for an address, it MUST reject
  announces and keysets carrying a different keyset for that address.
* **Announce received** (and valid, and not older than the one on file):
  store the keyset and ratchet, set `path = (arrival road, packet.via, packet.hops + 1)`.
  A short announce from an unknown identity waits for its keyset (§7.2).
* **Path expiry:** a path is forgotten `path_ttl` after the announce that set
  it, on the node's own clock (the reference uses a week, like Reticulum).
  Any valid announce refreshes it. With no path, a sender asks with a
  PATH_REQUEST.
* **Fewer hops win:** a byte-identical copy of an announce already accepted
  (so it need not be verified again) replaces the path if it came over fewer
  hops, or if the node is waiting on a path request for that destination (a
  transport answers one with the announce it cached, which the duplicate
  filter would otherwise drop).
* **Dead paths:** when a message has gone unanswered twice, the sender sends
  a fresh PATH_REQUEST while it keeps retrying; when a delivery gives up, the
  path is forgotten. A receiver that gets a repeat of a message it already
  has knows its receipt was lost, so it also asks for a fresh path back to
  the sender (the way back can die with the same transport).
  A *transport* node rebroadcasts it on all its roads with `hops + 1` and
  `via = own address`, after a small random delay, if `hops + 1 < max_hops` (16).
* **Sending DATA:** seal to the destination's current ratchet (§7.1), then use the path if there is one: `via = path.via` (null when
  the destination is a direct neighbour), send on `path.road`. Without a path,
  send a PATH_REQUEST and wait; if still none, send with `via = null` on all
  roads (reaches neighbours and propagation nodes).
* **DATA received**, not for us, at a transport node: forward if `via` is our
  address: `hops + 1`, `via = our path.via`, send on our path's road.
  A propagation node also takes `via = null` DATA; with no path it holds the
  sealed payload and forwards it when the destination announces. Where it
  holds it, how much, and for how long is local storage policy.
* **RECEIPT and LINK_*** packets are routed exactly like DATA (including by
  propagation nodes).
* **PATH_REQUEST for dest:** the destination sends a full announce. A transport node with
  a path replies on the arrival road with the cached announce
  (`hops = path.hops`, `via = own address`); without one it rebroadcasts the
  request with `hops + 1`.

### 9.0 Announce flood control

Announces are big (a full `pq` announce is 6,594 bytes, a short one 4,627) and flood the mesh, so nodes MUST limit them on slow roads. The
reference, following Reticulum:

* **Airtime budget.** On a road with a known bitrate, announces (own,
  rebroadcast and path responses) may use at most 2% of it: after sending an
  announce of S bytes, the next waits `S * 8 / (bitrate * 0.02)` seconds.
  Roads without a bitrate (UDP, WebSocket) are not budgeted.
* **Queue.** Waiting announces go out fewest-hops first. Only the newest
  announce per destination is kept, and one that waited over an hour is dropped.
* **Per-identity limit.** A transport node rebroadcasts any one identity's
  announces at most once a minute.
* **Cheap checks first.** Before verifying an announce's signature, drop it
  if its kid is not `dest`, if an included keyset does not hash to `dest` or
  `dest` is pinned to another keyset, or (by default) if the identity or its
  ratchet is not quantum-safe.

* **Ingress limits.** Work that costs CPU or airtime is rate-limited per
  road with token buckets, applied after the cheap checks: announce
  signature checks, link requests, messages for us, and path/keyset
  requests (reference numbers in §16).
* **Bounded state.** Peers (keyset, announce, path, ratchet) are capped and
  the least recently heard is forgotten; queues and per-address timers are
  capped too.

All of this runs on the node's own clock and is local policy: nodes MAY use
other numbers. The RNode bitrate is `sf * ((4 / cr) / (2^sf / (bw / 1000))) * 1000`.
Within a 2% budget on one 125 kHz LoRa channel, shared by every node on it:

| | SF7 (5,469 bit/s) | SF8 (3,125 bit/s) | SF12 (293 bit/s) |
|---|---:|---:|---:|
| full `pq` announce | one per 8 min | one per 14 min | one per 2.5 h |
| short `pq` announce | one per 5.6 min | one per 9.9 min | one per 1.8 h |

So announce rarely, like Reticulum: paths last a week, and a sender that
needs a path asks for one. The examples announce every 30 minutes (every
hour on the LoRa gateway).

### 9.1 Delivery receipts and retransmission

A sender that wants confirmation puts a fresh random 16-byte **receipt
secret** in the message body (field 6). A recipient that opened and verified
the message MUST answer with a RECEIPT packet to the sender's address:

```
receipt tag = HMAC-SHA-256(key = secret, "cosiechat receipt" || recipient address)[0:16]
payload     = receipt tag || 8 random bytes   ; the nonce gives every receipt a new packet hash
```

Only someone who decrypted the message knows the secret, so the tag proves
delivery at 24 bytes, with no signature. The recipient MUST send a receipt
every time it gets the message, even a repeat (its earlier receipt may have
been lost). It MUST hand each message id to the application only once.

Until the receipt arrives, the sender resends: the **same signed message** in
a **fresh envelope** (new HPKE encapsulation, to the peer's newest ratchet).
The message id stays the same, while the new packet hash gets past duplicate
filters. Retry timing is local policy. The reference retries after 30 s,
doubling up to 10 minutes, for 4 sends in all, using only its own event-loop
clock.

In a message with several recipients, every recipient knows the secret, so
recipients could forge each other's receipts. That is acceptable for this
extra (§6.1).

### 9.2 Links (sessions)

A sealed PQ message costs about 4.5 KB of fixed overhead: a 3.3 KB ML-DSA
signature and a 1.1 KB X-Wing encapsulation. A **link** pays for one PQ
handshake, after which each message is a symmetric COSE_Encrypt0 (about
140 bytes on the wire for a short text with a receipt). Like Reticulum's Links.

```
request  (LINK_REQUEST, initiator A -> B):
  COSE_Encrypt0 to B's ratchet (kid = ratchet id), exactly like a message envelope, of
    A's signature over CBOR { 1: A's ephemeral KEM public COSE_Key (same KEM as A's identity),
                              2: part_a (bstr .size 32, random),
                              3: B's address }

link id  = SHA-256(request)[0:16]

accept   (LINK_ACCEPT, B -> A):
  link id || COSE_Encrypt0, HPKE to A's ephemeral key, of CBOR { 1: part_b (bstr .size 32, random) }
             external_aad = SHA-256(request)

keys     = HKDF-SHA-256(ikm = part_a || part_b, salt = link id, info = "cosiechat link", L = 64)
A->B key = keys[0:32], B->A key = keys[32:64]      (ChaCha20/Poly1305, alg 24)

message  (LINK_DATA, either way):
  link id || COSE_Encrypt0(direction key, random 12-byte IV, external_aad = link id) of
    the message body (§6), with 7: true meaning "closing this link"
link message id = SHA-256(link id || body)
```

* A is authenticated by its signature, which also binds its ephemeral key and
  B's address. B MUST reject a request that is not for B, is from an unknown
  identity, carries a private key, or (by default) uses an ephemeral KEM that
  is not quantum-safe.
* B is authenticated without a signature: A's ephemeral key travels only
  inside the request encrypted to B, and the accept is bound to that exact
  request.
* **Forward secrecy per link:** the initiator MUST delete its ephemeral
  private key once the accept is processed. The keys need part_b, which only
  that deleted key can recover, so recorded link traffic stays sealed even if
  both identities and all ratchets are later stolen. Link keys live only as
  long as the link (in memory in the reference).
* Link messages are authenticated by a key only A and B hold, but not signed:
  a recipient cannot prove to a third party who wrote them.
* The initiator retries with a **new** request (so a new link id) if no accept
  arrives. A responder that sees the same request again MUST resend the same
  accept (its first may have been lost).
* Receipts (§9.1) work unchanged inside links. Resends re-encrypt the same
  body with a new IV.
* Once a link to a peer exists, the reference `send()` uses it in both
  directions. `close_link()` sends the close flag and forgets the keys.
* **A dead link is dropped.** A peer that restarted has lost its link keys
  and silently ignores the link id; it cannot say so, because a link message
  does not name its sender. So a sender that gets no receipt after a few link
  attempts (reference: 3) MUST drop the link and send the content as a sealed
  message instead. And a node that receives a sealed one-to-one message from
  a peer it holds a link with drops that link: the peer would have used it.
* Nodes bound how many links they hold (reference: 256, least recently used
  goes first).

### 9.3 Resources (large transfers)

Anything bigger than a message (files, images) goes as a **resource** over a
link, like Reticulum's Resources. It is split into parts that each fit one
LoRa frame (reference: 320 data bytes, a 426-byte packet), and the receiver
pulls them, so it sets the pace and repairs losses. All of it is link
messages, so it is encrypted and authenticated by the link keys:

```
advertise  link body {8: {1: id, 2: size, 3: part count, 4: SHA-256(data), ? 5: meta}}
request    link body {9: [id, [part index, ...]]}
part       link body {10: [id, index, bytes]}
done       link body {11: id}
id = SHA-256(data)[0:16]
```

* The sender advertises, and again whenever the receiver has been silent
  for a while (backing off).
* The receiver MUST refuse (ignore) an advertisement over its size limit
  (reference: 16 MiB) or whose id is not the start of its hash. Otherwise it
  requests the first window of missing parts (reference: 8). When a
  window is in it asks for the next; after a stall (about two windows of
  frame time) it asks again for what is missing, a bounded number of times.
* When it has every part it checks the size and the SHA-256, sends `done`,
  and hands the data over. A repeated advertisement of a resource it already
  finished is answered with `done` again.
* The sender answers a request with those parts only (at most two windows).

### 9.4 Propagation nodes

Like LXMF's propagation nodes: a node that holds messages for peers that are
offline. It says so in its announce (field 7, services bit `1`).

```
deposit   link body {15: [recipient, packet type, payload], ? 6: deposit receipt secret}
fetch     link body {12: true}
item      link body {13: [index, packet type, payload]}
end       link body {14: item count}
ack       link body {16: item count}
```

* **Deposit.** A sender with a link to a propagation node hands it the
  recipient's envelope, already sealed to the recipient's ratchet (so the
  node holds only ciphertext). The node stores it and confirms with a RECEIPT
  for `receipt_tag(deposit secret, its own address)`. The deposit secret is
  not the message's, so the node cannot fake the recipient's receipt. The
  reference deposits when asked (`send(..., propagate=True)`), and
  automatically when direct delivery gives up (`auto_propagate`).
* **Fetch.** A recipient links to the node (the link authenticates it; it
  does not have to announce) and asks. The node hands over a batch of what
  it holds for that address (reference: up to 64) and an `end` with the
  count; it keeps the batch until an `ack` with that count, and answers a
  repeated fetch with the same batch, so nothing is lost in transit and
  nobody else can drain a mailbox. The recipient handles each item as if it
  had just arrived, so receipts go back to the senders end to end.
* A propagation node also forwards what it holds when the recipient
  announces (§9).
* To open what it fetches, a recipient needs the ratchets the messages were
  sealed to: keeping ratchets across restarts is storage policy (§7.1).

## 10. Roads

A road is a broadcast medium that moves opaque frames and declares an MTU.

| road | framing | MTU |
|---|---|---:|
| UDP | one frame per datagram; broadcast by default (port 4242) or unicast peers | 1200 |
| WebSocket | one frame per binary message; server road = all clients share one medium | 1 MiB |
| RNode | RNode KISS host protocol over serial (115200 8N1) | 508 |

### 10.1 RNode

KISS framing: `FEND cmd data FEND`, with `FEND→FESC TFEND` and
`FESC→FESC TFESC` inside. Startup, as in Reticulum's RNodeInterface:

1. Send `DETECT(0x73)`, `FW_VERSION`, `PLATFORM`, `MCU` queries; expect `DETECT 0x46` and firmware ≥ 1.52.
2. Send `FREQUENCY` (u32 Hz), `BANDWIDTH` (u32 Hz), `TXPOWER` (dBm), `SF`, `CR`,
   optional airtime locks `ST_ALOCK`/`LT_ALOCK` (u16, percent × 100), then `RADIO_STATE ON`.
3. Wait until the device echoes every setting back and reports the radio on.

Data is `CMD_DATA (0x00)` frames of ≤ 508 bytes. `STAT_RSSI` (value − 157 dBm)
and `STAT_SNR` (signed, × 0.25 dB) precede received frames. `READY (0x0F)`
drives optional flow control. `LEAVE (0x0A) 0xFF` on shutdown.

## 11. Differences from Reticulum / LXMF

| | Reticulum / LXMF | cosiechat |
|---|---|---|
| identity | X25519 + Ed25519, 64 raw bytes | COSE_KeySet of signing keys only, PQ by default |
| address | SHA-256(name hash ‖ identity hash)[0:16] | SHA-256(keyset)[0:16] (no app names/aspects yet) |
| encryption | to the identity's X25519 key, or its ratchet | always to an announced ratchet, COSE-HPKE (X-Wing) |
| message | msgpack, fixed byte offsets | CBOR + COSE, self-describing |
| multi-recipient | none | extra: signed once, per-recipient copies (or one shared COSE_Encrypt) |
| sender | inside encrypted payload | protected `kid` of the signature, inside encryption |
| ratchets | X25519, opt-in, rotation and retention built in (30 min, 512 kept) | X-Wing (PQ), required, rotation and retention left to storage |
| announces | keyset in every announce | keyset only on first contact and in path-request answers |
| links | X25519 + Ed25519 handshake | X-Wing handshake, one ML-DSA signature, per-link forward secrecy |
| delivery proofs | signed proofs | 24-byte HMAC receipts (§9.1) |
| resources, stamps | yes | not yet (see below) |

## 12. Not yet specified

Link keepalive and idle timeout, fragment-level resume, propagation-node sync,
stamps/proof-of-work, resource transfer, named destinations (app name +
aspects), path expiry policy.

## 13. Test vectors

`tests/vectors/vectors.json` (regenerate with `cosiechat vectors`) holds:
keys and COSE objects for every algorithm; identities with their ratchets;
sealed messages (to a ratchet, and a shared multi-recipient Encrypt) with
receipt tags; full and short announces; link handshakes with their derived keys and messages;
packets; and road-auth frames. Signatures and HPKE are randomized, so these
are "must accept" cases.

`reject` holds cases an implementation MUST refuse, each naming the rule it
tests: tampering, forwarding to a third party, unknown sender, a ratchet we do
not hold, a signature kid naming someone else, a pre-quantum sender under the
default policy; announces that are tampered, for another address, older,
short with the wrong or no keyset, without a ratchet, or with a bad ratchet;
malformed frames; a
link request for someone else; a link accept for another request; and a frame
under the wrong road key.

`exact` holds byte-exact cases: fixed inputs and deterministic algorithms
(Ed25519, HMAC, AEAD with a given IV, CBOR, SHA-256, HKDF), for debugging an
encoder byte by byte: identity keyset and address, ratchet COSE_Key and id,
Sign1, Mac0, Encrypt0, full and short announces with packet bytes and hash,
a signed message layer with its id and receipt tag, fragment splits, a NACK,
link key derivation, and a road-auth frame. Keys are given as private bytes.

Another implementation should (1) accept every vector in that file, refusing
every `reject` case and reproducing every `exact` case, and (2) emit a file in
the same format that `cosiechat check FILE` accepts.

`interop/live.py` is the behavioural check: it drives an echo bot written in
any implementation over UDP or WebSocket through path requests, sealed
messages and receipts, ratchet rotation, links, resources and first contact
with an unknown sender (the bot must fetch the keyset). `examples/echo_bot.py`
is the reference bot and passes all six checks.

`interop/wolfcose` runs the vectors through stock wolfCOSE + wolfSSL (the
Arduino stack): `make test WOLFSSL_PREFIX=… WOLFCOSE_DIR=…`. Today it accepts
all 40 cases in its scope. That covers Ed25519, ESP256 and ML-DSA-44/65/87
Sign1; hybrid COSE_Sign; HMAC and AEAD Encrypt0; HPKE-0 Encrypt0 and
COSE_Encrypt; every message signature layer; complete `prequantum` messages;
every full and short announce; link messages and the `prequantum` link
accept; and road auth. It skips what wolfCOSE lacks: X-Wing/ML-KEM HPKE,
HPKE-4, HMAC 256/64, and COSE_Mac with HPKE recipients.

## 14. Sizes

Measured from the reference implementation (a test fails if this table and
the code disagree):

<!-- sizes -->
| | `pq` | `hybrid` | `prequantum` |
|---|---:|---:|---:|
| keyset | 1,963 B | 2,005 B | 43 B |
| full announce | 6,594 B (14 frames) | 6,714 B (14 frames) | 276 B |
| short announce | 4,627 B (10 frames) | 4,705 B (10 frames) | 230 B |
| message | 4,595 B (10 frames) | 4,673 B (10 frames) | 291 B |
| receipt | 48 B | 48 B | 48 B |
| link request | 5,808 B (12 frames) | 5,886 B (13 frames) | 355 B |
| link accept | 1,227 B (3 frames) | 1,227 B (3 frames) | 170 B |
| link message | 130 B | 130 B | 130 B |
| resource part | 426 B | 426 B | 426 B |

Whole packets without road auth; "frames" = RNode frames of 508 bytes after fragmentation. Messages carry the 19-character text "hello, how are you?" and a receipt secret. Generated by `cosiechat sizes`.
<!-- /sizes -->

## 15. CDDL

The whole wire format as CDDL (RFC 8610). This is `cosiechat.cddl`, which
`tests/test_cddl.py` validates against real encodings, including every frame
of a live mesh (a test fails if this copy and the file differ).

<!-- cddl -->
```cddl
; cosiechat wire format, protocol version 0 (draft). CDDL: RFC 8610.
; Checked against real encodings by tests/test_cddl.py.
; Everything is deterministically encoded CBOR (RFC 8949 4.2.1).

; ---------------------------------------------------------------------------
; frames: what one road send carries

frame = packet / fragment / nack / road-mac / road-encrypt

version = 0
address = bstr .size 16

packet = [
  version: version,
  type: packet-type,
  hops: uint,               ; hops travelled so far; the originator sends 0
  dest: address,
  via: address / null,      ; the transport node that should forward it
  payload: bstr,            ; see "payloads" below, by type
]

packet-type = 0 / 1 / 2 / 4 / 5 / 6 / 7 / 8 / 9
; 0 announce, 1 data, 2 path request, 4 receipt, 5 link request, 6 link accept,
; 7 link data, 8 keyset request, 9 keyset (3 and 10 are fragment and nack frames)

fragment = [version: version, 3, id: fragment-id, index: uint, count: uint, chunk: bstr]
nack = [version: version, 10, id: fragment-id, missing: [* uint]]
fragment-id = bstr .size 8

; with a road key every frame is wrapped (payload / plaintext = one frame above)
road-mac = COSE_Mac0_Tagged                ; HMAC 256/256
road-encrypt = COSE_Encrypt0_Tagged        ; A256GCM

; ---------------------------------------------------------------------------
; payloads, by packet type (each is the packet's payload bstr)

announce-payload = bstr .cbor signed      ; its payload: bstr .cbor announce-body
data-payload = bstr .cbor sealed
path-request-payload = bstr .size 8        ; random tag
receipt-payload = bstr .size 24            ; receipt tag (16) || random nonce (8)
link-request-payload = bstr .cbor sealed  ; a signed link-request-body inside
link-accept-payload = bstr                 ; link id (16) || COSE_Encrypt0_Tagged of link-accept-body
link-data-payload = bstr                   ; link id (16) || COSE_Encrypt0_Tagged of link-body
keyset-request-payload = bstr .size 8      ; random tag
keyset-payload = bstr .cbor keyset

; ---------------------------------------------------------------------------
; identities and keys

keyset = [+ COSE_Key]                      ; signing keys only; no kid, no private params

ratchet-key = {                            ; public HPKE key announced by an identity
  1 => int,                                ; kty
  2 => bstr .size 8,                       ; kid = SHA-256(pub)[0:8]
  3 => int,                                ; alg: an HPKE id
  * int => any,
}

; ---------------------------------------------------------------------------
; signed and sealed layers

signed = COSE_Sign1_Tagged / COSE_Sign_Tagged   ; protected kid (4) = signer address
sealed = COSE_Encrypt0_Tagged / COSE_Encrypt_Tagged

announce-body = {
  ? 1 => bstr .cbor keyset,                ; only in a full announce
  2 => uint,                               ; sequence
  ? 4 => any,                              ; app data
  5 => ratchet-key,
  ? 7 => uint,                             ; services bitmask: 1 = propagation node
}

message-body = {
  1 => [+ address],                        ; to
  2 => uint,                               ; time, ms (the sender's claim)
  ? 3 => tstr,                             ; title
  ? 4 => any,                              ; content
  ? 5 => { * any => any },                 ; fields
  ? 6 => bstr .size 16,                    ; receipt secret
}

link-request-body = {
  1 => COSE_Key,                           ; initiator's ephemeral KEM public key
  2 => bstr .size 32,                      ; part_a
  3 => address,                            ; the responder
}

link-accept-body = { 1 => bstr .size 32 }  ; part_b

; resources (large transfers) over a link, one of these per link message
resource-body = {8 => resource-advert} / {9 => resource-request} / {10 => resource-part} / {11 => resource-id}
resource-id = bstr .size 16                ; SHA-256(data)[0:16]
resource-advert = {
  1 => resource-id,
  2 => uint,                               ; size
  3 => uint,                               ; part count
  4 => bstr .size 32,                      ; SHA-256(data)
  ? 5 => any,                              ; meta (file name, type, ...)
}
resource-request = [resource-id, [* uint]] ; part indexes wanted
resource-part = [resource-id, uint, bstr]  ; index, data

; propagation nodes, over a link (one of these per link message)
propagation-body = {15 => deposit, ? 6 => bstr .size 16}   ; deposit (+ its receipt secret)
                 / {12 => true}                            ; fetch
                 / {13 => [uint, uint, bstr]}              ; item: index, packet type, payload
                 / {14 => uint}                            ; end of batch: item count
                 / {16 => uint}                            ; ack: got that many
deposit = [address, uint, bstr]            ; recipient, packet type (1 data / 4 receipt), payload

link-body = {                              ; a message body without `to`
  2 => uint,
  ? 3 => tstr,
  ? 4 => any,
  ? 5 => { * any => any },
  ? 6 => bstr .size 16,
  ? 7 => true,                             ; closing the link
}

; ---------------------------------------------------------------------------
; the COSE structures used (RFC 9052, reduced)

COSE_Sign1_Tagged = #6.18(COSE_Sign1)
COSE_Sign_Tagged = #6.98(COSE_Sign)
COSE_Mac0_Tagged = #6.17(COSE_Mac0)
COSE_Encrypt0_Tagged = #6.16(COSE_Encrypt0)
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)

; RFC 9052 writes the two header fields as a `Headers` group; they are spelled
; out here (identical on the wire) because some CDDL tools mis-align inline groups.
COSE_Sign1 = [protected: prot, unprotected: header_map, payload: bstr, signature: bstr]
COSE_Sign = [protected: prot, unprotected: header_map, payload: bstr, signatures: [+ COSE_Signature]]
COSE_Signature = [protected: prot, unprotected: header_map, signature: bstr]
COSE_Mac0 = [protected: prot, unprotected: header_map, payload: bstr, tag: bstr]
COSE_Encrypt0 = [protected: prot, unprotected: header_map, ciphertext: bstr]
COSE_Encrypt = [protected: prot, unprotected: header_map, ciphertext: bstr, recipients: [+ COSE_recipient]]
COSE_recipient = [protected: prot, unprotected: header_map, ciphertext: bstr]

prot = bstr .size 0 / bstr .cbor header_map      ; empty, or a serialized header map
header_map = { * label => any }
label = int / tstr

COSE_Key = {
  1 => int,                                ; kty
  ? 2 => bstr,                             ; kid
  3 => int,                                ; alg (required here)
  * int => any,
}
```
<!-- /cddl -->

## 16. Constants and defaults

Every number an implementation needs. **Protocol** values are wire format and
MUST be used; **node defaults** and **limits** are local policy (what the
reference does). Generated by `cosiechat constants` (a test fails if this
copy and the code differ).

<!-- constants -->
**Protocol (MUST)**

| | value | |
|---|---:|---|
| protocol version | 0 | first element of every frame |
| address | 16 | bytes: SHA-256(keyset)[0:16] |
| ratchet id | 8 | bytes: SHA-256(ratchet pub)[0:8] |
| link id | 16 | bytes: SHA-256(link request)[0:16] |
| link key part | 32 | bytes, each of part_a and part_b |
| fragment id | 8 | bytes, random |
| fragment overhead | 21 | bytes a sender leaves for the fragment header |
| request tag | 8 | random bytes in path and keyset requests |
| receipt secret | 16 | bytes, random, in message field 6 |
| receipt tag | 16 | bytes of HMAC-SHA-256 |
| receipt nonce | 8 | random bytes after the tag |
| NACK indexes | 4096 | at most, in one NACK |
| resource id | 16 | bytes: SHA-256(data)[0:16] |

**Node defaults (`Node(...)`, local policy)**

| | value | |
|---|---:|---|
| transport | `False` | route packets for others (rebroadcast announces, forward via) |
| propagate | `False` | also hold packets for unreachable destinations (implies transport) |
| max_hops | 16 | packets and announces are not forwarded beyond this |
| rebroadcast_delay | 0.25 | s, random jitter before a transport rebroadcast |
| announce_interval | `None` | s between automatic announces (None: only when asked) |
| quantum_safe_only | `True` | ignore / refuse peers that are not quantum-safe |
| retry_after | 30 | s before the first resend of an unconfirmed message |
| retry_max | 600 | s, cap on the doubling resend gap |
| max_attempts | 4 | sends of a sealed message before giving up |
| accept_links | `True` | answer link requests |
| link_attempts | 3 | sends on a link before falling back to sealed |
| nack_attempts | 3 | NACKs per stalled fragment set |
| max_links | 256 | links held (least recently used dropped) |
| path_ttl | 604,800 | s a path lives after the announce that set it |
| max_peers | 10,000 | peers remembered (least recently heard forgotten first) |
| max_resource | 16,777,216 | bytes: the largest resource accepted |
| auto_propagate | `True` | deposit with a propagation node when direct delivery gives up |
| announce_cap | 0.02 | share of a slow road announces may use |
| announce_queue_age | 3600 | s an announce may wait in the queue |
| rebroadcast_min_interval | 60 | s between rebroadcasts of one identity |

**Limits (local policy)**

| | value | |
|---|---:|---|
| propagation batch | 64 | items handed over per fetch |
| resource part | 320 | bytes of data per part (fits one LoRa frame) |
| resource window | 8 | parts a receiver asks for at a time |
| resource stalls | 8 | times a receiver re-asks without progress |
| trial ratchets | 16 | newest ratchets tried on a shared COSE_Encrypt |
| reassembly timeout | 60 | s before an incomplete fragment set is dropped |
| reassembly sets | 256 | incomplete fragment sets held |
| reassembly bytes | 1,048,576 | largest packet reassembled |
| completed sets remembered | 1024 | to ignore late resends |
| fragment cache sets | 32 | sent fragment sets kept for NACKs |
| fragment cache time | 60 | s they are kept |
| NACK delay | 2 frame-times + 0.2 s | stall before asking; doubles per try |
| duplicate filter | 50,000 | packet hashes remembered |
| delivered ids | 10,000 | message ids handed to the app (dedupe) |
| delivery results | 1000 | sent messages whose delivery can be awaited |
| link accepts kept | 256 | to answer a repeated link request |
| messages waiting for a keyset | 16 | per unknown sender |
| senders waited on | 256 | unknown senders at once |
| announce queue | 256 | destinations waiting per road (most hops dropped) |
| timer tables | 4096 | per-address rate-limit timers remembered |
| keyset waits | 256 | short announces / forwarded requests awaiting a keyset |
| ingress: announce | 5/s, burst 20 | per road (`Node(ingress=...)`) |
| ingress: link | 2/s, burst 10 | per road (`Node(ingress=...)`) |
| ingress: message | 50/s, burst 200 | per road (`Node(ingress=...)`) |
| ingress: request | 10/s, burst 30 | per road (`Node(ingress=...)`) |
| store per destination | 64 | packets (MemoryStore) |
| store destinations | 1024 | destinations (MemoryStore) |
<!-- /constants -->

## 17. Node behaviour (pseudo-code)

What the reference node does, in order, so another implementation behaves the
same and not just encodes the same. `now` is the node's own monotonic clock.
Numbers are the defaults from §16.

### 17.1 Receiving a frame (on road R)

```
on_frame(R, bytes):
  if R has a road key: bytes = unwrap(bytes) or drop          # §8.2
  item = decode(bytes) or drop                                 # unknown version: drop
  if item is NACK:        resend the listed fragments of item.id if we sent it   # §8.1
                          return
  if item is FRAGMENT:    add to reassembly(R, item.id)
                          restart the stall timer of (R, id); cancel it when complete
                          if not complete: return
                          item = decode(reassembled) or drop
  if hash(item) already seen:
    if item is ANNOUNCE:  seen_announce_again(R, item)         # §9 fewer hops
    return
  remember hash(item)
  dispatch by item.type:
    ANNOUNCE → on_announce      DATA / RECEIPT / LINK_* → on_routed
    PATH_REQUEST → on_path_request   KEYSET_REQUEST → on_keyset_request   KEYSET → on_keyset

fragment stall timer fires (R, id):                            # after 2 frame-times + 0.2 s
  if the set is still incomplete and fewer than 3 NACKs were sent:
    send NACK(id, missing indexes) on R; re-arm with twice the delay
```

### 17.2 Announces and paths

```
on_announce(R, p):
  cheap checks, else drop: signature kid == p.dest; an included keyset hashes to
    p.dest and matches any pinned keyset; (quantum_safe_only) identity and ratchet PQ
  rate limit 'announce' on R, else drop
  verify(p.payload, keyset from p or pinned)
    unknown keyset (short announce) → park (R, p); send KEYSET_REQUEST(p.dest); return
    invalid → drop
  if we hold an announce from p.dest with a higher sequence: drop
  store keyset (pin), announce, ratchet; note peer as recently heard (LRU, 10,000)
  if services has bit 1: remember p.dest as a propagation node
  path[p.dest] = (R, p.via, p.hops + 1, expires = now + 1 week)
  resolve anyone waiting for this path; hand held packets for p.dest to that path
  if transport and p.hops + 1 < 16 and p.dest not rebroadcast in the last 60 s:
    after a random delay, queue ANNOUNCE(hops + 1, via = us) on every road   # §9.0 budget

seen_announce_again(R, p):             # same bytes as the announce we accepted
  if no path, or we are waiting on a path request, or p.hops + 1 < path.hops:
    path[p.dest] = (R, p.via, p.hops + 1, ...)

on_path_request(R, p):
  rate limit 'request'
  if p.dest is us: after a random delay, send a FULL announce
  elif transport and we hold an announce and a path: answer on R with the cached
    announce (hops = path.hops, via = us), through R's announce queue
  elif transport: rebroadcast the request with hops + 1

path(dest): a path past its expiry is deleted and treated as unknown
```

### 17.3 Routed packets

```
on_routed(R, p):
  if p.dest is us:
    DATA → deliver(p)   RECEIPT → on_receipt   LINK_REQUEST / ACCEPT / DATA → §17.5
    return
  if not transport: drop
  if p.via is us, or (p.via is null and we are a propagation node, and dest is not
      a direct neighbour on R): forward(p)

forward(p):
  if no path to p.dest: (propagation node) store (p.type, p.payload) for p.dest; return
  if p.hops + 1 >= 16: drop
  send (p.type, hops + 1, dest, via = path.via, payload) on path.road

deliver(p):                                        # a sealed message for us
  rate limit 'message'
  open with the ratchet named by the kid; verify the signature
    sender unknown → park p; send KEYSET_REQUEST(sender); retry when it arrives
  (quantum_safe_only) sender not quantum-safe: drop
  if one-to-one and we hold a link to the sender: drop that link   # it lost it
  accept(m)

accept(m):
  if m has a receipt secret: send RECEIPT(receipt_tag, 8 random bytes) to m.sender
  if m.id already handed over: ask for a fresh path to m.sender (≤ once per 30 s); return
  remember m.id; hand m to the application
```

### 17.4 Sending and retrying

```
send(to, content):
  if a link to `to` exists: send on the link (§17.5), attempts = 3, fallback = sealed
  else: need identity + ratchet for `to` (else PATH_REQUEST and wait; none → error)
        sign once; per recipient: envelope to its newest ratchet, attempts = 4,
        fallback = deposit with a propagation node (§9.4), if any
  send_data(to, payload):
    via = path.via if we have a path, else null; send on path.road, or on all roads

retry(o):                                   # until its RECEIPT arrives
  wait 30 s, then double each time up to 600 s
  after the 2nd unanswered send: send a fresh PATH_REQUEST (≤ once per 30 s)
  each resend: a new envelope (or new IV on a link) around the same content
  when the attempts run out: forget the path; run the fallback, if any; else fail

on_receipt(p): find the send whose tag == p.payload[0:16]; mark it delivered
```

### 17.5 Links, resources, propagation

```
open_link(peer):
  request = envelope to peer's ratchet of sign({ephemeral KEM pub, part_a, peer address})
  send LINK_REQUEST; wait; no accept → a NEW request (new link id), backing off
on LINK_REQUEST: rate limit 'link'; sender unknown → park + fetch keyset
  open, verify, check it names us; derive keys; keep the accept (answer repeats with it)
on LINK_ACCEPT: finish; delete the ephemeral private key; the link is up
on LINK_DATA: open with the link key, then by body:
  message body → accept(m)          7: true → forget the link
  resource fields 8–11 → §9.3       propagation fields 12–16 → §9.4
links: at most 256, least recently used forgotten first
```

## 18. Security considerations

**Threat model.** Attackers can read, drop, replay, reorder and inject
frames on any road, run transport and propagation nodes, and later steal
devices (and their stored keys). A large quantum computer may exist in the
future and be used on recorded traffic.

**What each party learns.**

| | on-road observer | transport / propagation node | recipient |
|---|---|---|---|
| destination address, sizes, timing, hops | yes | yes | yes |
| ratchet id (links to the destination only) | yes | yes | yes |
| link id (ties messages of one session together) | yes | yes | yes |
| sender, full recipient list, content | no | no | yes |
| who deposits / fetches at a propagation node | no | the fetcher (link peer) and depositor | — |
| everything, with a road key in `encrypt` mode | only sizes and timing | as above | yes |

**Authenticity and confidentiality.** Messages are signed by the sender
(ML-DSA by default) and sealed to the recipient's ratchet (X-Wing by default);
the signed `to` list stops a recipient re-sealing a message to someone else
as if it were addressed to them. Links authenticate the initiator by
signature and the responder by ratchet possession; link messages are not
signed (no third-party proof of authorship). Announces, keysets and ratchets
are self-certifying through the address hash, and addresses are pinned on
first use (TOFU). Receipts prove the recipient opened the message; in a
multi-recipient message recipients could forge each other's receipts.

**Forward secrecy** comes from deleting ratchets (sealed messages) and link
ephemeral keys (links). How long ratchets live is storage policy (§7.1).
Identities hold no decryption key at all.

**Replay.** Duplicate packets are filtered in memory; message ids are handed
over once; announce sequences only go up, so a replayed old announce cannot
roll back a path or a ratchet.

**Denial of service.** Every expensive step (signature checks, HPKE decaps,
answers that transmit) is behind cheap checks and per-road token buckets
(§9.0); all tables are bounded (§16); announces have an airtime budget; NACKs
and resource requests are bounded in count. A neighbour can still fill a
road's airtime or pin a mailbox's size at a propagation node; road keys (§8.2)
keep strangers off a road.

**Not covered.** Traffic analysis beyond what is listed, a compromised device
(its held ratchets open recent traffic), weak road passphrases, and the
maturity of the drafts in §2 (see CAVEATS.md).

## 19. Versioning

The first element of every frame is the protocol version (§8). This draft is
**version 0**; nothing has been deployed, so it can still change.

* **Receivers MUST ignore map keys they do not know** in every CBOR map
  (announce, message, link bodies, COSE headers other than `crit`), and MUST
  drop packet types they do not know. That makes these changes
  **compatible, no version bump**: a new optional announce or message field,
  a new link body kind, a new packet type, a new suite or algorithm (peers
  that lack it just cannot use it).
* **Anything else bumps the version**: changing the meaning, encoding or
  size of an existing field, how an address, id, key or tag is derived, a
  COSE structure, or a MUST in this document. Nodes drop frames of versions
  they do not implement, so old and new meshes ignore each other cleanly
  rather than misunderstand each other.
* **The PQ HPKE ids** (56/57 for X-Wing, 62–65 for ML-KEM) are the values
  suggested by draft-reddy-cose-hpke-pq-pqt, not yet registered. If they are
  registered as different numbers, that is a version bump: version 1 uses
  the registered ids. A node MAY run both versions side by side during a move.
* Until version 1 is declared, treat version 0 as unstable: re-check the
  vectors after every update of this document.
