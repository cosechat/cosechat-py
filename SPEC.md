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

A suite is just a choice of algorithms for a new identity. Every message
states its own algorithms, so nodes with different suites talk to each other.

| suite | signing | KEM | public keyset | announce packet | 1-recipient message packet |
|---|---|---|---:|---:|---:|
| `pq` (default) | ML-DSA-65 | HPKE-9 (X-Wing) | 3189 B | ~7.8 KB (17 LoRa frames) | ~4.6 KB (10 frames) |
| `hybrid` | Ed25519 **and** ML-DSA-65 | HPKE-9 | 3231 B | ~7.9 KB | ~4.6 KB |
| `prequantum` | Ed25519 | HPKE-0 | 121 B | ~360 B (1 frame) | ~260 B (1 frame) |

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
| forward secrecy | ratchets (§7.1) use the identity's KEM, so X-Wing for `pq`/`hybrid` | a stolen identity key opens nothing; ratchet keys already deleted open nothing |
| content / MAC / KDF | AES-256-GCM, HMAC-SHA-256, SHAKE256, SHA-256 | Grover's algorithm only halves symmetric strength, leaving ≥ 128 bits |
| addresses | SHA-256 truncated to 128 bits | forging a keyset for an existing address is a second preimage: about 2⁶⁴ *sequential* quantum SHA-256 evaluations, far beyond reach; nodes also pin addresses (§9) |

An identity is **quantum-safe** when its KEM is X-Wing or ML-KEM (HPKE-9,
-12, -13) and at least one of its signing keys is ML-DSA. Because the
algorithms are part of the keyset, and so of the address, nobody can downgrade
a quantum-safe identity to pre-quantum crypto.

What the suites do *not* protect (see [CAVEATS.md](CAVEATS.md) for the full list):

* **Mixed meshes.** A message is only as strong as its recipient's KEM, and a
  signature only as strong as its sender's keys. A `pq` node sending to a
  `prequantum` identity produces a message a quantum attacker can read later.
  Nodes MUST therefore run a *quantum-safe-only* policy **by default**:
  ignore announces from, refuse to send to, and drop messages from identities
  that are not quantum-safe. Accepting pre-quantum peers MUST be an explicit
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

An identity is a CBOR array of COSE_Keys (a COSE_KeySet): one or more
signing keys, then exactly one HPKE KEM key. Keys in the public keyset carry
no `kid` and no private parameters.

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

Only with forward secrecy explicitly turned off is `sealed` addressed to the
recipient's long-term identity KEM key, and then it carries no kid.

What each party can see:

| | router | recipient |
|---|---|---|
| destination address (packet header) | yes | yes |
| ratchet id (Encrypt0 kid) | yes (links only to the destination, already visible) | yes |
| sender address | **no** | yes, in the signed protected header |
| full recipient list | **no** | yes, inside the signature |
| title, content, fields | **no** | yes |

Receivers MUST:

1. open the envelope: find the ratchet named by the kid and decrypt with it;
   with no kid, use the identity KEM key, but only if forward secrecy is off
   (it is on by default, and then such messages MUST be dropped),
2. read the sender from the protected `kid` of the signature,
3. find the sender's keyset (from announces, or the attached identity below),
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
  reference tries at most 16), then the identity key if forward secrecy is
  off. Useful when one ciphertext really does reach everyone, such as storage
  or a future broadcast destination.

## 7. Announces

```
body     = { 1: public keyset (bstr),
             2: sequence (uint),
             3: nonce (8 random bytes),
             4: app data (any, optional),
             5: ratchet (public COSE_Key, required unless forward secrecy is off) }
announce = identity signature over bstr(body)       ; protected kid = address
```

A receiver MUST check that the keyset in `1` hashes to the signed kid, that
this equals the packet's `dest`, and that the signature verifies with that
keyset. App data is application-defined; the examples send `{"name": ...}`.

The **sequence** MUST grow with every announce of an identity. A receiver
MUST ignore an announce whose sequence is lower than the last one it accepted
for that identity, so a replayed old announce cannot bring back an old path
or ratchet. The sequence only orders an identity's own announces, and is
never compared with the receiver's clock. The reference uses Unix ms and
never goes backwards; a device without a clock can use a persisted counter.

### 7.1 Ratchets (forward secrecy)

Like Reticulum's ratchets, but on by default and post-quantum.

* A ratchet is a fresh HPKE KEM key with **the same KEM as the identity**
  (X-Wing for `pq`/`hybrid`). Its public COSE_Key in announce field `5` has
  `kid` = ratchet id = `SHA-256(pub)[0:8]`, and no private parameters.
  Receivers MUST reject an announce whose ratchet uses another KEM, has a
  wrong kid, or carries private parameters. The ratchet is inside the signed
  body, so only the identity can announce it.
* A sender MUST seal to the ratchet in the newest announce it accepted from
  the peer. With none, it sends a path request to get an announce; if none
  comes, it MUST NOT send unless forward secrecy is explicitly off.
* A receiver opens a message with the ratchet named by its kid, if it still
  holds it.
* **Default:** forward secrecy on. Then senders only seal to ratchets, and
  receivers drop anything sealed to their long-term key. Turning it off
  (reference: `Node(forward_secrecy=False)`) stops announcing ratchets and
  accepts long-term-key messages. Such a node still seals to a peer's ratchet
  when it has one.

**Lifetime is storage policy, not protocol.** When a node rotates and when it
deletes old ratchet private keys is up to the application and its storage.
Deleting a ratchet is what makes messages sealed to it unrecoverable, so it
sets the forward-secrecy window. Rules that do not depend on anyone's clock:

* announce the new ratchet whenever you rotate (the reference
  `Node.rotate_ratchet()` does);
* keep old ratchets long enough for messages still in flight, and for
  store-and-forward delays you want to allow;
* a message sealed to a ratchet you no longer hold simply fails to open.

The reference library keeps ratchets in memory by default and never rotates
or deletes them by itself, so by default forward secrecy holds across
restarts. `examples/storage.py` shows one suggested policy: rotate every 30
minutes and delete after 10 days by the local clock, in files that can be
passphrase-encrypted at rest.

## 8. Packets

```
packet = [ version, type, hops, dest, via, payload ]
  version uint, 0 for this draft
  type    0 ANNOUNCE | 1 DATA | 2 PATH_REQUEST | 4 RECEIPT
          | 5 LINK_REQUEST | 6 LINK_ACCEPT | 7 LINK_DATA
  hops    uint, hops travelled so far (originator sends 0)
  dest    bstr .size 16
  via     bstr .size 16 / null   the transport node that should forward it
  payload bstr   announce | sealed message | 8-byte random tag (path request)
                 | receipt tag (16) || random nonce (8)
                 | link request | link accept | link message (§9.2)

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
incomplete sets after a timeout (reference: 60 s). There is no
retransmission; a lost fragment loses the packet. Senders size chunks as
`mtu - road auth overhead - 21`.

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
too) and a path table `dest → (road, via, hops, announce time)`.

* **Pinning:** once a node holds a keyset for an address, it MUST reject
  announces carrying a different keyset for that address.
* **Announce received** (and valid, and not older than the one on file):
  store the keyset, set `path = (arrival road, packet.via, packet.hops + 1)`.
  A *transport* node rebroadcasts it on all its roads with `hops + 1` and
  `via = own address`, after a small random delay, if `hops + 1 < max_hops` (16).
* **Sending DATA:** seal to the destination's current ratchet (§7.1), then use the path if there is one: `via = path.via` (null when
  the destination is a direct neighbour), send on `path.road`. Without a path,
  send a PATH_REQUEST and wait; if still none, send with `via = null` on all
  roads (reaches neighbours and propagation nodes).
* **DATA received**, not for us, at a transport node: forward if `via` is our
  address: `hops + 1`, `via = our path.via`, send on our path's road.
  A propagation node also takes `via = null` DATA; with no path it holds the
  sealed payload and forwards it when the destination announces.
* **RECEIPT and LINK_*** packets are routed exactly like DATA (including by
  propagation nodes).
* **PATH_REQUEST for dest:** the destination announces. A transport node with
  a path replies on the arrival road with the cached announce
  (`hops = path.hops`, `via = own address`); without one it rebroadcasts the
  request with `hops + 1`.

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
| identity | X25519 + Ed25519, 64 raw bytes | COSE_KeySet, any algorithms, PQ by default |
| address | SHA-256(name hash ‖ identity hash)[0:16] | SHA-256(keyset)[0:16] (no app names/aspects yet) |
| encryption | ephemeral X25519 + HKDF + AES-CBC/HMAC token | COSE-HPKE (X-Wing), COSE_Encrypt0/Encrypt |
| message | msgpack, fixed byte offsets | CBOR + COSE, self-describing |
| multi-recipient | none | extra: signed once, per-recipient copies (or one shared COSE_Encrypt) |
| sender | inside encrypted payload | protected `kid` of the signature, inside encryption |
| ratchets | X25519, opt-in, rotation and retention built in (30 min, 512 kept) | X-Wing (PQ), on by default, rotation and retention left to storage |
| links | X25519 + Ed25519 handshake | X-Wing handshake, one ML-DSA signature, per-link forward secrecy |
| delivery proofs | signed proofs | 24-byte HMAC receipts (§9.1) |
| resources, stamps | yes | not yet (see below) |

## 12. Not yet specified

Link keepalive and idle timeout, fragment-level resume, propagation-node sync,
stamps/proof-of-work, resource transfer, named destinations (app name +
aspects), path expiry policy.

## 13. Test vectors

`tests/vectors/vectors.json` (regenerate with `cosiechat vectors`) holds keys,
COSE objects for every algorithm, identities with their ratchets, sealed
messages (to a ratchet, to a long-term key, and a shared multi-recipient
Encrypt), announces with ratchets, packets and road-auth frames. Signatures
and HPKE are randomized, so vectors are "must accept" cases. Another
implementation should (1) accept every vector in that file and (2) emit a
file in the same format that `cosiechat check FILE` accepts.

`interop/wolfcose` runs the vectors through stock wolfCOSE + wolfSSL (the
Arduino stack): `make test WOLFSSL_PREFIX=… WOLFCOSE_DIR=…`. Today it accepts
all 36 cases in its scope. That covers Ed25519, ESP256 and ML-DSA-44/65/87
Sign1; hybrid COSE_Sign; HMAC and AEAD Encrypt0; HPKE-0 Encrypt0 and
COSE_Encrypt; every message signature layer; complete `prequantum` messages;
every announce; and road auth. It skips what wolfCOSE lacks: X-Wing/ML-KEM
HPKE, HPKE-4, HMAC 256/64, and COSE_Mac with HPKE recipients.
