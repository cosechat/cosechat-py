# Porting cosechat (JS, Arduino, anything)

How to build another implementation that interoperates with this reference.
The wire format is [SPEC.md](SPEC.md) (with [cosechat.cddl](cosechat.cddl));
behaviour is SPEC §17; numbers are SPEC §16. This file is the practical path.

## Order of work

Build bottom-up, and check each layer against the test vectors
(`tests/vectors/vectors.json`) before going on. Nothing below the node needs a
network.

1. **CBOR** with deterministic encoding (RFC 8949 §4.2.1).
2. **COSE structures** (`src/cosechat/cose.py` is ~400 lines): Sign1, Sign,
   Mac0, Encrypt0, and Encrypt/Mac if you want the multi-recipient extra.
   Check with the `cose` vectors and the `exact` Sign1/Mac0/Encrypt0 cases.
3. **Keys and algorithms**: COSE_Key (OKP, EC2, AKP, Symmetric), ML-DSA,
   Ed25519, HPKE-9 (X-Wing) and HPKE-0. Check `exact` identity/ratchet cases.
4. **Identity, ratchets, announces, messages, receipts**: check `identities`,
   `announces`, `messages`, the `exact` announce and signed-message cases,
   and every `reject` case (each names the rule it tests).
5. **Packets, fragments, NACKs, road auth**: check `packets`, `road_auth`,
   `exact` fragments/NACK/road-auth.
6. **Links** (key derivation is in `exact`; handshakes in `links`), then
   resources and propagation.
7. **Node behaviour** (SPEC §17), then roads.
8. **Conformance**: run `cosechat check your-vectors.json` on vectors *you*
   generate in the same format, and run `interop/live.py` against your echo
   bot (it must pass 6/6).

## Libraries (use existing ones; do not write crypto)

| need | Python (this repo) | JavaScript | Arduino / MCU |
|---|---|---|---|
| CBOR | cbor2 (`canonical=True`) | cborg (deterministic encoding) or cbor-x | wolfCOSE's CBOR (`wc_CBOR_*`) |
| COSE | own thin layer (`cose.py`) | port `cose.py` (no JS COSE lib does ML-DSA/X-Wing) | wolfCOSE |
| ML-DSA | cryptography ≥ 50 | @noble/post-quantum (`ml_dsa65`) | wolfCOSE / wolfCrypt ML-DSA |
| ML-KEM, X-Wing | cryptography ≥ 50 (HPKE `MLKEM768_X25519`) | @noble/post-quantum (`ml_kem768_x25519`) | wolfCrypt ML-KEM + X25519 (glue, below) |
| HPKE | cryptography ≥ 50 | hpke-js (@hpke/core, @hpke/hybridkem-x-wing) | wolfCrypt HPKE (HPKE-0 via wolfCOSE) |
| Ed25519, X25519, P-256 | cryptography | @noble/curves | wolfCrypt |
| AES-GCM, ChaCha20-Poly1305, HMAC, SHA-2, SHAKE, HKDF | cryptography, hashlib | WebCrypto, @noble/ciphers, @noble/hashes | wolfCrypt |

Library claims to verify yourself, with the vectors as the judge:

* **HPKE-9 uses the SHAKE256 KDF** (HPKE KDF id `0x0011`, the single-stage
  KDF of draft-ietf-hpke-pq), not HKDF. Make sure your HPKE library supports
  it for X-Wing; if not, that key schedule is the glue you write. The
  `cose` vectors (HPKE-9 Encrypt0 and Encrypt) and the `pq` messages will
  fail until it is right.
* **COSE-HPKE integrated mode (Encrypt0) needs HPKE's `aad` input** set to the
  Enc_structure. Some HPKE APIs only expose single-shot seal with `info`.
* **X-Wing private keys are 32-byte seeds**, expanded with SHAKE256 (SPEC §3);
  check your library derives the same public key (`tests/vectors/xwing-seed-pk.txt`).

## Arduino / wolfCOSE notes

What stock wolfCOSE 2.x already does, checked by `interop/wolfcose` (40/40):
Ed25519/ESP256/ML-DSA Sign1, COSE_Sign, HMAC Mac0, AES-GCM/ChaCha Encrypt0,
HPKE-0 Encrypt0 and COSE_Encrypt, and every signature layer of every message
and announce. Build wolfCOSE with the flags in `interop/wolfcose/Makefile`
(including `-DWOLFCOSE_EXPERIMENTAL` for COSE-HPKE).

Glue you have to write over wolfCrypt:

* **X-Wing HPKE (HPKE-9 / HPKE-9-KE)**: wolfCrypt has ML-KEM-768, X25519 and
  SHAKE256; you need the X-Wing combiner (draft-connolly-cfrg-xwing-kem),
  the HPKE key schedule with the SHAKE256 KDF, and AES-256-GCM. Until then an
  Arduino node can run the `prequantum` suite (all wolfCOSE-native) with
  `quantum_safe_only` turned off — not quantum-safe.
* **HPKE-0 vs HPKE-0-KE**: wolfCOSE enforces a key's `alg`. A ratchet is
  announced as HPKE-0; set the decoded key's alg to HPKE-0-KE before opening
  a COSE_Encrypt recipient with it (SPEC §2; `interop/wolfcose/check.c` does).
* **ML-DSA signing memory**: an ML-DSA-65 signature is 3,309 bytes and
  signing needs a few tens of KB of working memory; enable wolfSSL's
  small-stack / small-memory ML-DSA options, or keep the pq suite on boards
  with PSRAM (ESP32-S3 with PSRAM is comfortable).

### Memory budget (pq suite)

| item | bytes |
|---|---:|
| ML-DSA-65 public key / private seed | 1,952 / 32 |
| ML-DSA-65 signature | 3,309 |
| X-Wing public key / private seed / encapsulation | 1,216 / 32 / 1,120 |
| largest packet you must reassemble (a full announce) | ~6.6 K |
| one peer: keyset + ratchet COSE_Key (+ path) | 1,963 + 1,236 ≈ 3.2 K |
| + its cached announce, kept to answer path requests (transport nodes) | 4.6–6.6 K |

So an end node that remembers 32 peers needs ~100 KB for them, a transport
node ~300 KB. (An end node need not cache announces at all.) Pick small limits
(all local policy, SPEC §16), for example:

| setting | reference | small MCU |
|---|---:|---:|
| `max_peers` | 10,000 | 16–64 |
| reassembly bytes / sets | 1 MiB / 256 | 16 KiB / 4 |
| duplicate filter | 50,000 | 256 |
| delivered ids | 10,000 | 64 |
| fragment cache sets | 32 | 2 |
| `max_links` | 256 | 4 |
| `max_resource` | 16 MiB | what fits your storage |

### No clock, no problem

The protocol never compares anyone's clock with anyone else's. On a board
without an RTC:

* **Announce sequence**: keep a counter in flash/NVS; on boot, add a margin
  (say 1,000) and save it, then add 1 per announce. It only has to grow.
* **Message timestamps** are display-only; send 0 or uptime if you have
  nothing better.
* **Timers** (retries, NACK delays, path expiry, rate limits) use a monotonic
  uptime counter (`millis()`).
* **Ratchets** can live in RAM only (forward secrecy across reboots) or in
  NVS; keep the ones you announced for as long as you want to accept mail
  sealed to them.

### Roads on a microcontroller

A board with its own LoRa radio (SX126x/SX127x) does not need the RNode
protocol: its road is the radio itself, with an MTU of 255 (one LoRa packet)
and a bitrate from its SF/BW/CR (the formula in SPEC §9.0). Everything above
the road is the same. Talking to an RNode over USB serial uses the KISS
protocol in SPEC §10.1.

## JavaScript notes

* **Browser**: WebSocket road only, to a transport node running
  `WebSocketServerRoad` (e.g. `examples/chat.py --ws-server 4243 --transport`).
* **Node.js**: UDP (`dgram`), WebSocket (`ws`), RNode over serial
  (`serialport`).
* The node is naturally asynchronous; the Python `Node` maps onto
  promises and timers one to one.
