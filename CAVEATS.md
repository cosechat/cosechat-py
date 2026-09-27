# Caveats

Known limits of cosiechat as it stands. The wire format is in
[SPEC.md](SPEC.md). This file is the honest list of what it does not (yet) do.

## Security

* **Not audited.** Nothing here has had a security review. Treat it as a
  reference and test oracle, not a hardened product.
* **Drafts, not standards.** ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are NIST
  standards. X-Wing, COSE-HPKE, and the COSE algorithm ids for PQ HPKE
  (HPKE-9 = 56/57, HPKE-12/13 = 62–65) are still Internet-Drafts. Those ids
  are the drafts' *suggested* values and may change before registration,
  which would change the wire format.
* **Quantum safety depends on both ends.** A message is only as strong as its
  recipient's KEM, and a signature only as strong as its sender's keys.
  Nodes are quantum-safe-only by default, so they ignore, refuse, and drop
  `prequantum` peers. Opting out (`Node(quantum_safe_only=False)`,
  `examples/chat.py --allow-prequantum`) makes traffic with those peers readable
  by a future quantum attacker who records it today.
* **Forward secrecy is only as good as your ratchet deletion.** Messages are
  sealed to ratchet keys (SPEC §7.1). The library never rotates or deletes
  them on its own: by default they live in memory, so a restart is the
  forward-secrecy boundary. How often to rotate and how long to keep old
  ratchets is the application's storage policy (`Node.rotate_ratchet()`; a
  suggested policy is in `examples/storage.py`: rotate every 30 minutes,
  delete after 10 days). Someone who steals the ratchets a node still holds
  can read messages sealed to them. Stealing only the identity key opens nothing.
* **Deleting a ratchet is only as good as the storage.** Removing a key from
  a file does not remove it from flash, SSDs, backups or swap. That is a
  storage concern: use full-disk encryption, secure elements, or media you
  can really erase.
* **Forward secrecy is on by default, which has costs.** You can only message
  a peer whose announce (with its ratchet) you have received, so first
  contact needs an announce (a path request triggers one). A message sealed
  to a ratchet the recipient has since deleted can no longer be opened, which
  includes messages held too long by a store-and-forward node. Opting out
  (`Node(forward_secrecy=False)`) goes back to long-term keys.
* **No dates are trusted.** The library never expires or rejects anything by
  comparing a peer's timestamp with its own clock. Announce sequence numbers
  only order one identity's own announces. The price: a peer that rotates
  its ratchet and then loses the new one (say, a reboot with RAM-only
  ratchets) stays unreachable until it announces again.
* **Addresses are 128 bits.** Forging a keyset for an existing address takes
  a second preimage of truncated SHA-256: about 2⁶⁴ sequential quantum
  evaluations with Grover's algorithm, far out of reach. Nodes also pin an
  address to the first keyset they see for it. The flip side of pinning is
  trust on first use: a node that has never seen the real keyset accepts
  whichever valid one arrives first.
* **Road keys are only as good as the passphrase.** Road auth (Mac0 or
  Encrypt0 per frame) uses HMAC-SHA-256 / AES-256-GCM, but the key comes from
  a passphrase through HKDF, which does not slow down guessing. A weak
  passphrase can be brute-forced offline from one captured frame.
* **Metadata is visible.** Routers and anyone on an unencrypted road see
  destination addresses, packet sizes, timing, and hop counts. With road auth
  in `encrypt` mode, outsiders on that road see only sizes and timing.
  Announces are public by design.
* **No replay protection for messages.** Duplicate packets are filtered by
  hash in memory (up to 50,000), but that is lost on restart. Messages carry a
  timestamp and a unique id; applications should dedupe by `Message.id`.
* **Key storage is the application's job.** The library does no file I/O.
  `examples/storage.py` shows one practice: files written atomically with
  mode 0600, and optionally encrypted at rest with a passphrase (scrypt, then
  COSE_Encrypt0). `cosiechat keygen` writes a plain, unencrypted keyset.

## Protocol gaps (vs Reticulum / LXMF)

* No links (sessions), delivery proofs, resources (large transfers),
  stamps/proof-of-work, propagation-node sync, or named destinations
  (app name + aspects).
* **Fragments are not retransmitted.** A PQ announce is about 17 LoRa frames
  and a PQ message about 10. Losing any one frame loses the whole packet.
* Path expiry and path-quality selection are minimal: the first announce
  copy wins, and a newer announce replaces the path.
* Store and forward is in memory only (64 messages per destination) and is
  lost when a propagation node restarts. Persisting it is a storage concern.
* One identity per node.
* **Multi-recipient messages are an extra.** Reticulum/LXMF has none, and
  clients are expected to message one peer at a time. `Node.send([a, b])`
  just sends each recipient its own copy of one signed message, and the shared
  COSE_Encrypt form lives in the library for experiments. Receivers
  trial-decrypt a shared COSE_Encrypt against up to 16 ratchets, which costs
  about 0.7 ms per try for X-Wing in Python.

## Airtime and size

| suite | announce | 1-recipient message |
|---|---:|---:|
| `pq` (default) | ~7.8 KB (17 LoRa frames) | ~4.6 KB (10 frames) |
| `hybrid` | ~7.9 KB | ~4.6 KB |
| `prequantum` | ~360 B (1 frame) | ~260 B (1 frame) |

Post-quantum keys and signatures are kilobytes, and announces also carry a
~1.2 KB X-Wing ratchet. On slow LoRa settings a PQ
message can take seconds to tens of seconds of airtime, and duty-cycle limits
(e.g. 1% in parts of the EU 868 MHz band) cap how often you can send. Announce
sparingly on radio roads.

## Implementation notes

* **wolfCOSE (Arduino) coverage.** Stock wolfCOSE verifies everything except
  X-Wing and ML-KEM HPKE (the `pq`/`hybrid` encryption layer), HPKE-4,
  HMAC 256/64, and COSE_Mac with HPKE recipients. The `pq` encryption layer on
  Arduino needs glue code over wolfCrypt, which already has ML-KEM, X25519,
  SHAKE256, and HPKE. `interop/wolfcose` shows what passes today.
* **wolfCOSE needs a small adjustment for key encryption.** It enforces a
  key's `alg`, so a KEM key tagged HPKE-0 must be retagged HPKE-0-KE before it
  is used with a COSE_Encrypt recipient (SPEC §2).
* **Private API in pyca/cryptography.** COSE-HPKE integrated mode (Encrypt0)
  needs HPKE's `aad` input, which `cryptography` 50 only exposes through a
  private helper (`keys._hpke_seal_aad`). A future `cryptography` release
  could move it.
* **The COSE layer is hand-written.** No Python COSE library supports ML-DSA
  or X-Wing yet, so `cose.py` builds the RFC 9052 structures itself. It is
  cross-checked against pycose and python-cwt for the algorithms they support.
* **python-cwt bug.** python-cwt 3.3 reuses one encapsulated key (`ek`) across
  HPKE recipients, so its multi-recipient messages cannot be opened by all
  recipients. `tests/test_interop.py` works around it.
* **RNode support is tested against an emulator only.** The RNode road
  follows Reticulum's RNodeInterface, but it has not been run against real
  hardware yet.
* **UDP broadcast** needs peers on the same subnet and a network that passes
  broadcasts. Use `--peer` / `peers=[...]` for unicast otherwise.
