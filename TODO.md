# TODO / handoff notes

This file is for whoever (human or LLM) picks up this repo next. It says what
exists, the decisions already made (don't re-litigate them), how to work
here, and what is left in priority order.

## What this is

`cosiechat-py` is the **Python reference implementation and test oracle** of
cosiechat: a Reticulum/LXMF-style mesh messaging protocol rebuilt from
standards (CBOR, COSE, COSE-HPKE, ML-DSA, X-Wing). The sibling folders
`../cosiechat-js` and `../cosiechat-arduino` (wolfCOSE + wolfSSL) are empty
and will be ported from this repo. The docs are the porting guide:

* `SPEC.md`: wire format and node behaviour (normative)
* `CAVEATS.md`: known limits, stated honestly
* `README.md`, `examples/README.md`: usage
* `tests/vectors/vectors.json`: interop vectors (`cosiechat vectors` / `cosiechat check`)
* `interop/wolfcose/`: C checker proving the vectors verify on stock wolfCOSE

## Decisions already made (by the user)

* **Protocol vs road are separate.** The data library (`keys`, `cose`,
  `identity`, `message`, `ratchet`, `packet`) does no I/O. Roads (`roads/`)
  move opaque frames and know no crypto. `node.py` joins them. Everything is
  testable without hardware (memory road, emulated RNode).
* **Use existing libraries, don't hand-roll crypto.** All primitives come from
  pyca/`cryptography` (>= 50, which has ML-DSA, ML-KEM and HPKE including
  X-Wing), and CBOR from `cbor2`. `cose.py` is a thin RFC 9052 structure layer
  only because no Python COSE lib supports ML-DSA/X-Wing. It is cross-checked
  against pycose and python-cwt (`tests/test_interop.py`).
* **Must be implementable on wolfCOSE/wolfSSL** (Arduino). Check
  `interop/wolfcose` after wire changes.
* **Quantum-safe by default.** Suites are `pq` (default: ML-DSA-65 + X-Wing
  HPKE-9), `hybrid` (Ed25519 AND ML-DSA-65 + X-Wing), and `prequantum`
  (Ed25519 + HPKE-0). **Never call it "classic"**: this is a new protocol with
  no legacy. `Node(quantum_safe_only=True)` is the default; pre-quantum peers
  need an explicit opt-out.
* **Forward secrecy by default** via ratchets (X-Wing keys in announces).
  `Node(forward_secrecy=True)` is the default.
* **The library trusts no dates and does no storage.** Ratchet rotation and
  retention, key files, and encryption at rest are application policy, shown in
  `examples/storage.py`. Announce field 2 is a *sequence* (orders one
  identity's own announces, never compared with a clock). Message timestamps
  are display-only.
* **Single-recipient is the focus** (as in LXMF). Multi-recipient (per-recipient
  copies, or a shared COSE_Encrypt) is an extra.
* **Addresses** = SHA-256(public COSE_KeySet)[0:16]. The sender is in the
  signature's protected `kid`, inside the encryption. Routers see only the
  destination address.

## How to work here

* `uv sync --all-extras`, then `uv run pytest` (149 tests, ~6 s, no hardware).
* Formatting: StandardJS-flavored, **2-space indent, single quotes**, via ruff
  (`uv run ruff format && uv run ruff check`, config in `pyproject.toml`).
  C uses `.clang-format` (copy from `~/.claude/formatting/`) when C is added.
* After any wire change: `uv run python -m cosiechat.vectors > tests/vectors/vectors.json`,
  run the tests, and run the wolfCOSE checker (below).
* wolfCOSE checker: build wolfSSL (CMake: `-DWOLFSSL_MLDSA=yes -DWOLFSSL_MLKEM=yes
  -DWOLFSSL_HPKE=yes -DWOLFSSL_ED25519=yes -DWOLFSSL_CURVE25519=yes
  -DWOLFSSL_SHA3=yes -DWOLFSSL_SHAKE256=yes -DWOLFSSL_HKDF=yes`, plus AES-GCM,
  ChaCha, ECC, keygen), build wolfCOSE with the flags in
  `interop/wolfcose/Makefile` (`WOLFCOSE_FLAGS`, including
  `-DWOLFCOSE_EXPERIMENTAL`), then
  `make -C interop/wolfcose test WOLFSSL_PREFIX=... WOLFCOSE_DIR=...`
  (currently 36/36).
* Git rules (from the user): one-line commit messages of at most 40
  characters, no AI attribution or co-authors. Work on branches and open PRs,
  don't push to `main`. Short PR title, one-line description. There is **no
  remote yet**, so ask the user before creating one.
* Keep docs in step with code: SPEC (normative), CAVEATS (limits), README,
  and this file.

## Status

Done: COSE Sign1/Sign/Mac0/Mac/Encrypt0/Encrypt; identities and suites;
sealed messages; announces with ratchets and sequence; packets, fragments and
road auth; routing (announce flood, via-forwarding, path requests,
store-and-forward); roads (memory, UDP, WebSocket, RNode/KISS);
quantum-safe-only and forward-secrecy defaults; key pinning; vectors and
checker; wolfCOSE interop; examples (storage, chat, echo bot/client,
mesh_sim, lora_gateway).

## Left to do, in priority order

Legend: [ ] todo, [~] in progress, [x] done

### A. Required for real use (especially LoRa)

1. [x] **Wire version.** Done: every frame is `[version, ...]`, VERSION = 0. Packets have no version. Add one (e.g. packet
   `[version, type, ...]` or a leading version byte) before other
   implementations ship. The PQ HPKE ids (56/57, 62–65) are still draft values.
2. [x] **Delivery receipts and retransmission.** Done (SPEC §9.1): 24-byte
   HMAC receipts from a secret in the message, re-sealed resends with backoff,
   and app-level dedupe by message id. `node.delivered(m)`, `on_receipt`.
2b. [ ] **Fragment-level resume for LoRa.** Resends are whole-message; a PQ
   message is 10–20 LoRa frames, so at 10% frame loss most attempts fail.
   Let the receiver ask for just the missing fragments (a NACK listing
   indexes for a fragment id), or add FEC. `test_lossy_lora_road_still_delivers_once`
   shows the problem.
3. [x] **Sessions (links).** Done (SPEC §9.2, `link.py`): X-Wing handshake
   with one ML-DSA signature, per-link forward secrecy, ~140-byte messages.
   Still to add: keepalive and idle timeout, link-level MTU hints.
   Original note: **Sessions (like Reticulum Links).** Each PQ message carries about 4.5 KB
   of fixed overhead (3.3 KB ML-DSA signature + 1.1 KB X-Wing). Handshake once
   (X-Wing to the peer's ratchet, signed both ways), then symmetric AEAD per
   message (tens of bytes). Gives per-session forward secrecy. Keep
   sender-authentication semantics equal to signed messages.
4. [ ] **Announce flood control.** Transport nodes rebroadcast every announce
   (PQ is about 7.8 KB), which can eat a LoRa duty cycle and costs an ML-DSA
   verify each (CPU DoS). Add per-road announce bandwidth caps (Reticulum uses
   about 2%), per-identity rate limits, and queueing by hop count.
5. [ ] **Path upkeep.** Expire or replace dead paths, prefer fewer hops, and
   recover when a transport node vanishes. Use only the local monotonic clock
   for this, never peer dates.
6. [ ] **Large transfers (like Reticulum Resources).** Chunking, windowing and
   a whole-object hash, over sessions, for attachments.

### B. Required for SPEC.md to be the porting guide

7. [ ] **CDDL** for every structure (packet, fragment, announce body, message
   body, keyset, ratchet key, receipts and sessions once added).
8. [ ] **Must-reject vectors**: tampered data, kid mismatch, lower announce
   sequence, bad ratchet (wrong KEM, wrong kid, has a private key), not
   addressed to us, unknown sender, pre-quantum peer under the default policy,
   and a long-term-key message when ratchets are required. Extend
   `vectors.check()` to verify rejections.
9. [ ] **Byte-exact vectors** where the output is deterministic: Ed25519,
   HMAC, AEAD with a fixed IV, packet encodings, fragment splits with a fixed id.
10. [ ] **Live cross-implementation runner**: one script that drives a Python
    node against a JS or Arduino node over UDP/WebSocket (announce, message,
    receipt, rotation, path request). `examples/echo_client.py` is a start.
11. [ ] **Arduino porting note**: the X-Wing HPKE glue over wolfCrypt, the
    HPKE-0/-0-KE key-alg retag, the memory budget for PQ keys and signatures
    on ESP32, and storing the announce sequence and ratchets without an RTC.

### C. Library quality

12. [ ] Public API cleanup: decide what is public, docstrings, type hints,
    `py.typed`. Rename or explain `seal` vs `seal_each`; `Path.updated` is unused.
13. [ ] `keys._hpke_seal_aad` uses a *private* `cryptography` helper
    (`_encrypt_with_aad`). Pin the version range, and add a test that fails
    loudly if the helper goes away.
14. [ ] Test the RNode road on real hardware (so far only the emulator in
    `tests/test_roads.py`).
15. [ ] Several destinations per identity (Reticulum "aspects"), or several
    identities per node.
16. [ ] A human address format with a checksum, and a QR/share format for
    address plus keyset.
17. [ ] Packaging: versioning, a changelog, CI (tests + ruff + wolfCOSE
    checker), PyPI.

### D. Housekeeping

18. [ ] Create a GitHub remote (ask the user first), push `main`, and open
    PRs for feature branches.
