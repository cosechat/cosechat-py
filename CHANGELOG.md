# Changelog

## 0.1.0 (unreleased)

First version of the Python reference implementation. Protocol version 0
(draft; see SPEC.md §19).

* COSE Sign1/Sign/Mac0/Mac/Encrypt0/Encrypt on pyca/cryptography, checked
  against pycose, python-cwt and stock wolfCOSE.
* Signing-only identities (ML-DSA-65 by default), ratchets (X-Wing), sealed
  messages with 24-byte receipts, full/short announces with keyset fetch.
* Routing: announce budget, path requests and expiry, fewer hops, dead path
  recovery, ingress limits; fragments with resume (NACK).
* Links, resources (large transfers), propagation nodes (deposit/fetch).
* Roads: memory, UDP, WebSocket, RNode (KISS), shared, wifi_raw (802.11
  action frames), ble (BLE advertising). A WebSocket server road is one
  shared medium (clients hear each other), as SPEC §10 says.
* Real RNodes over the air: `tests/test_rnode_hardware.py` runs two nodes'
  announce, message and receipt exchange when two serial RNodes are attached
  (skipped otherwise). The RNode handshake retries the detect and config steps,
  since opening the port resets the device.
* Anonymous broadcast roads: `RawWifiRoad` (raw 802.11 action frames, Linux
  AF_PACKET) and `BLERoad` (anonymous BLE extended advertising). BLE TX and RX
  both go through BlueZ over D-Bus (`dbus-fast`/`dbus-next`); the road needs an
  adapter that supports extended advertising, and the path is tested against a
  fake D-Bus (`tests/test_ble_bluez.py`). Codec functions are always
  available; for tests use `MemoryHub`.
* Announces on a half-duplex radio: a full announce is ~18 s of air at SF8 and
  a radio cannot hear while it transmits, so two nodes announcing at once are
  deaf to each other's fragments and NACKs. Documented in CAVEATS, and the
  hardware test now announces one side at a time with no announce budget.
* Examples: `lora_gateway.py` bridges an RNode radio and the shared
  WebSocket room (`room.py`, the one the web example uses) or LAN UDP;
  `echo_bot.py` runs on an RNode (`--rnode`); `chat.py --ws` joins the room.
* Contact cards and address text.
* Interop: vectors (accept, reject, exact), CDDL, live conformance runner.
