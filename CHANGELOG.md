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
* Roads: memory, UDP, WebSocket, RNode (KISS), shared. A WebSocket server
  road is one shared medium (clients hear each other), as SPEC §10 says.
* Contact cards and address text.
* Interop: vectors (accept, reject, exact), CDDL, live conformance runner.
