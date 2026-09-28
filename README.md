# cosechat (Python reference)

Post-quantum mesh messaging in the spirit of
[Reticulum](https://github.com/markqvist/Reticulum) and
[LXMF](https://github.com/markqvist/LXMF), rebuilt from standards:
CBOR, COSE (Sign1 / Sign / Mac0 / Mac / Encrypt0 / Encrypt), COSE-HPKE with
X-Wing (ML-KEM-768 + X25519), and ML-DSA signatures.

This is the reference implementation and test oracle for the JS and Arduino
([wolfCOSE](https://www.wolfssl.com/products/wolfcose/)/wolfSSL) ports.
The wire format is in [SPEC.md](SPEC.md) (and as CDDL in [cosechat.cddl](cosechat.cddl)), how to
build another implementation is in [PORTING.md](PORTING.md), known limits are in [CAVEATS.md](CAVEATS.md),
and runnable examples (including a UDP echo bot) are in [examples/](examples/).

* An **address** is the hash of a public keyset. Announcing it tells the mesh
  "I can be reached on this road".
* Messages are **signed, then encrypted**. They are stored encrypted, and only
  the recipient's private key opens them.
* Routers forward messages **across different roads without reading them**.
  They see only the destination address.
* The **sender** is in the signed protected header, inside the encryption.
  Routers see neither the sender nor the full recipient list.
* **Identities only sign; messages go to ratchets.** An identity is its
  signing keys. Each node announces a post-quantum ratchet key (X-Wing) that
  messages are sealed to; rotating it gives forward secrecy (like Reticulum's
  ratchets, but required).
* **Small announces, sent rarely.** The keyset goes only in first-contact
  announces and path-request answers; paths last a week, like Reticulum.
  Sizes: SPEC §14, or `cosechat sizes`.
* **Storage is yours.** The library does no file I/O and trusts no dates: how
  keys are stored, encrypted at rest, rotated and deleted is the application's
  call. [examples/storage.py](examples/storage.py) shows a suggested practice.
* **Links** (sessions): one PQ handshake, then ~140-byte messages, with
  per-link forward secrecy. `await node.open_link(peer)`, then `send()` uses it.
* **Delivery receipts**: 24-byte proofs, resends until confirmed. `await node.delivered(m)`.
* **One recipient per message**, as in LXMF. Multi-recipient messages exist as an extra.
* **Quantum-safe by default.** The `pq` suite is the default, and nodes ignore non-PQ peers unless
  you opt out with `quantum_safe_only=False` / `--allow-prequantum`. See [CAVEATS.md](CAVEATS.md).

## Layout

```
src/cosechat/
  keys.py       COSE algorithms + COSE_Key (all crypto from pyca/cryptography)
  cose.py       Sign1, Sign, Mac0, Mac, Encrypt0, Encrypt (RFC 9052 structures)
  identity.py   keyset -> address, suites (pq / hybrid / prequantum)
  message.py    seal / unseal, announces
  contact.py    address text with a checksum, contact cards (cosechat: URIs)
  ratchet.py    ratchet keys (forward secrecy): mechanism only, no clocks
  link.py       sessions: PQ handshake, then symmetric messages
  packet.py     packets, fragmentation, road auth (Mac0 / Encrypt0 per frame)
  node.py       routing: announces, paths, via-forwarding, path requests, store & forward
  roads/        memory, udp, websocket, rnode (+ kiss), shared, wifi_raw, ble
  vectors.py    interop test vectors: generate + check
  cli.py        cosechat dev tool: keygen, info, vectors, check
interop/wolfcose/   C checker: runs the vectors through stock wolfCOSE
examples/           storage policy, chat, echo bot + client, mesh simulation, LoRa gateway
```

The data library (`keys`, `cose`, `identity`, `message`, `ratchet`, `link`, `packet`)
does no I/O. Roads know nothing about crypto. `Node` joins the two. Nothing
in the library stores keys or expires them by time.

Two roads sit on a *radio* rather than a socket, with no association and no
connection, like LoRa: `wifi_raw` (raw 802.11 action frames over AF_PACKET)
and `ble` (anonymous BLE extended advertising through BlueZ). Both are
Linux-only on a host, both are MTU-matched to the C reference so an ESP32 can
share the medium, and both expose their codec so another transport can carry
the same frames. For tests and simulation every road has an in-process
counterpart in `roads/memory.py`.

## Use

```sh
uv sync --all-extras
uv run pytest                      # the real-RNode test skips unless two are attached
uv run cosechat keygen -o me.key  # dev tool: new identity (plain keyset)
uv run cosechat info me.key
uv run cosechat sizes             # measured wire sizes
uv run cosechat constants         # every constant and default
uv run examples/chat.py --name alice --udp 4242
uv run examples/chat.py --lock --udp 4242           # passphrase-encrypt keys at rest
uv run examples/chat.py --ws-server 4243 --transport  # a hub for browsers
uv run examples/chat.py --ws                          # join the web example's room
uv run examples/chat.py --rnode /dev/ttyUSB0 --freq 868000000 --sf 8
uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 868000000       # LoRa <-> the web room
uv run examples/echo_bot.py --rnode /dev/ttyACM0 --freq 868000000   # a bot on LoRa
```

In the chat, `@<address prefix> text` sends, a bare line replies, and
`/peers`, `/announce`, `/rotate` and `/quit` do what they say.

```python
import asyncio
from cosechat import Identity, Node
from cosechat.roads.udp import UDPRoad

async def main():
  node = Node(Identity.generate('pq'), app_data={'name': 'alice'})
  node.add_road(UDPRoad(('0.0.0.0', 4242)))
  node.on_message(lambda m: print(m.sender.hex(), m.content))
  async with node:
    await node.announce()
    await asyncio.sleep(3600)

asyncio.run(main())
```

The data library works on its own:

```python
from cosechat import Identity, message
from cosechat.ratchet import MemoryRatchets

alice, bob = Identity.generate(), Identity.generate()
bobs_ratchets = MemoryRatchets(bob.kem_alg)            # bob announces .current()
announce = message.make_announce(bob, bobs_ratchets.current())
ratchet = message.verify_announce(announce, bob.address).ratchet

sealed, sent = message.seal(alice, [bob.public()], 'hi bob', ratchets={bob.address: ratchet})
got = message.unseal(bob, sealed, {alice.address: alice.public()}.get, ratchets=bobs_ratchets)
```

## Testing other implementations

```sh
uv run cosechat vectors -o vectors.json   # what other implementations must accept
uv run cosechat check their-vectors.json  # check what they produce
uv run interop/live.py <bot address> --udp HOST:PORT --udp-peer HOST:PORT   # live checks vs an echo bot
cd interop/wolfcose && make test WOLFSSL_PREFIX=... WOLFCOSE_DIR=...
```

The COSE layer is also cross-checked against
[pycose](https://github.com/TimothyClaeys/pycose) and
[python-cwt](https://github.com/dajiaji/python-cwt) (`tests/test_interop.py`),
and X-Wing against the draft's test vector.

## Formatting

2-space indent, single quotes (StandardJS-flavored), via ruff:
`uv run ruff format && uv run ruff check`.
