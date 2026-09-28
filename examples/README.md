# Examples

Run from the repo root with `uv run`.

| example | what it shows | needs |
|---|---|---|
| [storage.py](storage.py) | **suggested storage practice**: key files (0600, atomic), passphrase encryption at rest, ratchet rotation/retention by the local clock | nothing |
| [room.py](room.py) | the shared broadcast room (`signal-worker`) every WebSocket example defaults to | nothing |
| [chat.py](chat.py) | interactive node on any roads, keys kept with storage.py | any road |
| [mesh_sim.py](mesh_sim.py) | a 5-node mesh in one process: routing across three roads (one LoRa-sized), routers that can't read, prequantum peers shut out | nothing |
| [echo_bot.py](echo_bot.py) | a bot that echoes every message back and announces itself periodically; on UDP or an RNode | UDP or a radio |
| [echo_client.py](echo_client.py) | pings an echo bot and checks the replies; exits non-zero on failure | a bot |
| [lora_gateway.py](lora_gateway.py) | bridges an RNode radio and the WebSocket room (or LAN UDP), with store and forward | an RNode |

## LoRa in a browser

`lora_gateway.py` is a transport node: one RNode on a serial port, and the
WebSocket room the [web example](../../cosechat-js/examples/web) joins. A
browser page and the LoRa mesh then see each other, because a transport node
forwards announces and messages between its roads.

With two RNodes (one for the gateway, one for the bot) and the browser:

```sh
# 1. the bridge, on the machine with internet (defaults to the web example's room)
uv run examples/lora_gateway.py /dev/ttyUSB0 --freq 915000000 --announce-cap 0
# 2. wait ~20 s for the gateway's first announce to leave the air, then start bob
#    (--rnode with no --listen opens the radio only, so this can be a LoRa-only device)
uv run examples/echo_bot.py --rnode /dev/ttyACM0 --freq 915000000 --announce-cap 0
#    it prints its address
# 3. alice: cd cosechat-js && npm start, open http://localhost:8080, and chat with bob
```

All nodes that share the radio need the same frequency, bandwidth, SF and CR.
`--announce-cap 0` turns off the LoRa announce airtime budget (SPEC §9.0) so
every announce really goes out instead of queueing for minutes — convenient on
a quiet test channel, and antisocial on a busy one (leave it at the default
0.02 for a real mesh).

One more radio fact worth knowing: a LoRa radio cannot receive while it
transmits, and a full announce is ~18 s of air at SF8. Two nodes that announce
at the same moment are deaf to each other's fragments *and* to each other's
fragment NACKs, so nothing reassembles — that is why the gateway gets a head
start above. [CAVEATS.md](../CAVEATS.md) has the details.

A *sealed* message is ~10 fragments on LoRa too, and one lost fragment costs
the whole message, so chat over a **link**: after the handshake each message is
one frame. `chat.py` opens one when you message someone, and the web example
opens one when you pick a peer; the echo bot answers over it automatically.

`tests/test_bridge.py` runs this whole path in-process: the gateway and the
bot are built by the examples, the radio is an emulated RNode, and the room is
a local WebSocket server.

## Echo bot

```sh
uv run examples/echo_bot.py                        # prints its address
uv run examples/echo_client.py <address>           # on the same LAN
```

Both default to UDP broadcast on port 4242. For unicast, or two processes on
one machine without broadcast, point them at each other:

```sh
uv run examples/echo_bot.py --listen 127.0.0.1:47001 --peer 127.0.0.1:47002
uv run examples/echo_client.py <address> --listen 127.0.0.1:47002 --peer 127.0.0.1:47001
```

`echo_client.py` is a handy conformance check: point it at a bot written in
another implementation (JS, Arduino) and it reports whether every message came
back intact, including a `fields` map.
