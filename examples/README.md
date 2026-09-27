# Examples

Run from the repo root with `uv run`.

| example | what it shows | needs |
|---|---|---|
| [storage.py](storage.py) | **suggested storage practice**: key files (0600, atomic), passphrase encryption at rest, ratchet rotation/retention by the local clock | nothing |
| [chat.py](chat.py) | interactive node on any roads, keys kept with storage.py | any road |
| [mesh_sim.py](mesh_sim.py) | a 5-node mesh in one process: routing across three roads (one LoRa-sized), routers that can't read, prequantum peers shut out | nothing |
| [echo_bot.py](echo_bot.py) | a UDP bot that echoes every message back and announces itself periodically | UDP |
| [echo_client.py](echo_client.py) | pings an echo bot and checks the replies; exits non-zero on failure | UDP |
| [lora_gateway.py](lora_gateway.py) | bridges an RNode radio and LAN UDP, with store and forward | an RNode |

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
