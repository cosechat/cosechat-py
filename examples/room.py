"""
The broadcast room the web example (`cosechat-js/examples/web`) joins.

[signal-worker](https://github.com/konsumer/signal-worker) is a Cloudflare
worker that repeats every WebSocket frame to everyone else in the room, so it
is one shared medium, like a LAN. Every cosechat example that talks over a
WebSocket room defaults to this URL, so a gateway, a bot and a browser page
meet in the same place without any configuration.
"""

ROOM = 'wss://signal.konsumer.workers.dev/ws/cosechat'
