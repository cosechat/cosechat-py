"""The examples keep working: mesh_sim in-process, echo bot + client as real processes over UDP."""

import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cosechat import Identity
from cosechat.keys import HPKE_9

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'
sys.path.insert(0, str(EXAMPLES))
import storage  # noqa: E402


def test_mesh_sim():
  out = subprocess.run(
    [sys.executable, EXAMPLES / 'mesh_sim.py'], capture_output=True, text=True, timeout=60
  )
  assert out.returncode == 0, out.stderr
  assert "bob got 'hello across three roads'" in out.stdout
  assert 'read a message' not in out.stdout
  assert 'bob knows mallory: False' in out.stdout


def test_udp_echo_bot_roundtrip(tmp_path):
  ident = tmp_path / 'bot'
  bot_addr = storage.load_identity(ident).address.hex()
  bot = subprocess.Popen(
    [sys.executable, EXAMPLES / 'echo_bot.py', '--identity', ident, '--interval', '2',
     '--listen', '127.0.0.1:47201', '--peer', '127.0.0.1:47202'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
  )  # fmt: skip
  try:
    time.sleep(1.5)
    client = subprocess.run(
      [sys.executable, EXAMPLES / 'echo_client.py', bot_addr, '--count', '2',
       '--listen', '127.0.0.1:47202', '--peer', '127.0.0.1:47201'],
      capture_output=True, text=True, timeout=60, cwd=EXAMPLES,
    )  # fmt: skip
  finally:
    bot.terminate()
    log = bot.communicate(timeout=10)[0]
  assert client.returncode == 0, client.stdout + client.stderr + log
  assert 'all echoes ok' in client.stdout
  assert 'ping 0' in log


# --- examples/storage.py: the suggested storage policy ---


class Clock:
  t = 1_000_000.0

  def __call__(self):
    return self.t


def test_storage_ratchet_policy_uses_local_clock(tmp_path):
  clock = Clock()
  path = tmp_path / 'r'
  rs = storage.FileRatchets(HPKE_9, path, rotate_every=60, keep_for=300, clock=clock)
  assert rs.maintain()  # first ratchet
  first = rs.current()
  clock.t += 59
  assert not rs.maintain() and rs.current() is first
  clock.t += 2
  assert rs.maintain() and rs.current() is not first
  assert stat.S_IMODE(path.stat().st_mode) == 0o600
  again = storage.FileRatchets(HPKE_9, path, clock=clock)
  assert again.get(first.kid).priv == first.priv
  clock.t += 300
  rs.maintain()
  assert rs.get(first.kid) is None
  assert storage.FileRatchets(HPKE_9, path, clock=clock).get(first.kid) is None


def test_storage_encrypts_keys_at_rest(tmp_path):
  path = tmp_path / 'id'
  ident = storage.load_identity(path, passphrase='hunter2')
  raw = path.read_bytes()
  assert ident.to_bytes() not in raw and ident.public_bytes not in raw
  assert storage.load_identity(path, passphrase='hunter2') == ident
  with pytest.raises(PermissionError):
    storage.load_identity(path)
  with pytest.raises(PermissionError):
    storage.load_identity(path, passphrase='wrong')
  plain = storage.load_identity(tmp_path / 'plain')
  assert Identity.from_bytes((tmp_path / 'plain').read_bytes()) == plain


def test_chat_example_starts():
  out = subprocess.run(
    [sys.executable, EXAMPLES / 'chat.py', '--help'], capture_output=True, text=True, timeout=30
  )
  assert out.returncode == 0 and '--lock' in out.stdout


def test_file_store_survives_a_propagation_node_restart(tmp_path):
  from test_node import inbox, make, run, until

  from cosechat.node import Node
  from cosechat.roads.memory import MemoryHub

  async def main():
    hub = MemoryHub()
    a, b = make(hub), make(hub)
    box = inbox(b)
    async with a:
      async with b:
        await a.announce()
        await b.announce()
        await until(lambda: a.peer_ratchet(b.address) and b.path(a.address))
      # b is offline; a propagation node with files comes up, takes the message, restarts
      prop = Node(propagate=True, rebroadcast_delay=0.01, store=storage.FileStore(tmp_path / 's'))
      prop.add_road(hub.road())
      async with prop:
        await a.send(b.address, 'kept on disk', receipt=False)
        await until(lambda: b.address in prop.store)
      prop2 = Node(propagate=True, rebroadcast_delay=0.01, store=storage.FileStore(tmp_path / 's'))
      prop2.add_road(hub.road())
      async with prop2, b:
        await b.announce()
        await until(lambda: box)
    assert box[0].content == 'kept on disk'
    assert not any((tmp_path / 's').rglob('*-*'))  # handed over and deleted

  run(main())


def test_file_store_policy(tmp_path):
  class Clock:
    t = 1_000_000.0

    def __call__(self):
      return self.t

  clock = Clock()
  st = storage.FileStore(tmp_path, per_dest=2, keep_for=100, clock=clock)
  dest = b'\x01' * 16
  assert st.put(dest, 1, b'a') and st.put(dest, 1, b'b')
  assert not st.put(dest, 1, b'c')  # full
  clock.t += 101
  st.maintain()
  assert st.take(dest) == []
  assert st.put(dest, 1, b'd') and st.take(dest) == [(1, b'd')]


def test_live_runner_passes_against_the_reference_bot(tmp_path):
  ident = tmp_path / 'bot'
  bot_addr = storage.load_identity(ident).address.hex()
  bot = subprocess.Popen(
    [sys.executable, EXAMPLES / 'echo_bot.py', '--identity', ident, '--interval', '60',
     '--listen', '127.0.0.1:47601', '--peer', '127.0.0.1:47602'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
  )  # fmt: skip
  try:
    time.sleep(1.5)
    run = subprocess.run(
      [sys.executable, EXAMPLES.parent / 'interop' / 'live.py', bot_addr, '--timeout', '10',
       '--udp', '127.0.0.1:47602', '--udp-peer', '127.0.0.1:47601'],
      capture_output=True, text=True, timeout=120,
    )  # fmt: skip
  finally:
    bot.terminate()
    bot.communicate(timeout=10)
  assert run.returncode == 0, run.stdout + run.stderr
  assert '6/6 checks passed' in run.stdout
