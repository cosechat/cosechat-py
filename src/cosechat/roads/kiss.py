"""KISS framing (as used by RNode firmware): FEND cmd data FEND, with FESC escaping."""

FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD


def escape(data: bytes) -> bytes:
  return data.replace(bytes([FESC]), bytes([FESC, TFESC])).replace(
    bytes([FEND]), bytes([FESC, TFEND])
  )


def unescape(data: bytes) -> bytes:
  out = bytearray()
  esc = False
  for b in data:
    if esc:
      out.append(FEND if b == TFEND else FESC if b == TFESC else b)
      esc = False
    elif b == FESC:
      esc = True
    else:
      out.append(b)
  return bytes(out)


def frame(cmd: int, data: bytes = b'') -> bytes:
  return bytes([FEND, cmd]) + escape(data) + bytes([FEND])


class Decoder:
  """Feed raw serial bytes, get back complete (cmd, data) frames."""

  def __init__(self, max_size: int = 4096):
    self.max_size = max_size
    self._buf = bytearray()
    self._in_frame = False

  def feed(self, data: bytes) -> list[tuple[int, bytes]]:
    out = []
    for b in data:
      if b == FEND:
        if self._in_frame and self._buf:
          body = unescape(bytes(self._buf))
          out.append((body[0], body[1:]))
        self._buf.clear()
        self._in_frame = True
      elif self._in_frame:
        if len(self._buf) < self.max_size:
          self._buf.append(b)
        else:
          self._buf.clear()
          self._in_frame = False
    return out
