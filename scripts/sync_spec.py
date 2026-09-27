"""
Refresh the generated parts of SPEC.md from the code:

  §14 sizes      <!-- sizes -->      cosiechat sizes
  §15 CDDL       <!-- cddl -->       cosiechat.cddl
  §16 constants  <!-- constants -->  cosiechat constants

  uv run python scripts/sync_spec.py

The tests fail when these are stale, so run this after changing any of them.
"""

from pathlib import Path

from cosiechat import constants, sizes

ROOT = Path(__file__).resolve().parents[1]


def replace(text: str, marker: str, body: str) -> str:
  start = f'<!-- {marker} -->\n'
  end = f'\n<!-- /{marker} -->'
  i = text.index(start) + len(start)
  j = text.index(end, i)
  return text[:i] + body + text[j:]


def main():
  spec = ROOT / 'SPEC.md'
  text = spec.read_text()
  text = replace(text, 'sizes', sizes.table())
  cddl = (ROOT / 'cosiechat.cddl').read_text().rstrip('\n')
  text = replace(text, 'cddl', f'```cddl\n{cddl}\n```')
  text = replace(text, 'constants', constants.table())
  spec.write_text(text)
  print('SPEC.md generated sections refreshed')


if __name__ == '__main__':
  main()
