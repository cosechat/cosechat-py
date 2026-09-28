"""
keys._hpke_seal_aad / _hpke_open_aad lean on a private cryptography helper,
because COSE-HPKE integrated mode (Encrypt0) needs HPKE's `aad` input and the
public API does not expose it yet. If this test fails after a cryptography
upgrade, the helper moved: switch to the public API if one exists now, or
adapt keys.py, and only then raise the version bound in pyproject.toml.
"""

from cryptography.hazmat.bindings._rust import openssl as rust

from cosechat import cose
from cosechat import keys as K


def test_private_hpke_aad_helpers_exist():
  assert hasattr(rust.hpke, '_encrypt_with_aad'), 'cryptography removed _encrypt_with_aad'
  assert hasattr(rust.hpke, '_decrypt_with_aad'), 'cryptography removed _decrypt_with_aad'


def test_aad_is_really_bound():
  k = K.Key.generate(K.HPKE_9)
  sealed = cose.encrypt0(b'x', k.public(), external_aad=b'one')
  assert cose.decrypt0(sealed, k, external_aad=b'one') == b'x'
  try:
    cose.decrypt0(sealed, k, external_aad=b'two')
  except K.CoseError:
    return
  raise AssertionError('HPKE aad was ignored')
