#!/bin/sh
# Everything that must pass before a commit: lint, format, tests.
set -e
cd "$(dirname "$0")/.."
.venv/bin/ruff check src tests examples interop scripts
.venv/bin/ruff format --check src tests examples interop scripts
.venv/bin/python -m pytest -q
