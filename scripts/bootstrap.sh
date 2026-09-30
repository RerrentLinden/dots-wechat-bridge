#!/bin/sh
# Local dependency setup only. No credentials, network policy or services are changed.
set -eu
cd "$(dirname "$0")/.."
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m unittest discover -s probe_tests
.venv/bin/python scripts/generate-schema.py --check
