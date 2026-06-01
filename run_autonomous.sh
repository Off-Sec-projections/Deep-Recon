#!/usr/bin/env bash

set -euo pipefail

echo "Starting autonomous hunter setup..."

if [[ ! -d "venv" ]]; then
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q aiohttp requests python-dotenv

if [[ ! -f ".env" ]]; then
  echo "Missing .env file with required API credentials."
  exit 1
fi

python autonomous_auto_hunter.py "$@"
