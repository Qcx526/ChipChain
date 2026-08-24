#!/usr/bin/env sh
set -eu

# Canonical generation uses audited machine words and requires no cross compiler.
python3 "$(dirname "$0")/generate_fixture.py"
