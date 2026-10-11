#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -I"$ROOT/rtos/include" \
  "$ROOT/rtos/src/swoosh_gate.c" "$ROOT/rtos/tests/gate_tests.c" -o "$BUILD/gate-tests"
"$BUILD/gate-tests"
