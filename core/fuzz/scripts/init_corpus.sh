#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Emanuele Relmi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p \
  "${ROOT_DIR}/fuzz_targets" \
  "${ROOT_DIR}/corpus_seed" \
  "${ROOT_DIR}/corpus" \
  "${ROOT_DIR}/artifacts" \
  "${ROOT_DIR}/coverage" \
  "${ROOT_DIR}/logs" \
  "${ROOT_DIR}/examples" \
  "${ROOT_DIR}/scripts"

cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" --example generate_seed_corpus