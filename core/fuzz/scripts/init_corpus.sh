#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Emanuele Relmi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p \
  "${ROOT_DIR}/fuzz_targets" \
  "${ROOT_DIR}/corpus_seed" \
  "${ROOT_DIR}/corpus" \
  "${ROOT_DIR}/corpus_min" \
  "${ROOT_DIR}/artifacts" \
  "${ROOT_DIR}/coverage" \
  "${ROOT_DIR}/logs" \
  "${ROOT_DIR}/examples" \
  "${ROOT_DIR}/scripts"

cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" --example generate_seed_corpus

while IFS= read -r -d '' target_dir; do
  target="$(basename "${target_dir}")"
  mkdir -p "${ROOT_DIR}/corpus/${target}"
  find "${target_dir}" -maxdepth 1 -type f -exec cp -n {} "${ROOT_DIR}/corpus/${target}/" \;
done < <(find "${ROOT_DIR}/corpus_seed" -mindepth 1 -maxdepth 1 -type d -print0)