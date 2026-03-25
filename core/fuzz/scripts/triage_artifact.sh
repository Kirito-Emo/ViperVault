#!/usr/bin/env bash
set -uo pipefail

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Emanuele Relmi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS_ROOT="${ROOT_DIR}/artifacts"
OUT_ROOT="${ROOT_DIR}/triage"
SEED_ROOT="${ROOT_DIR}/corpus_seed"

mkdir -p "${OUT_ROOT}"

usage() {
  echo "Usage:"
  echo "  ./scripts/triage_artifact.sh"
  echo "  ./scripts/triage_artifact.sh <target>"
  echo "  ./scripts/triage_artifact.sh <target> <artifact_path>"
}

safe_basename() {
  local path="$1"
  basename "${path}" | tr -c 'A-Za-z0-9._-' '_'
}

triage_one() {
  local target="$1"
  local artifact="$2"

  local stamp
  local artifact_name
  local out_dir
  local repro_log
  local tmin_log
  local work_artifact
  local minimized_artifact
  local repro_exit
  local tmin_exit

  stamp="$(date +%F_%H-%M-%S)"
  artifact_name="$(safe_basename "${artifact}")"
  out_dir="${OUT_ROOT}/${target}_${stamp}_${artifact_name}"
  mkdir -p "${out_dir}"

  work_artifact="${out_dir}/artifact_original.bin"
  minimized_artifact="${out_dir}/artifact_minimized.bin"
  cp -f "${artifact}" "${work_artifact}"
  cp -f "${artifact}" "${minimized_artifact}"

  repro_log="${out_dir}/repro.log"
  tmin_log="${out_dir}/tmin.log"

  echo "== Reproducing target=${target}"
  echo "== Artifact=${artifact}"

  ASAN_OPTIONS=detect_leaks=0 \
  LSAN_OPTIONS=detect_leaks=0 \
  cargo +nightly fuzz run "${target}" "${work_artifact}" \
    2>&1 | tee "${repro_log}"
  repro_exit=${PIPESTATUS[0]}

  echo "== Minimizing testcase copy"

  ASAN_OPTIONS=detect_leaks=0 \
  LSAN_OPTIONS=detect_leaks=0 \
  cargo +nightly fuzz tmin "${target}" "${minimized_artifact}" \
    2>&1 | tee "${tmin_log}"
  tmin_exit=${PIPESTATUS[0]}

  {
    echo "# Fuzz triage report"
    echo
    echo "## Metadata"
    echo
    echo "- Target: \`${target}\`"
    echo "- Original artifact: \`${artifact}\`"
    echo "- Repro exit code: \`${repro_exit}\`"
    echo "- Tmin exit code: \`${tmin_exit}\`"
    echo
    echo "## Local files"
    echo
    echo "- Original copy: \`${work_artifact}\`"
    echo "- Minimized copy: \`${minimized_artifact}\`"
    echo "- Repro log: \`${repro_log}\`"
    echo "- Tmin log: \`${tmin_log}\`"
    echo
    echo "## Reproduce command"
    echo
    echo '```bash'
    echo "ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run ${target} ${work_artifact}"
    echo '```'
    echo
    echo "## Minimize command"
    echo
    echo '```bash'
    echo "ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz tmin ${target} ${minimized_artifact}"
    echo '```'
    echo
    echo "## Suggested regression-seed promotion"
    echo
    echo '```bash'
    echo "cp -n ${minimized_artifact} ${SEED_ROOT}/${target}/regression_${artifact_name}"
    echo '```'
  } > "${out_dir}/report.md"

  echo "Report written to ${out_dir}/report.md"
}

triage_target_dir() {
  local target="$1"
  local target_dir="${ARTIFACTS_ROOT}/${target}"
  local found=0

  if [[ ! -d "${target_dir}" ]]; then
    echo "Target artifacts directory does not exist: ${target_dir}"
    return 1
  fi

  for artifact in "${target_dir}"/*; do
    [[ -f "${artifact}" ]] || continue
    found=1
    triage_one "${target}" "${artifact}"
  done

  if [[ ${found} -eq 0 ]]; then
    echo "No artifacts found for target ${target}"
  fi
}

main() {
  local target="${1:-}"
  local artifact="${2:-}"
  local found=0

  if [[ -n "${target}" && -n "${artifact}" ]]; then
    if [[ ! -f "${artifact}" ]]; then
      echo "Artifact does not exist: ${artifact}"
      exit 1
    fi
    triage_one "${target}" "${artifact}"
    exit 0
  fi

  if [[ -n "${target}" ]]; then
    triage_target_dir "${target}"
    exit 0
  fi

  for target_dir in "${ARTIFACTS_ROOT}"/*; do
    [[ -d "${target_dir}" ]] || continue
    found=1
    target_name="$(basename "${target_dir}")"
    triage_target_dir "${target_name}"
  done

  if [[ ${found} -eq 0 ]]; then
    echo "No artifact directories found under ${ARTIFACTS_ROOT}"
  fi
}

main "$@"