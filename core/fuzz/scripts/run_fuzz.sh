#!/usr/bin/env bash
set -uo pipefail

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Emanuele Relmi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p \
  "${ROOT_DIR}/logs" \
  "${ROOT_DIR}/corpus" \
  "${ROOT_DIR}/corpus_min" \
  "${ROOT_DIR}/artifacts" \
  "${ROOT_DIR}/dictionaries"

targets=(
  decode_vault_file
  decode_signed_backup
  parse_totp_otpauth_uri
  decode_base32_secret_strict
  import_interop_quarantine
  canonicalize_base32_for_export
  vault_codec_roundtrip
  enable_duress_on_vault
  otpauth_roundtrip
)

default_fuzz_seconds=10

declare -A run_results
declare -A min_results
declare -A artifact_counts
declare -A min_before_counts
declare -A min_after_counts
declare -A min_reduction_pct

prepare_runtime_corpus() {
  local target="$1"
  local seed_dir="${ROOT_DIR}/corpus_seed/${target}"
  local min_dir="${ROOT_DIR}/corpus_min/${target}"
  local runtime_dir="${ROOT_DIR}/corpus/${target}"

  rm -rf "${runtime_dir}"
  mkdir -p "${runtime_dir}"

  if [[ -d "${min_dir}" ]]; then
    echo "Seeding ${target} from corpus_min"
    find "${min_dir}" -maxdepth 1 -type f -exec cp -n {} "${runtime_dir}/" \;
  fi

  if [[ -d "${seed_dir}" ]]; then
    echo "Merging curated seeds for ${target}"
    find "${seed_dir}" -maxdepth 1 -type f -exec cp -n {} "${runtime_dir}/" \;
  fi
}

dictionary_for_target() {
  local target="$1"

  case "${target}" in
    decode_vault_file|decode_signed_backup|vault_codec_roundtrip|enable_duress_on_vault)
      echo "${ROOT_DIR}/dictionaries/vault.dict"
      ;;
    parse_totp_otpauth_uri|import_interop_quarantine|otpauth_roundtrip)
      echo "${ROOT_DIR}/dictionaries/otpauth.dict"
      ;;
    *)
      echo ""
      ;;
  esac
}

count_files_in_dir() {
  local dir="$1"

  if [[ -d "${dir}" ]]; then
    find "${dir}" -maxdepth 1 -type f | wc -l | tr -d '[:space:]'
  else
    echo "0"
  fi
}

count_artifacts_for_target() {
  local target="$1"
  count_files_in_dir "${ROOT_DIR}/artifacts/${target}"
}

pick_min_source_dir() {
  local target="$1"
  local runtime_dir="${ROOT_DIR}/corpus/${target}"
  local min_dir="${ROOT_DIR}/corpus_min/${target}"
  local seed_dir="${ROOT_DIR}/corpus_seed/${target}"

  if [[ -d "${runtime_dir}" ]] && find "${runtime_dir}" -maxdepth 1 -type f | read -r; then
    echo "${runtime_dir}"
    return 0
  fi

  if [[ -d "${min_dir}" ]] && find "${min_dir}" -maxdepth 1 -type f | read -r; then
    echo "${min_dir}"
    return 0
  fi

  if [[ -d "${seed_dir}" ]] && find "${seed_dir}" -maxdepth 1 -type f | read -r; then
    echo "${seed_dir}"
    return 0
  fi

  echo ""
}

compute_reduction_pct() {
  local before="$1"
  local after="$2"

  if [[ "${before}" -eq 0 ]]; then
    echo "0"
    return 0
  fi

  awk -v b="${before}" -v a="${after}" 'BEGIN { printf "%.1f", ((b-a)/b)*100 }'
}

run_target() {
  local target="$1"
  local seconds="$2"

  local timestamp
  local dict_file
  local log_file
  local artifact_dir
  local exit_code
  local -a fuzz_args

  timestamp="$(date +%F_%H-%M-%S)"
  dict_file="$(dictionary_for_target "${target}")"
  log_file="${ROOT_DIR}/logs/${target}_${timestamp}.log"
  artifact_dir="${ROOT_DIR}/artifacts/${target}"

  prepare_runtime_corpus "${target}"
  mkdir -p "${artifact_dir}"

  fuzz_args=(
    -max_total_time="${seconds}"
    -artifact_prefix="${artifact_dir}/"
    -detect_leaks=0
  )

  if [[ -n "${dict_file}" && -f "${dict_file}" ]]; then
    fuzz_args+=(-dict="${dict_file}")
  fi

  echo "Running fuzz target: ${target} (${seconds}s)"
  echo "Artifacts directory: ${artifact_dir}"
  echo "Log file: ${log_file}"
  echo "Leak detection: disabled"

  ASAN_OPTIONS=detect_leaks=0 \
  LSAN_OPTIONS=detect_leaks=0 \
  cargo +nightly fuzz run \
    "${target}" \
    "${ROOT_DIR}/corpus/${target}" \
    -- \
    "${fuzz_args[@]}" \
    2>&1 | tee "${log_file}"

  exit_code=${PIPESTATUS[0]}

  artifact_counts["${target}"]="$(count_artifacts_for_target "${target}")"

  if [[ ${exit_code} -eq 0 ]]; then
    run_results["${target}"]="OK"
  else
    run_results["${target}"]="FAIL (${exit_code})"
  fi

  return 0
}

minimize_target() {
  local target="$1"
  local timestamp
  local log_file
  local src_dir
  local dst_dir
  local tmp_dir
  local exit_code
  local before_count
  local after_count
  local reduction

  timestamp="$(date +%F_%H-%M-%S)"
  log_file="${ROOT_DIR}/logs/${target}_cmin_${timestamp}.log"
  dst_dir="${ROOT_DIR}/corpus_min/${target}"
  src_dir="$(pick_min_source_dir "${target}")"

  if [[ -z "${src_dir}" ]]; then
    echo "No corpus available for ${target}; skipping minimization"
    min_results["${target}"]="NO CORPUS"
    min_before_counts["${target}"]="0"
    min_after_counts["${target}"]="0"
    min_reduction_pct["${target}"]="0.0"
    return 0
  fi

  tmp_dir="$(mktemp -d "${ROOT_DIR}/corpus_min/.${target}.tmp.XXXXXX")"

  echo "Minimizing corpus for ${target}"
  echo "Source corpus: ${src_dir}"
  echo "Temporary corpus: ${tmp_dir}"
  echo "Log file: ${log_file}"

  find "${src_dir}" -maxdepth 1 -type f -exec cp -n {} "${tmp_dir}/" \;

  before_count="$(count_files_in_dir "${tmp_dir}")"
  min_before_counts["${target}"]="${before_count}"

  ASAN_OPTIONS=detect_leaks=0 \
  LSAN_OPTIONS=detect_leaks=0 \
  cargo +nightly fuzz cmin \
    "${target}" \
    "${tmp_dir}" \
    2>&1 | tee "${log_file}"

  exit_code=${PIPESTATUS[0]}
  after_count="$(count_files_in_dir "${tmp_dir}")"
  min_after_counts["${target}"]="${after_count}"
  reduction="$(compute_reduction_pct "${before_count}" "${after_count}")"
  min_reduction_pct["${target}"]="${reduction}"

  if [[ ${exit_code} -eq 0 ]]; then
    rm -rf "${dst_dir}"
    mkdir -p "${dst_dir}"
    find "${tmp_dir}" -maxdepth 1 -type f -exec cp -f {} "${dst_dir}/" \;
    min_results["${target}"]="OK"
    echo "Corpus minimization completed for ${target}: ${before_count} -> ${after_count} files (${reduction}% reduction)"
  else
    min_results["${target}"]="FAIL (${exit_code})"
    echo "Corpus minimization failed for ${target} with exit code ${exit_code}"
  fi

  rm -rf "${tmp_dir}"
  return 0
}

run_all() {
  local seconds="$1"

  for target in "${targets[@]}"; do
    run_target "${target}" "${seconds}"

    if [[ "${run_results[$target]}" == "OK" ]]; then
      minimize_target "${target}"
    else
      echo "Skipping corpus minimization for ${target} due to fuzz failure"
      min_results["${target}"]="SKIPPED"
      min_before_counts["${target}"]="0"
      min_after_counts["${target}"]="0"
      min_reduction_pct["${target}"]="0.0"
    fi
  done
}

min_all() {
  for target in "${targets[@]}"; do
    minimize_target "${target}"
  done
}

summary() {
  echo
  echo "================================== FUZZ SUMMARY =================================="
  printf "%-32s %-12s %-12s %-10s %-10s %-10s %-10s\n" \
    "Target" "Run" "Min" "Artifacts" "Before" "After" "Reduction"

  for target in "${targets[@]}"; do
    printf "%-32s %-12s %-12s %-10s %-10s %-10s %-10s\n" \
      "${target}" \
      "${run_results[$target]:-SKIPPED}" \
      "${min_results[$target]:-SKIPPED}" \
      "${artifact_counts[$target]:-0}" \
      "${min_before_counts[$target]:-0}" \
      "${min_after_counts[$target]:-0}" \
      "${min_reduction_pct[$target]:-0.0}%"
  done

  echo "=================================================================================="
}

mode="${1:-all}"
seconds="${2:-$default_fuzz_seconds}"

case "${mode}" in
  run)
    for target in "${targets[@]}"; do
      run_target "${target}" "${seconds}"
      min_results["${target}"]="SKIPPED"
      min_before_counts["${target}"]="0"
      min_after_counts["${target}"]="0"
      min_reduction_pct["${target}"]="0.0"
    done
    ;;
  min)
    min_all
    ;;
  all)
    run_all "${seconds}"
    ;;
  *)
    echo "Usage:"
    echo "  ./scripts/run_fuzz.sh run [seconds]"
    echo "  ./scripts/run_fuzz.sh min"
    echo "  ./scripts/run_fuzz.sh all [seconds]"
    exit 1
    ;;
esac

summary