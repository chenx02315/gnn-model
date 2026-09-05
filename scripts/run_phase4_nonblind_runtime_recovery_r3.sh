#!/usr/bin/env bash
# Rebuild the non-blind Phase4 runtime recovery after adding the unique F/H
# full-boundary logs. This script writes only versioned r3 artifacts.

set -euo pipefail

evidence_root=/temp/jiangchuanc/multimode_ate_phase4_20260825_A
recovery_root=/temp/jiangchuanc/multimode_atpg_runtime_recovery_v1/phase4_nonblind_v2_r1
tools_dir="$recovery_root/tools_r3"
inventory_dir="$recovery_root/inventory_r3"
attempt_dir="$recovery_root/attempts_r3"
join_dir="$recovery_root/joins_r3"
summary_dir="$recovery_root/summaries_r3"
split_contract="$tools_dir/data_split_v1.json"

circuits=(b20 b21 b22 aes_core spi tv80)

role_and_family() {
  case "$1" in
    b20|b21|b22) printf '%s\t%s\n' PILOT itc99_b14_connected ;;
    aes_core) printf '%s\t%s\n' TRAIN iwls_aes_core ;;
    spi) printf '%s\t%s\n' TRAIN iwls_spi ;;
    tv80) printf '%s\t%s\n' VALIDATION iwls_tv80 ;;
    *) return 1 ;;
  esac
}

baseline_log() {
  local circuit=$1
  local mode=$2
  local version=phase4_v2
  if [[ "$circuit" == b20 ]]; then
    version=phase4_v1
  fi
  printf '%s/10_circuits/%s/logs/%s_%s_%s_full_%s.driver.log\n' \
    "$evidence_root" "$circuit" "$mode" "$circuit" "$mode" "$version"
}

mkdir -p "$inventory_dir" "$attempt_dir" "$join_dir" "$summary_dir"

required_tools=(
  audit_runtime_log_inventory.py
  recover_runtime_attempts.py
  build_runtime_join_v2.py
  summarize_runtime_recovery.py
  runtime_schema.py
  data_split_v1.json
)
for name in "${required_tools[@]}"; do
  test -f "$tools_dir/$name"
done

# Preflight every source and target before reading the candidate-level tables.
for circuit in "${circuits[@]}"; do
  measurement_root="$evidence_root/10_circuits/$circuit/10_coverage95_phase4_v2"
  f_log=$(baseline_log "$circuit" F)
  h_log=$(baseline_log "$circuit" H)
  test -d "$measurement_root"
  test -f "$f_log"
  test -f "$h_log"
  for target in \
    "$inventory_dir/${circuit}_inventory_v2_r3.json" \
    "$attempt_dir/${circuit}_attempt_manifest_v2_r3.tsv" \
    "$join_dir/${circuit}_join_v2_r3.tsv" \
    "$join_dir/${circuit}_audit_v2_r3.json"; do
    if [[ -e "$target" ]]; then
      printf 'refusing to overwrite existing r3 artifact: %s\n' "$target" >&2
      exit 2
    fi
  done
done
for target in "$summary_dir/summary_r3.json" "$summary_dir/tools_r3.sha256"; do
  if [[ -e "$target" ]]; then
    printf 'refusing to overwrite existing r3 artifact: %s\n' "$target" >&2
    exit 2
  fi
done

for circuit in "${circuits[@]}"; do
  IFS=$'\t' read -r role family < <(role_and_family "$circuit")
  measurement_root="$evidence_root/10_circuits/$circuit/10_coverage95_phase4_v2"
  f_log=$(baseline_log "$circuit" F)
  h_log=$(baseline_log "$circuit" H)
  inventory="$inventory_dir/${circuit}_inventory_v2_r3.json"
  attempt="$attempt_dir/${circuit}_attempt_manifest_v2_r3.tsv"
  join="$join_dir/${circuit}_join_v2_r3.tsv"
  audit="$join_dir/${circuit}_audit_v2_r3.json"

  python3 "$tools_dir/audit_runtime_log_inventory.py" \
    --input "$measurement_root" \
    --evidence-root "$evidence_root" \
    --extra-log "$f_log" \
    --extra-log "$h_log" \
    --circuit "$circuit" \
    --cohort phase4_v2_base_plus_full_boundaries_r3 \
    > "$inventory.tmp"
  mv "$inventory.tmp" "$inventory"

  inventory_sha=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["inventory_manifest_sha256"])' "$inventory")
  test -n "$inventory_sha"
  python3 "$tools_dir/recover_runtime_attempts.py" \
    --adapter gnu_time_log \
    --input "$measurement_root" \
    --evidence-root "$evidence_root" \
    --extra-log "$f_log" \
    --extra-log "$h_log" \
    --output "$attempt.tmp" \
    --phase phase4 \
    --cohort phase4_v2_r1_full_gnu_time_plus_full_boundaries_r3 \
    --environment-cohort phase4_20260825_A_phase4_v2_base_environment_unverified \
    --circuit "$circuit" \
    --family "$family" \
    --role "$role" \
    --inventory-manifest-sha256 "$inventory_sha"
  mv "$attempt.tmp" "$attempt"

  python3 "$tools_dir/build_runtime_join_v2.py" \
    --circuit "$circuit" \
    --measurements-root "$measurement_root" \
    --attempt-manifest "$attempt" \
    --split-contract "$split_contract" \
    "$join.tmp" "$audit.tmp"
  mv "$join.tmp" "$join"
  mv "$audit.tmp" "$audit"
done

summary_args=()
for circuit in "${circuits[@]}"; do
  summary_args+=(
    --circuit
    "$circuit=$inventory_dir/${circuit}_inventory_v2_r3.json,$attempt_dir/${circuit}_attempt_manifest_v2_r3.tsv,$join_dir/${circuit}_join_v2_r3.tsv,$join_dir/${circuit}_audit_v2_r3.json"
  )
done

python3 "$tools_dir/summarize_runtime_recovery.py" \
  --split-contract "$split_contract" \
  "${summary_args[@]}" \
  --output "$summary_dir/summary_r3.json.tmp"
mv "$summary_dir/summary_r3.json.tmp" "$summary_dir/summary_r3.json"

(
  cd "$tools_dir"
  sha256sum "${required_tools[@]}"
) > "$summary_dir/tools_r3.sha256.tmp"
mv "$summary_dir/tools_r3.sha256.tmp" "$summary_dir/tools_r3.sha256"

sha256sum "$summary_dir/summary_r3.json"
