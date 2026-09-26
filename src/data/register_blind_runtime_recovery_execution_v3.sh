#!/usr/bin/env bash
set -euo pipefail
BUNDLE_ROOT=/temp/jiangchuanc/blind_runtime_recovery_execution_v3_authorized_r1_bundle
REG=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v3_registration_r1
[[ "${BLIND_RUNTIME_RECOVERY_V3_REGISTER_TOKEN:-}" == "REVIEWED_ONE_SHOT_V3" ]]
[[ ! -e "$REG" && ! -e /temp/jiangchuanc/multimode_ate_phase4_20260825_A/17_blind_runtime_recovery_execution_v3_r1_private ]]
cd -- "$BUNDLE_ROOT"
python3 -m src.data.run_blind_runtime_recovery_execution_v3 --root "$BUNDLE_ROOT" --registration-preflight
mkdir -m 0700 -- "$REG"
printf '%s\n' "bsub -H -rn -cwd $BUNDLE_ROOT -q normal -J blind_rt_recovery_v3_r1 -oo $REG/stdout.log -eo $REG/stderr.log /bin/bash $BUNDLE_ROOT/src/data/launch_blind_runtime_recovery_execution_v3.sh" > "$REG/registration_command.txt"
bsub -H -rn -cwd "$BUNDLE_ROOT" -q normal -J blind_rt_recovery_v3_r1 -oo "$REG/stdout.log" -eo "$REG/stderr.log" /bin/bash "$BUNDLE_ROOT/src/data/launch_blind_runtime_recovery_execution_v3.sh" | tee "$REG/bsub.txt"
job_id=$(sed -n 's/^Job <\([1-9][0-9]*\)> is submitted to queue <normal>\.$/\1/p' "$REG/bsub.txt")
[[ -n "$job_id" && $(wc -l < "$REG/bsub.txt") -eq 1 ]]
bjobs -noheader -o "jobid stat job_name queue" "$job_id" > "$REG/bjobs.txt"
bjobs -al "$job_id" > "$REG/bjobs_al.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$REG/capture_utc.txt"
date +%:z > "$REG/timezone_offset.txt"
