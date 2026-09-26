#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT=/temp/jiangchuanc/blind_runtime_recovery_execution_v2_authorized_r1_bundle
PLAN=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/14_blind_runtime_recovery_execution_v2_inputs_r1/plan.json
AUTHORIZATION=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v2_registration_r1/authorization.json

[[ "$(realpath -e "$BUNDLE_ROOT")" == "$BUNDLE_ROOT" ]]
[[ -f "$PLAN" && -f "$AUTHORIZATION" ]]

module load mentor/tessent2021
exec python3 "$BUNDLE_ROOT/src/data/run_blind_runtime_recovery_execution_v2.py" \
  --root "$BUNDLE_ROOT" \
  --plan "$PLAN" \
  --authorization "$AUTHORIZATION" \
  --source-preflight \
  --execute
