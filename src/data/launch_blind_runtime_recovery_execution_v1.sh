#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT=/temp/jiangchuanc/blind_runtime_recovery_execution_v1_authorized_r1_bundle
PLAN=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/12_blind_runtime_recovery_v1_r4_private/payload/plan.json
AUTHORIZATION=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v1_registration_r1/authorization.json

[[ "$(realpath -e "$BUNDLE_ROOT")" == "$BUNDLE_ROOT" ]]
[[ -f "$PLAN" && -f "$AUTHORIZATION" ]]

module load mentor/tessent2021
exec python3 "$BUNDLE_ROOT/src/data/run_blind_runtime_recovery_execution_v1.py" \
  --root "$BUNDLE_ROOT" \
  --plan "$PLAN" \
  --authorization "$AUTHORIZATION" \
  --source-preflight \
  --execute
