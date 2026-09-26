#!/usr/bin/env bash
set -euo pipefail
BUNDLE_ROOT=/temp/jiangchuanc/blind_runtime_recovery_execution_v3_authorized_r1_bundle
PLAN=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/16_blind_runtime_recovery_execution_v3_inputs_r1/plan.json
AUTHORIZATION=/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v3_registration_r1/authorization.json
[[ "$(realpath -e "$BUNDLE_ROOT")" == "$BUNDLE_ROOT" && -f "$PLAN" && -f "$AUTHORIZATION" ]]
cd -- "$BUNDLE_ROOT"
module load mentor/tessent2021
exec python3 -m src.data.run_blind_runtime_recovery_execution_v3 --root "$BUNDLE_ROOT" --plan "$PLAN" --authorization "$AUTHORIZATION" --source-preflight --execute
