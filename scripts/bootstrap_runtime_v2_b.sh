#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <fresh-root> <repo-root> <package-root> <outcome-split-root>" >&2
  exit 2
fi

protected=/ssd/cjc/multimode_ate_gnn_v1

# Canonicalize every external path before the first mkdir/cp/cd.  This closes
# symlink aliases into the protected historical workspace.
fresh_root=$(realpath -m -- "$1")
repo_root=$(realpath -e -- "$2")
package_root=$(realpath -e -- "$3")
outcome_split_root=$(realpath -e -- "$4")

case "$fresh_root" in
  /ssd/cjc/gnn_model_runtime_v2_*) ;;
  *) echo "fresh root is outside the allowed runtime-v2 namespace" >&2; exit 3 ;;
esac
case "$fresh_root" in
  "$protected"|"$protected"/*) echo "protected root rejected" >&2; exit 4 ;;
esac
if [[ -e "$fresh_root" ]]; then
  echo "fresh root already exists" >&2
  exit 5
fi
for input_path in "$fresh_root" "$repo_root" "$package_root" "$outcome_split_root"; do
  case "$input_path" in
    "$protected"|"$protected"/*) echo "protected input rejected" >&2; exit 6 ;;
  esac
done

mkdir -p "$fresh_root/evidence" "$fresh_root/inputs" "$fresh_root/runs"
cp -a "$package_root" "$fresh_root/inputs/runtime_training_package_v2"
cp -a "$outcome_split_root" "$fresh_root/inputs/outcome_split_v2"
package_root="$fresh_root/inputs/runtime_training_package_v2"
outcome_split_root="$fresh_root/inputs/outcome_split_v2"
python3 -m venv "$fresh_root/venv"
"$fresh_root/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip \
  > "$fresh_root/evidence/pip_install.log" 2>&1
"$fresh_root/venv/bin/python" -m pip install --disable-pip-version-check -r "$repo_root/requirements/runtime_v2.in" \
  >> "$fresh_root/evidence/pip_install.log" 2>&1
"$fresh_root/venv/bin/python" -m pip --version > "$fresh_root/evidence/pip_version.txt"
"$fresh_root/venv/bin/python" -m pip freeze --all | LC_ALL=C sort > "$fresh_root/evidence/requirements-runtime-v2-lock.txt"
( cd "$repo_root" && "$fresh_root/venv/bin/python" -m src.models.preflight_runtime_v2 \
    --contract "$repo_root/contracts/runtime_training_v2.json" \
    --package "$package_root" \
    --stage-seal "$repo_root/data/manifests/runtime_training_package_v2_20261002.json" \
    --outcome-split "$outcome_split_root" \
    --dependency-lock "$fresh_root/evidence/requirements-runtime-v2-lock.txt" \
    --workspace "$fresh_root" \
    --output "$fresh_root/evidence/environment_preflight.json" )
( cd "$repo_root" && "$fresh_root/venv/bin/python" -m unittest \
    tests.test_runtime_training_v2 tests.test_runtime_v2_preflight -v ) \
    > "$fresh_root/evidence/synthetic_tests.log" 2>&1
sha256sum "$fresh_root/evidence/requirements-runtime-v2-lock.txt" \
  "$fresh_root/evidence/environment_preflight.json" \
  "$fresh_root/evidence/pip_install.log" \
  "$fresh_root/evidence/pip_version.txt" \
  "$fresh_root/evidence/synthetic_tests.log" > "$fresh_root/evidence/SHA256SUMS"
echo "RUNTIME_V2_BOOTSTRAP=PASS_ENVIRONMENT_PREFLIGHT"
