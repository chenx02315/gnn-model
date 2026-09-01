#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <dataset> <graphs> <family-map> <output-root>" >&2
  exit 64
fi

dataset=$1
graphs=$2
family_map=$3
output_root=$4
script_dir=$(cd "$(dirname "$0")" && pwd)
python=/ssd/cjc/multimode_ate_gnn_v1/.venv/bin/python
[[ -x $python ]] || { echo "missing Python runtime: $python" >&2; exit 69; }
[[ ! -e $output_root ]] || { echo "refusing overwrite: $output_root" >&2; exit 73; }
mkdir -p "$output_root"

for seed in 20260824 20260825 20260826; do
  "$python" "$script_dir/train_family_holdout_phase4_v3.py" \
    --dataset "$dataset" \
    --graphs "$graphs" \
    --family-map "$family_map" \
    --output "$output_root/seed_$seed" \
    --device cuda \
    --epochs 220 \
    --seed "$seed" \
    > "$output_root/seed_$seed.log" 2>&1
done

"$python" "$script_dir/summarize_three_seeds.py" --run-root "$output_root"
sha256sum "$output_root"/seed_*/lofo_*.tsv "$output_root"/seed_*/run_summary.json \
  "$output_root"/three_seed_per_model.tsv "$output_root"/three_seed_aggregate.tsv \
  "$output_root"/three_seed_summary.json \
  > "$output_root/three_seed_outputs.sha256"
printf 'THREE_SEED_LOFO=PASS\n'
