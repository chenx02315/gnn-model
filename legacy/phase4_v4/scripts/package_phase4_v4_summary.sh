#!/usr/bin/env bash
set -euo pipefail

base=/ssd/cjc/multimode_ate_phase4_20260825_B
run=$base/41_runs/formal_phase4_v4_safe_abstain_three_seed_r1
independent=$base/51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent
delivery=$base/60_delivery
package=$delivery/phase4_v4_safe_abstain_summary_r1.tar.gz
extract=$delivery/verified_extract_r1

cd "$run"
sha256sum -c three_seed_outputs.sha256
cd "$independent"
sha256sum -c independent_outputs.sha256
test ! -e "$package"
test ! -e "$extract"
mkdir -p "$delivery"
cd "$base"
tar -czf "$package" \
  31_gnn_formal_phase4_v4_safe_abstain/metadata/input_references.sha256 \
  31_gnn_formal_phase4_v4_safe_abstain/metadata/scripts_r3.sha256 \
  41_runs/formal_phase4_v4_safe_abstain_three_seed_r1/three_seed_per_model.tsv \
  41_runs/formal_phase4_v4_safe_abstain_three_seed_r1/three_seed_aggregate.tsv \
  41_runs/formal_phase4_v4_safe_abstain_three_seed_r1/three_seed_summary.json \
  41_runs/formal_phase4_v4_safe_abstain_three_seed_r1/three_seed_outputs.sha256 \
  51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent/independent_per_seed.tsv \
  51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent/independent_aggregate.tsv \
  51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent/independent_infeasible_selections.tsv \
  51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent/independent_summary.json \
  51_summary/formal_phase4_v4_safe_abstain_three_seed_r1_independent/independent_outputs.sha256
sha256sum "$package" > "$package.sha256"

count=$(tar -tzf "$package" | wc -l)
test "$count" -le 32
while IFS= read -r member; do
  case "$member" in
    /*|../*|*/../*) echo "unsafe member: $member" >&2; exit 65 ;;
  esac
done < <(tar -tzf "$package")
if tar -tvzf "$package" | awk '{print substr($1,1,1)}' | grep -Ev '^[-d]$' >/dev/null; then
  echo "archive contains a non-regular, non-directory member" >&2
  exit 66
fi
mkdir -p "$extract"
tar -xzf "$package" -C "$extract"
printf 'PACKAGE_COUNT=%s\n' "$count"
stat -c 'PACKAGE=%n SIZE=%s' "$package"
cat "$package.sha256"
