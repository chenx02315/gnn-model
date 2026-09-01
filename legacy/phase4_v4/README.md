# Phase4 v4 历史模型基线

来源：`/ssd/cjc/multimode_ate_phase4_20260825_B`，版本 `formal_phase4_v4_safe_abstain_three_seed_r1`，独立汇总版本 `independent_r2`。

## 已同步到 Git

- `scripts/`：三 seed 训练、汇总和独立复核脚本；
- `reports/seed_*/`：每 seed 的 circuit/family 指标、LOFO 摘要和 run summary；
- `reports/`：三 seed 汇总及原始输出 SHA-256；
- `reports/independent_r2/`：独立复算结果；
- `metadata/checkpoints.sha256`：B 端 210 个 `.pt`/`.joblib` checkpoint 的路径与 SHA-256。

## 不进入 Git

- 三 seed checkpoint 二进制（合计约 60 MB）；
- 三份 `lofo_predictions.tsv`（合计约 42 MB）；
- 图、原始训练表及其他大产物。

这些文件继续保留在 B 端 `/ssd/cjc`。需要恢复模型时，必须先按 `checkpoints.sha256` 校验，再在受控目录有界复制。

## 结论边界

独立汇总状态为 PASS，固定 seed 为 20260824、20260825、20260826，安全门禁记录 D95 feasible rate=1、unsafe selection rate=0。该版本优化和报告的是 safe-abstain/ATE fallback gain；它没有使用本项目新恢复的 attempt 级 ATPG wall time，因此不能直接作为“ATPG 搜索时间优化”结论。
