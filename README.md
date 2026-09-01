# gnn-model

固定 H64/M16/F4、多模式 H→M→F 条件下的 D95 安全、成本感知 Top-k 组合推荐。

## 研究目标

模型为 HF/HMF 推荐整数 H/M pattern 上限和候选验证顺序。Tessent 只验证少量候选，在共同故障 D95 硬约束下，以更少累计 ATPG wall time 找到 ATE cycles 接近完整网格最优的组合。

本项目严格区分：

- ATPG 搜索时间：Tessent 候选生成和验证的累计 wall time；
- ATE 应用成本：最终 patterns 对应的 tester cycles。

Pattern 或 cycles 下降不能单独证明 ATPG runtime 下降。

## 目录

- `contracts/`：实验合同、时间口径、数据划分和统计门禁；
- `src/data/`：日志恢复、attempt manifest 与候选连接；
- `src/models/`：D95、ATE cycles、ATPG cost 模型；
- `src/replay/`：Top-k 离线回放；
- `tests/`：确定性与无泄漏测试；
- `docs/`：方法和执行计划；
- `data/manifests/`：小型 SHA-256 清单和审计摘要。
- `legacy/phase4_v4/`：B 端既有三 seed safe-abstain 基线的代码、小型指标与 checkpoint 哈希；不作为本项目 ATPG runtime 模型结论。

原始 Tessent 日志、TSDB、STIL、MTFI、训练大文件和运行目录不进入 Git。

## 当前阶段

当前执行 P0–P2：冻结实验合同、建立 attempt 级耗时证据链，并将正式候选唯一连接到 H/M/F Tessent 运行。

## B 端模型版本策略

B 端 `formal_phase4_v4_safe_abstain_three_seed_r1` 作为历史基线保留。Git 收录可复现脚本、三 seed 小型指标、独立汇总与 210 个 checkpoint 的 SHA-256 清单；`.pt`、`.joblib` 和大预测表继续留在 `/ssd/cjc`，不直接进入 Git。

该历史模型验证的是 D95 安全选择和 ATE fallback gain，不等价于“降低累计 ATPG wall time”。新的论文主模型将在同一仓库中另建成本标签、成本模型和 Top-k 回放链。
