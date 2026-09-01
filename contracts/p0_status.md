# P0 状态：BLOCKED_PENDING_EVIDENCE

P0 当前允许继续 P1/P2 数据审计，但禁止正式训练、盲测访问或 runtime 结论。

待补四项：

1. `candidate_space.tsv`、唯一候选 UID 与 SHA-256；
2. 每电路共同故障文件、`N_common`、D95 规则与 SHA-256；
3. timeout、retry、cache、prefix reuse、tie-break 与 fallback 的冻结值；
4. TRAIN/VALIDATION/PILOT/BLIND_TEST 的 circuit-family 清单与 SHA-256。

当前 b20 候选空间审计：正式 HF/HMF 测量 404 行，对应 392 个唯一 `(scheme,h_limit,m_limit)` 动作；12 个动作同时出现在 coarse/refine。正式 candidate space 必须以 action key 去重，并把多次测量保留为重复 attempts，禁止按 outcome 选取一行。

P1 b20 计时清单已通过：4,221 条 attempt 全部保留，解析完整、无重复 run_id。

P2 b20 直接连接当前为条件通过：2,558 个 stage-mode 行中，21 行 repeatability 因源表没有结果路径而按合同标记 `NO_RESULT_PATH`；445 行 F 因 `TARGET_BEFORE_F` 标记 `NOT_RUN`；2,068 行以 `source_log` basename 唯一连接，歧义为 0。另有 24 行 `MISSING`，实际只引用两个共享基线 `H_b20_H_full_phase4_v1` 与 `F_b20_F_full_phase4_v1`，A 端未发现其独立 driver 计时日志。正式 cost label 前必须选择“隔离重跑这两个基线”或“明确视为预计算固定成本并从训练目标排除”，不得填补或推断耗时。

时间主终点固定为“命中 epsilon-near-optimal 前所有实际 Tessent attempts 的累计 elapsed”，包括失败和重试。命中后如另做独立确认，该确认只在端到端次指标计时，不与 search 重复计算。
