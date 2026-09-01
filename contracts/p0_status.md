# P0 状态：BLOCKED_PENDING_EVIDENCE

P0 当前允许继续 P1/P2 数据审计，但禁止正式训练、盲测访问或 runtime 结论。

待补四项：

1. `candidate_space.tsv`、唯一候选 UID 与 SHA-256；
2. 每电路共同故障文件、`N_common`、D95 规则与 SHA-256；
3. timeout、retry、cache、prefix reuse、tie-break 与 fallback 的冻结值；
4. TRAIN/VALIDATION/PILOT/BLIND_TEST 的 circuit-family 清单与 SHA-256。

时间主终点固定为“命中 epsilon-near-optimal 前所有实际 Tessent attempts 的累计 elapsed”，包括失败和重试。命中后如另做独立确认，该确认只在端到端次指标计时，不与 search 重复计算。

