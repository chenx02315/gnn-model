# Phase4 非盲 runtime 恢复审计 r3

本目录只保存可进入 Git 的聚合计数、join 审计和 SHA-256；逐 attempt manifest 与逐行 join 留在 A 端，不在 Git 展开。

## 结论

- 范围：`b20`、`b21`、`b22`、`aes_core`、`spi`、`tv80`，不包含三个 `BLIND_TEST` 电路。
- 原始 driver logs：30,994；elapsed/exit footer 均为 30,994，missing wall 为 0，nonzero exit 为 0。
- 结果状态：显式 ATPG PASS 1,441；缺少原生 ATPG 状态的 29,553 条保持 `UNKNOWN_LEGACY_STATUS`，不由 exit=0 推断成功。
- 测量引用：15,505；唯一连接 13,187；合同定义 `NOT_RUN` 2,209；repeatability 无结果路径 109。
- `MISSING=0`、`MISSING_RESULT_PATH=0`、`AMBIGUOUS=0`。
- 153 条跨阶段引用连接到六电路各自唯一的 F/H full-boundary attempts（共 12 个）；累计 search wall time 必须按唯一 attempt 计费。

汇总文件 `provenance/summary_r3.json` 的 SHA-256：

`352a66b50956fd9607274b0c28ac139adb071487da761e4faefd670edc203752`

## A 端权威路径

- 恢复根：`/temp/jiangchuanc/multimode_atpg_runtime_recovery_v1/phase4_nonblind_v2_r1`
- r3 inventory：`inventory_r3/`
- r3 attempts：`attempts_r3/`
- r3 joins：`joins_r3/`
- r3 汇总：`summaries_r3/summary_r3.json`
- 隔离工具：`tools_r3/`

## 已知边界

- `environment_cohort` 明确记录为 `phase4_20260825_A_phase4_v2_base_environment_unverified`，不是已验证环境等价声明。
- 30,994 条 attempts 的 `retry_order_status` 均为 `UNKNOWN_ORDER`；本审计没有重建时间顺序，也没有进行 fastest-success 筛选。
- 本目录不证明 BLIND executed-stage runtime 覆盖，不解锁训练、调参或论文正式泛化结论。
- ATE cycles、pattern 数、CPU user/system time 均未用作 wall-runtime 标签或插补来源。
