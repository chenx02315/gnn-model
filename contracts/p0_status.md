# P0 状态：BLOCKED_PENDING_EVIDENCE

P0 当前允许继续 P1/P2 数据审计，但禁止正式训练、盲测访问或 runtime 结论。

待补一项：

1. TRAIN/VALIDATION/PILOT/BLIND_TEST 的 circuit-family 清单与 SHA-256；当前七电路仅有五个 family，正式 runtime 泛化 split 仍阻断。

候选空间门禁已通过：输入 6,287 行（SHA-256 `bce1e586fc47c57a01579d343322d12bc19b76b8b299649f5513d8788144bfb6`），筛得 3,161 条正式 HF/HMF 测量，按可部署动作去重为 3,050 个动作（输出 SHA-256 `07673677be6d97c4293453f3cfd11abeded30a4535bc86bdf69b37a4ecd1c514`）。其中 111 个动作有重复测量，outcome 冲突为 0；F 不进入动作键。

当前 b20 候选空间审计：正式 HF/HMF 测量 404 行，对应 392 个唯一 `(scheme,h_limit,m_limit)` 动作；12 个动作同时出现在 coarse/refine。正式 candidate space 必须以 action key 去重，并把多次测量保留为重复 attempts，禁止按 outcome 选取一行。

P1 b20 计时清单已通过：4,221 条 attempt 全部保留，解析完整、无重复 run_id。

七电路 D95/common-fault 门禁已通过：`data/manifests/d95_common_faults_seven_v1.json` 覆盖 b20、b21、b22、wb_dma、aes_core、tv80、spi；所有电路 `d95=ceil(0.95*N_common)`、canonical mapping 行数、H/M/F readback 均一致。审计 JSON SHA-256 为 `a1997e92f0dc6e3fd0c94a36dad8fd4bf0b16a438398b8124df89f36517608d9`。

b20 的权威 common-fault 目录名保留为 `common_b20_m16_phase4_v1`，其 manifest、mapping 和三模式 readback 已现场核验通过；其余六电路使用对应的 `phase4_v2` common 目录。目录版本差异不得被自动改名或解释为故障集合等价。

runtime policy 已冻结为 pilot 版：H/M/F timeout=60/30/30 秒；失败与允许的一次基础设施重试全部计时；禁止 fastest-success 选择；主会话冷 artifact cache；跨方法/跨 session 不复用；只有同一 session 内、精确内容寻址的 H/HM 前缀可复用。b20 两个无 timing 的 full-run 禁止插补或当作零成本，若前瞻选中必须独立执行并计时。

P2 b20 直接连接当前为条件通过：2,558 个 stage-mode 行中，21 行 repeatability 因源表没有结果路径而按合同标记 `NO_RESULT_PATH`；445 行 F 因 `TARGET_BEFORE_F` 标记 `NOT_RUN`；2,068 行以 `source_log` basename 唯一连接，歧义为 0。另有 24 行 `MISSING`，实际只引用两个共享基线 `H_b20_H_full_phase4_v1` 与 `F_b20_F_full_phase4_v1`，A 端未发现其独立 driver 计时日志。正式 cost label 前必须选择“隔离重跑这两个基线”或“明确视为预计算固定成本并从训练目标排除”，不得填补或推断耗时。

时间主终点固定为“命中 epsilon-near-optimal 前所有实际 Tessent attempts 的累计 elapsed”，包括失败和重试。命中后如另做独立确认，该确认只在端到端次指标计时，不与 search 重复计算。
