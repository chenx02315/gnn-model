# P0 状态：BLOCKED_RECOVERY_AUDIT

P0 当前允许继续 P1/P2 数据审计，但禁止正式训练、盲测访问或 runtime 结论。

正式家族划分已在候选级盲测 runtime 连接检查前预注册并封存（SHA-256 `c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac`）：PILOT 1 family / 4 circuits，TRAIN 6 families，VALIDATION 2 families，BLIND_TEST 3 families。b18/b20/b21/b22 的 `itc99_b14_connected` 整体只进入 PILOT；IWLS/OpenCores 电路统一采用已登记 Phase4 family map 的 `iwls_*` canonical 标签。

当前仅剩 runtime 恢复审计阻断：Phase2 已发现 b18、s35932、s38417、s38584 的真实 `wall_time` 行；Phase3 已发现 s13207、s15850、s5378、s9234 的逐次 driver log，抽样均含 elapsed/user/system/exit footer。发现证据不等于可训练标签；必须先通过 `contracts/runtime_recovery_gate_v1.json` 的 R01-R14，全量证明时间语义、失败/重试保留、SHA-256、环境 cohort、结果路径唯一连接和盲测 executed-stage 100% 覆盖。缺失耗时禁止插补，ATE cycles 禁止充当 runtime。

恢复审计 v1 已推进到非盲连接层：Phase2 全量根目录只读恢复 b18 6,806、s35932 1,981、s38417 5,003 个 driver logs；Phase3 全量根目录恢复 s13207 3,010、s15850 3,201、s5378 7,085 个 logs。全部具有 elapsed/exit footer；s38417 保留 3 个 nonzero exit，s5378 的 7,085 条全量根目录存在多版本历史路径，故采用覆盖审计 manifest 加 3 个精确 full-baseline logs，形成 3,453 行权威 attempt manifest，未按最快成功选择。六电路候选阶段共 7,015 行，唯一连接 5,659，合同定义 `NOT_RUN` 1,230，重复性无结果路径 126，`MISSING`/`AMBIGUOUS` 均为 0；跨阶段连接与 marker/run_id 不一致均保留在审计中。唯一连接中有 2,525 条显式 ATPG PASS、3,134 条 `UNKNOWN_LEGACY_STATUS`；后者不得由 exit=0 推断 ATPG 成功。三个 BLIND 家族仅完成 aggregate-only 清点：s38584 753、s9234 4,520、wb_dma 2,581 个日志均 footer 齐全且 nonzero exit 为 0，未暴露路径、run_id、候选或逐次耗时，也未进行候选级连接。详见 `data/manifests/runtime_recovery_inventory_v1.json` 与 `data/manifests/runtime_nonblind_join_audit_v2.json`。

候选空间门禁已通过：输入 6,287 行（SHA-256 `bce1e586fc47c57a01579d343322d12bc19b76b8b299649f5513d8788144bfb6`），筛得 3,161 条正式 HF/HMF 测量，按可部署动作去重为 3,050 个动作（输出 SHA-256 `07673677be6d97c4293453f3cfd11abeded30a4535bc86bdf69b37a4ecd1c514`）。其中 111 个动作有重复测量，outcome 冲突为 0；F 不进入动作键。

当前 b20 候选空间审计：正式 HF/HMF 测量 404 行，对应 392 个唯一 `(scheme,h_limit,m_limit)` 动作；12 个动作同时出现在 coarse/refine。正式 candidate space 必须以 action key 去重，并把多次测量保留为重复 attempts，禁止按 outcome 选取一行。

P1 b20 计时清单已通过：4,221 条 attempt 全部保留，解析完整、无重复 run_id。

七电路 D95/common-fault 门禁已通过：`data/manifests/d95_common_faults_seven_v1.json` 覆盖 b20、b21、b22、wb_dma、aes_core、tv80、spi；所有电路 `d95=ceil(0.95*N_common)`、canonical mapping 行数、H/M/F readback 均一致。审计 JSON SHA-256 为 `a1997e92f0dc6e3fd0c94a36dad8fd4bf0b16a438398b8124df89f36517608d9`。

b20 的权威 common-fault 目录名保留为 `common_b20_m16_phase4_v1`，其 manifest、mapping 和三模式 readback 已现场核验通过；其余六电路使用对应的 `phase4_v2` common 目录。目录版本差异不得被自动改名或解释为故障集合等价。

runtime policy 的 timeout/retry/cache/prefix-reuse 主体继续沿用冻结的 v1；新增 `contracts/runtime_policy_v2.json` 仅修正历史证据，不改变这些实验规则。Phase4 的 F/H full-boundary 日志已作为唯一真实 attempts 纳入恢复；同一基线被多条测量引用时按唯一 attempt 计费，禁止按引用次数重复累计。v1 中 b20 两个 full-boundary run 缺失 timing 的旧判断保留为历史版本，v2 已用原始 GNU-time footer 纠正，但仍需 P0 R01-R14 全通过后才可进入 runtime head 或正式离线回放。

P2 b20 直接连接已由 r3 修复通过：2,558 个 stage-mode 行中，21 行 repeatability 因源表没有结果路径而按合同标记 `NO_RESULT_PATH`，445 行 F 因 `TARGET_BEFORE_F` 标记 `NOT_RUN`，其余 2,092 行全部唯一连接，`MISSING=0`、`AMBIGUOUS=0`。其中 24 条跨阶段引用连接到两个唯一的 `H_b20_H_full_phase4_v1` 与 `F_b20_F_full_phase4_v1` driver attempts；其 wall time 来自原始 GNU-time footer，不做插补。

非盲连接审计 v2 已通过：Phase2 b18/s35932/s38417 与 Phase3 s13207/s15850/s5378 均为 `ambiguity_count=0`，`MISSING=0`，空路径仅出现在合同允许的 `NOT_RUN` 或 repeatability `NO_RESULT_PATH`。`PRUNED_OR_UNREACHED` 已保留原始原因并映射为 `NOT_RUN`，不计入 runtime。该审计仅证明已覆盖的六个非盲电路连接正确，不等于 P0 解锁。

Phase4 六个非盲电路的 r3 连接层已完成：30,994 个 driver attempts 全部具有 elapsed/exit footer，1,441 个有显式 ATPG PASS，29,553 个保留为 `UNKNOWN_LEGACY_STATUS`；15,505 条测量引用中 13,187 条唯一连接、2,209 条合同定义 `NOT_RUN`、109 条 repeatability `NO_RESULT_PATH`，`MISSING=0`、`MISSING_RESULT_PATH=0`、`AMBIGUOUS=0`。153 条 F/H full-boundary 引用连接到 12 个唯一跨阶段 attempts，未重复计费。汇总 SHA-256 为 `352a66b50956fd9607274b0c28ac139adb071487da761e4faefd670edc203752`，详见 `data/manifests/phase4_runtime_nonblind_v2_r3/`。

Phase4 非盲 r6 已在不修改 r3 的前提下收敛状态语义：`TARGET_BEFORE_F`/`INFEASIBLE_AT_D95` 只抑制未执行的 F，非空 H/M 路径继续作为真实 attempts；泛化 `NOT_RUN`/`PRUNED_OR_UNREACHED` 也不得覆盖非空 per-mode 路径。r6 保持 30,994 attempts、15,505 引用、13,187 `UNIQUE`、2,209 `NOT_RUN`、109 `NO_RESULT_PATH`、零缺失和零歧义，并把 153 条跨阶段引用直接重算为 12 个 distinct attempts。两次隔离复跑的 summary 均为 SHA-256 `482d447ed46dc5af5e225b78dad4e2c4ae2cab4333d800ab5ce7dc5602289ad2`。r4 因错误地将行级状态覆盖到 H/M 而被否决，r5 因泛化状态边界尚未完成而中止；二者仅在 A 端保留为失败证据，不进入 Git 权威汇总。

P0 仍未解锁。当前剩余关键阻断是 R07 的三个 BLIND 家族 executed-stage runtime 100% 覆盖尚未证明，以及 R03/R05/R11 所需的全源文件哈希、失败/重试 lineage 与真实环境 cohort 仍需形成统一 gate assessment；Phase4 r6 的 30,994 个 attempts 目前只能记录为环境未核验、retry order 未知。一次性、无模型、仅覆盖率的 BLIND 解封流程已冻结在 `contracts/blind_runtime_unseal_v1.json`，但只有 R07/R13 之外的全部门禁先通过后才能执行；当前前置条件不满足，任何候选级 BLIND join 仍保持封存。R01-R14 全部通过前，不得训练、调参、比较方法或做正式泛化结论。

Phase2 wall-time 语义门禁 R10 已独立通过：`collect_b14_all_results.py`（SHA-256 `78d433bb1a1cf9b21da37f993b165bc46d6a828de149896ae895fb3a4ec2bd83`）直接从 driver log 的 GNU `Elapsed (wall clock)` footer 写入 CSV `wall_time`。对 b18 2,057、s35932 841、s38417 1,711，共 4,609 个非盲 source rows 逐行核对，缺日志、缺 footer、非法 CSV/footer 格式、缺 CSV wall_time、重复 `(mode,run_id)` 和 footer 不一致均为 0；严格格式审计工具 SHA-256 为 `d82c0573c88d0ae26bac1d7f54b3015cffa4c35a831eeaabb96d711b419e645f`，聚合审计 SHA-256 为 `f274c639d83206d0ceaab88dd741213b42bf0bbc88bdec15daf14ee9dba24f59`。该 PASS 只关闭 R10，不改变 R03/R04/R05/R06/R11 或 BLIND 门禁。

R01-R14 当前逐项状态已冻结在 `contracts/runtime_recovery_gate_assessment_v1.json`：R01、R02、R08、R09、R10、R12、R14 为 PASS；R03、R04、R05、R06、R11 为 PARTIAL；R07、R13 为 BLOCKED。该表只报告门禁状态，不会把 PARTIAL 当作通过。

时间主终点固定为“命中 epsilon-near-optimal 前所有实际 Tessent attempts 的累计 elapsed”，包括失败和重试。命中后如另做独立确认，该确认只在端到端次指标计时，不与 search 重复计算。
