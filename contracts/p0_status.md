# P0 状态：BLOCKED_RECOVERY_AUDIT

P0 当前允许继续 P1/P2 数据审计，但禁止正式训练、盲测访问或 runtime 结论。

正式家族划分已在候选级盲测 runtime 连接检查前预注册并封存（SHA-256 `c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac`）：PILOT 1 family / 4 circuits，TRAIN 6 families，VALIDATION 2 families，BLIND_TEST 3 families。b18/b20/b21/b22 的 `itc99_b14_connected` 整体只进入 PILOT；IWLS/OpenCores 电路统一采用已登记 Phase4 family map 的 `iwls_*` canonical 标签。

当前仅剩 runtime 恢复审计阻断：Phase2 已发现 b18、s35932、s38417、s38584 的真实 `wall_time` 行；Phase3 已发现 s13207、s15850、s5378、s9234 的逐次 driver log，抽样均含 elapsed/user/system/exit footer。发现证据不等于可训练标签；必须先通过 `contracts/runtime_recovery_gate_v1.json` 的 R01-R14，全量证明时间语义、失败/重试保留、SHA-256、环境 cohort、结果路径唯一连接和盲测 executed-stage 100% 覆盖。缺失耗时禁止插补，ATE cycles 禁止充当 runtime。

恢复审计 v1 已推进到非盲连接层：Phase2 全量根目录只读恢复 b18 6,806、s35932 1,981、s38417 5,003 个 driver logs；Phase3 全量根目录恢复 s13207 3,010、s15850 3,201、s5378 7,085 个 logs。全部具有 elapsed/exit footer；s38417 保留 3 个 nonzero exit，s5378 的 7,085 条全量根目录存在多版本历史路径，故采用覆盖审计 manifest 加 3 个精确 full-baseline logs，形成 3,453 行权威 attempt manifest，未按最快成功选择。六电路候选阶段共 7,015 行，唯一连接 5,659，合同定义 `NOT_RUN` 1,230，重复性无结果路径 126，`MISSING`/`AMBIGUOUS` 均为 0；跨阶段连接与 marker/run_id 不一致均保留在审计中。唯一连接中有 2,525 条显式 ATPG PASS、3,134 条 `UNKNOWN_LEGACY_STATUS`；后者不得由 exit=0 推断 ATPG 成功。三个 BLIND 家族已完成 aggregate-only 前置审计：s38584 753、s9234 4,520、wb_dma 2,581，共 7,854 个日志全部保留并具有 parse status、唯一 attempt ID、source digest、inventory 绑定、phase/cohort/environment cohort；retry order 全部保持 `UNKNOWN_ORDER`，未插补顺序、未按最快成功筛选、未进行候选级连接，也未导出逐次记录。两次隔离复跑的三个汇总 JSON 均逐字节一致。该证据关闭 R04、R05、R11，但不关闭 R06、R07 或 R13。R03 的 7 个外部回读不一致已用 A 端新目录 `joins_nonblind_v3_authority` 和增量收据完成版本化和解；A 端 v5 聚合复核重算并独立验证了 18 个此前缺失摘要；最后在本地隔离恢复目录重新发现并逐字节核验 b18/s35932/s38417 三个早期 Phase2 manifest。当前 73/73 匹配、0 缺失、0 不一致、0 未绑定，R03 已 PASS；2.3 MB 原始 manifest 不进入 Git，Git 仅保留聚合回执、验证器和 SHA-256。详见 `data/manifests/blind_attempt_preconditions_v1/assessment.json`、`data/manifests/phase2_manifest_recovery_receipt_v1.json` 与 `data/manifests/runtime_source_ledger_v1.json`。

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

P0 仍未解锁。R04、R05、R11 已由 7,854 条 BLIND 日志的聚合前置审计关闭；环境未知性与 retry order 未知性均被显式保留，不作等价或顺序推断。当前剩余关键阻断是 R06 的 BLIND 候选阶段到 attempt 歧义、R07 的三个 BLIND 家族 executed-stage runtime 100% 覆盖，以及依赖覆盖交集冻结的 R13。旧 v1 的 R06 循环前置条件和 v2 将未来推荐方法误写进解封收据的问题均保留为版本化审计证据，不执行。当前权威合同为 `contracts/blind_runtime_unseal_v3.json`：一次性、无模型、仅覆盖率的原子审计只按三个电路计算 R06/R07 和各自候选空间哈希；复封后再把 `contracts/recommendation_method_registry_v1.json` 中预注册的三种方法全部绑定到同一组哈希以判定 R13。v3 与执行工具必须先完成独立复核，当前仍不得执行候选级 BLIND join。R01-R14 全部通过前，不得训练、调参、比较方法或做正式泛化结论。

v3 静态预检曾 PASS，但封闭执行器实现复核发现其要求收据包含自身 SHA-256，属于不可实现的自引用摘要。v3 与其预检收据均保留为失败边界证据。当前权威合同升级为 `contracts/blind_runtime_unseal_v4.json`：任何 BLIND 数据读取前先用排他创建写入不可逆 `CONSUMED` 标记，之后候选级状态只驻留内存；三个电路全部完成后才写最终 JSON，再生成外部 `receipt.json.sha256`。进程崩溃也会消耗唯一机会，禁止把崩溃当作可重跑。失败只能发布无分电路明细的失败 envelope 与外部摘要。v4 静态预检现已 PASS，明确验证自哈希不存在、当前仅 R06/R07/R13 非 PASS、BLIND 集合与 split 完全一致；仍须独立复核封闭执行器，一次性解封尚未执行。

v4 封闭执行器 `src/data/run_blind_unseal_v4.py` 已实现但未在真实 BLIND 数据上执行。它在消费标记创建后才读取数据，逐候选连接与 action key 只驻留内存；成功只输出三个电路的计数与哈希，任一电路失败则只输出无分电路值的统一失败 envelope。单元测试覆盖排他防重放、消费标记先于数据读取、HF/HMF action key 去重且不使用 F/outcome、成功 sidecar，以及失败不泄露部分结果。真实一次性运行必须等独立复核通过。

独立复核清单已冻结在 `contracts/blind_unseal_independent_review_v1.json`。对提交 `a67ad679f80678d552d8c42d18fa6787e582c9f4` 的只读复核已形成 `data/manifests/blind_unseal_independent_review_v1.json`，结论为 FAIL：v4 未强制复核回执和现场门禁，BLIND 输入集合及工具依赖未做预注册摘要绑定，发布状态也未达到崩溃原子性；另有输出路径别名、R07 分母定义和负向/一致性测试缺口。复核期间未访问 A/B 或 BLIND 数据，真实一次性解封仍未执行。v4 作为失败证据保留，修复只进入新 v5 链；v5 再获独立 PASS 前执行权限为 false。

v5 已建立但仍封存：`contracts/blind_runtime_unseal_job_v5.json` 固定三个 BLIND 电路的根目录、家族、环境 cohort、六个测量表以及输出目录；`data/manifests/blind_input_inventory_freeze_v1.json` 只记录 A 端聚合文件集合摘要和 4,520/753/2,581 条日志计数，没有读取或导出候选行、run_id、耗时或 outcome。`contracts/blind_runtime_unseal_v5.json` 进一步固定 split 文件、方法注册表、job、聚合清单和全部执行依赖的 SHA-256；执行器在本地重新计算当前门禁并强制独立 PASS 回执，之后才可耐久排他写入 `CONSUMED`。实际输入集合须在消费后、解析前与预注册摘要完全一致；发布必须同时具备 `CONSUMED`、`receipt.json`、sidecar 和最后写入的 `RELEASED`，缺一均视为不可重跑的 `INCOMPLETE_CONSUMED`。R07 已明确把 formal stage 的 `MISSING_RESULT_PATH` 留在分母并判失败。v5 静态预检 PASS，但 `contracts/blind_unseal_independent_review_v2.json` 仍为待复核状态，因此真实解封、训练和调参仍禁止。

v5 对提交 `075d3b0` 的独立只读复核已 FAIL，正式回执为 `data/manifests/blind_unseal_independent_review_v2.json`。复核确认输入集合、耐久消费标记、R07 分母和聚合输出方向正确，但发现两个 P0：`reviewed_commit` 只校验 40 位格式而未解析到部署提交；更早地，项目 helper 在摘要核验前已被 import，替换模块可在拒绝前执行。另有发布消费者未校验 CONSUMED 内容、RELEASED 的 contract 绑定、receipt schema/字段集合这一 P1。复核未访问 A/B/BLIND，也未运行真实解封。v5 作为失败证据保留；v6 必须以外部先验摘要校验的最小 bootstrap 作为唯一入口，在任何项目模块 import 前完成提交和文件校验，并补齐发布语义验证。

v6 已实现并保持封存。`src/data/bootstrap_blind_unseal_v6.py` 顶层只使用 Python 标准库；A 端必须先用签入 sidecar 从 Git checkout 根目录外部校验 bootstrap SHA-256，bootstrap 随后在动态 import 任一项目模块前核验全部工具摘要、PASS 复核回执、`reviewed_commit` 可解析性、HEAD 祖先关系、干净工作树，以及该提交内 contract/tool blob 的逐字节摘要。`src/data/run_blind_unseal_v6.py` 直接执行只返回拒绝，只接受 bootstrap 传入并与 PASS 回执一致的 attestation。v6 复用的 v5 连接核在 import 前也已被固定摘要。发布消费者现同时验证 CONSUMED 内容、contract/tool 绑定、receipt schema 与字段白名单、sidecar、RELEASED 绑定及三个电路顺序，阻止自洽但跨版本拼接的四件套。v6 使用新的未创建输出目录 `11_blind_runtime_unseal_v6_one_shot`，仍未访问候选级 BLIND 数据；必须等待 `contracts/blind_unseal_independent_review_v3.json` 的独立复核 PASS。

v6 对提交 `8a6f8d83671b509d84de655a15004ff5215624bd` 的独立只读复核已 FAIL，正式回执为 `data/manifests/blind_unseal_independent_review_v3.json`。复核确认提交和七项工具摘要绑定、import 前标准库 bootstrap、消费后输入重哈希、R07 分母以及聚合字段白名单方向正确，但发现两个 P0：当前门禁只是读取未固定摘要的 assessment 状态，并未从冻结证据重算；导入 runner 后仍可用可伪造字典直接调用公开 API 绕过 bootstrap。另有三个 P1：成功路径未调用发布语义验证器、同用户可删除 `/temp` 消费标记后重放、复核回执的只读/未解封范围字段未被强制验证。复核未访问 A/B/BLIND，也未运行真实解封。v6 作为失败证据保留；任何 v7 实现前必须先确认 A 端是否存在进程用户不可删除的外部账本或等价 LSF 审计边界。

A 端只读权限盘点确认 Phase4 根目录及 logs 均由 `jiangchuanc` 所有并可由同用户写入，单靠 `/temp` 标记无法声称敌手级不可逆；LSF 9.1 的 `bsub/bjobs/bhist/bacct` 可用，但现场 `HIST_HOURS=5`，调度历史必须在 resume 后五小时内捕获。`contracts/blind_runtime_unseal_protocol_v7.json` 因而把目标收敛为诚实操作员假设下的 operational one-shot：先冻结证据，再只提交一个 held 非数组 job，登记其 Job ID 后独立复核，PASS 后只允许 `bresume` 该 ID，运行后用四件套和 LSF 历史共同审计。该边界不能阻止同账户恶意删除、伪造环境或直接读取 BLIND，论文不得写成密码学或权限级不可逆。

v7 单文件执行器草案提交 `74636c0aae8cf3ba8a58cb25774017d071a725c3` 的独立只读复核已 FAIL，正式回执为 `data/manifests/blind_unseal_independent_review_v4.json`。虽然 10 项聚焦测试和全套 141 项测试通过，但执行器没有等价移植权威的 mode-aware `NOT_RUN`/`TARGET_BEFORE_F` 语义、wall-time/exit/timeout/失败重试恢复、canonical basename，也未完整证明逐动作 R07/R13；held-job 注册字段和 `bhist/bacct` 亦未进入 release 门禁，Git blob 摘要还错误地去除了尾部字节。复核未访问 A/B/BLIND，未注册或执行 LSF job。v7 只作为失败草案保留；修复必须进入 v8，且 v8 独立 PASS 前禁止 held-job 注册、BLIND 解封和训练。

Phase2 wall-time 语义门禁 R10 已独立通过：`collect_b14_all_results.py`（SHA-256 `78d433bb1a1cf9b21da37f993b165bc46d6a828de149896ae895fb3a4ec2bd83`）直接从 driver log 的 GNU `Elapsed (wall clock)` footer 写入 CSV `wall_time`。对 b18 2,057、s35932 841、s38417 1,711，共 4,609 个非盲 source rows 逐行核对，缺日志、缺 footer、非法 CSV/footer 格式、缺 CSV wall_time、重复 `(mode,run_id)` 和 footer 不一致均为 0；严格格式审计工具 SHA-256 为 `d82c0573c88d0ae26bac1d7f54b3015cffa4c35a831eeaabb96d711b419e645f`，聚合审计 SHA-256 为 `f274c639d83206d0ceaab88dd741213b42bf0bbc88bdec15daf14ee9dba24f59`。该 PASS 只关闭 R10，不改变 R03/R04/R05/R06/R11 或 BLIND 门禁。

R01-R14 当前逐项状态已冻结在 `contracts/runtime_recovery_gate_assessment_v1.json`：R01、R02、R03、R04、R05、R08、R09、R10、R11、R12、R14 为 PASS；R06 为 PARTIAL；R07、R13 为 BLOCKED。该表只报告门禁状态，不会把 PARTIAL 当作通过。

R03 的统一来源账本已通过：本地签入文件全部重算，27 条关键本地交叉引用一致；原始回读的 7 个失配已由版本化增量和解，A 端 v5 以冻结 18-ID 规格生成 2.6 KB 聚合回执（SHA-256 `4e3f75819cd3dd4c013fdf09445d292fe7ab0e2eb32346da987941797b2a8407`）；最后三个 Phase2 历史 manifest 在本地保留目录中重新发现，经 `audit_phase2_manifest_recovery.py` 全量核验 4,609 行并命中冻结摘要。账本现为 73/73 匹配、0 缺失、0 失配、0 未绑定。R03 PASS 只关闭来源摘要完整性，不自动触发 BLIND 解封或 P0 放行。

时间主终点固定为“命中 epsilon-near-optimal 前所有实际 Tessent attempts 的累计 elapsed”，包括失败和重试。命中后如另做独立确认，该确认只在端到端次指标计时，不与 search 重复计算。
