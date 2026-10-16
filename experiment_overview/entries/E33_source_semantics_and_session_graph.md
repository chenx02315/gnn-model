# E33：历史会话图与费用口径适配检查

## 先说结论和例子

历史 runtime 不能简单改字段名接到 E31。旧数据允许多个候选共享同一次 H 前缀，并把同一动作的多次完整测量取平均；E31 的简化账本假设独立、单次调用、无共享。二者都能用于各自明确的验证，但计费单位不能混用。

例如 H 运行 10 秒，两个候选的 F 分别运行 2 秒、3 秒：

- 采集这些记录共包含三个不同 session，elapsed 合计 15 秒。
- 假设每个候选都独立从头尝试，按引用计算的费用是 `(10+2)+(10+3)=25` 秒。
- 15 秒不是整个实验的日历耗时（进程可能并行）；25 秒也不是已经测得的线上搜索耗时（实际策略可能复用 H）。

另一个例子：同一动作两次独立测量的费用为 12 秒和 20 秒，旧口径给该动作的估计是 16 秒。不能改成只选 12 秒，也不能把 32 秒当作每次尝试成本。

本轮核对代码和合同，并实现只处理生成数据的物化 session 图诊断。不读取真实结果行，不运行旧的真实 mapping/aggregation 程序，不做模型前向、拟合、远端或新 ATPG。它不是已完成的原始来源 reader，不输出 E31 records 或可直接送入 FIT 的训练标签。

## 静态源码核对发现的实际差异

| 差异 | 源码依据 | 适配时不能做什么 |
| --- | --- | --- |
| stage 和 mode 是两列 | `recover_runtime_attempts.py:67–69`、`runtime_schema.py:4–11` | 不把 `02_hf_coarse` 当作 H/M/F 模式 |
| 一份日志可能有多个 process session | `remediate_runtime_attempts_v2.py:159–199,255–274` | 不只取文件末尾的成功记录，遗漏早期失败 |
| 原 retry 顺序从 1 开始 | `remediate_runtime_attempts_v2.py:284–315` | 不为了 E31 从零开始而自动重编号；run/group ID 不等于完整 invocation |
| 同 session 可被多个 invocation 引用 | `audit_runtime_action_attempt_mapping_v1.py:223–246` | 不复制 attempt ID 把共享图伪装成互斥树 |
| F search probe 有额外映射边 | 同文件 `270–315` | 不把多个独立搜索 group 拼成一条 stage 重试链 |
| 动作费用来自各 invocation 费用的平均 | `aggregate_runtime_action_costs_v1.py:142–187` | 不选最快调用，不用所有调用总和冒充单次费用 |
| 历史安全训练包写入 SUCCESS/D95=1 | `build_runtime_training_package_v2.py:235–273` | 不能由安全包推断失败动作账本完整 |
| environment 字符串不等于真实性证明 | `repeat_phase4_nonblind_runtime_recovery.py:110–116` | cohort 字符串一致只证明内部一致，不认证硬件/软件环境 |

旧 mapping 审计入口本身会读取测量状态和质量冲突值，不能把运行它当成本轮的“无质量标签 reader”。这里仅检查了其源码。12 个源码/合同 SHA 与核对结论另存小型来源回执；不是对真实数据的来源认证，也不是断言旧证据不存在。

## 新接口处理什么

输入是严格、已投影的内存视图：deployable action、source invocation 引用、独立 process session 和映射边。保留 parent/session index/count、原 retry group/order、mode 与历史 stage、来源哈希及 cohort。所谓“无质量标签”是指不接触 cycles、D95、epsilon 或整个 action 的结果；session 的工具运行 SUCCESS/FAILURE/TIMEOUT 状态仍用于明确保留失败计费。

检查唯一节点与边、source 所属动作、上下游元数据、parent 会话全集、group 顺序和引用完整性；group 内部按电路与原始 group ID 定位，不把不同电路的同名 group 合并，也不改其 ID。跨 invocation 共享合法保留。未映射的输入 session 也保留并单列计数和秒数。未知或缺失 elapsed、CPU 替代、混 cohort、inclusive parent 计时声明、success-only 初级恢复状态不被自动接受或补造。

分别报告：所有输入 session 秒数、已映射不同 session 秒数、按引用累加的独立尝试 proxy、每 source 的提供集合内费用以及每 action 的全部 source 算术平均。使用 Decimal 字符串诊断，不自动产生训练费用标签。原始来源集合是否完整、排除理由是否合法、计时是否真正互斥，需要另行核对原始证据；给定集合内部检查不能替代它们。

HF/HMF 是否实际运行了每个模式，也不能只凭这张图推断：达到目标而早停可能没有 F。接口记录已观察和未观察模式，但不将 session SUCCESS 推成整个 action 成功，不判断 D95 或近优。

## 验收、记录与下一节点

测试使用生成的小图覆盖共享前缀、重复测量均值、不同 F group、失败/timeout 与未映射 session 保留、parent/session 完整性、错误连接和混环境、非数值/缺失 elapsed 拒绝，以及输入重排确定性。完整执行数量和独立复核以完成回执为准，不把源码检查或合成图当成真实 TRAIN 读取已经通过。

修复后新增测试 22 项（图检查 18、合同/来源一致性 4），全部通过且零跳过。完整相关回归 617 项：511 项执行、106 项平台/依赖条件跳过，零失败、零错误；分组为 419（3 跳过）+16（0 跳过）+182（103 跳过）。独立复核重复的 22 项不叠加计数；另用 Fraction 与独立 Decimal50 核对 7 个费用坐标全部相符。

首次源码审核未通过：初版 `379e819f...2fe338` 虽通过 20 项局部测试，但独立反例发现，同一 source 能混入不同 invocation stage；GNU footer 声明还能接受同文件 session 与 retry 顺序颠倒，或多个文件假借同一 footer 顺序。原始 16,353 字节源码已在本地 staging 的 `v6_session_graph_20261016_r1/pre_review_source.json` 以原字节 base64 保存，供负面证据复盘。

已一次聚焦修复为：source 的 invocation stage 唯一；GNU 组必须同 parent、同非空 log SHA、retry order 与 session index 一致；EMBEDDED 多文件组按不同 log SHA 判断，不因共用同一 CSV artifact SHA 被误拒。合法跨阶段前缀和多文件路径保留，不自动重编号。另外将字段名也收紧为内置字符串。修复后源码为 `4da26b67...33b456`；这是未发布实现的本地修复，不是正式实验重试。

真实来源适配还需要预先冻结字段投影，将 remediated manifest 与完整 lineage 按原 ID 连接，核对原 inventory 和排除凭据；特别是 invocation 边界、独立 rerun/search/retry 分类、terminal measurement 与非重叠计时依据。不能用初级 `COLLECTED_SUCCESS_ONLY` 表或“一个文件一个 attempt”假设补齐这些内容。

本轮保持 `e31_direct_compatible=false`、来源/原集合完整性/计时认证 false、真实读取与训练放行 false。后续应核验真实 TRAIN 的上述来源链，再决定沿用哪一种历史 proxy；最后接模型域和受控 trainer，不靠增加实验数或重复旧合成采样掩盖语义问题。

## 证据入口

- [接口合同](../../contracts/ranking_v6_session_graph_v1.json)
- [静态来源核对](../../data/manifests/ranking_v6_e33_source_audit_20261016_r1.json)
- [完成回执](../../data/manifests/ranking_v6_e33_completion_20261016_r1.json)
- [独立复核](../../data/manifests/ranking_v6_e33_review_20261016_r1.json)
- [SHA-256](../../data/manifests/ranking_v6_e33_20261016_r1.sha256)
