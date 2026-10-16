# E36：先补完整清单，不把成功记录误当候选全集

## 现在得到什么结论

这次从生成代码确认：**旧动作表先筛选结果为PASS的历史记录，再合并H/M配置。它不是已证实的执行前完整候选全集。**

例如，历史上尝试了配置A和B，但B没有PASS，旧动作表可能只留下A。即使删掉表中的质量数值，A这个清单仍然经过结果筛选。因此，E35的映射账目对齐，不能直接推导出候选没有遗漏，也不能马上训练。

这不是证明B一定缺失，也不是断言原始生成证据不存在；当前查清的是生成代码的筛选规则，未读取实际候选或质量行。

另一个实际阻塞：对本地`runtime_training_staging_20260928/formal_candidate_space_v2_r1`做一次目录列举时返回Access denied。没有重试、改变ACL、提权、改用其他路径绕过，也没有读取该目录下任何数据。这个阶段的真实全集连接尚未执行。

## 目的与本阶段范围

论文核心目标不变：固定H64/M16/F4、D95安全组合，减少命中近优解之前累计ATPG wall time；不是把ATE cycles叫作运行时间。

本次授权接续E35，只核查候选/source全集及生成依据：

- 读取仓库中的生成/映射代码和合同，核查结果筛选、ID和行序规则。
- 定义六TRAIN的无质量元数据清单，以及提供清单内部的覆盖/唯一连接检查接口。
- 以人工构造的小数据验证接口；不把测试数据或接口通过叫作真实候选审计完成。
- 不读质量值、validation/BLIND数据、真实候选行、原日志或checkpoint，不访问A/B，不训练、不提交LSF/Tessent。

使用AgentFleet分工：源码只读核查、独立接口实现、独立复核；父代理负责范围、合同及最终封存。数据质量流程要求把“文件内覆盖”“生成全集”“执行前冻结”分别标记，避免给一个笼统PASS。

## 已核实的源码事实

| 源码 | 实际行为 | 对后续的影响 |
| --- | --- | --- |
| `src/data/build_formal_candidate_space_v2.py:119` | eligible由`result_status == PASS`生成 | 动作入选受运行结果影响 |
| `src/data/build_candidate_space.py:28` | 筛eligible/formal/HF或HMF阶段后才建动作 | edges不是天然的完整候选清单 |
| `src/data/build_candidate_space.py:45` | 按电路、HF/HMF、H及可选M合并，F不作为动作key | key不含F，并不能消除前面的结果筛选 |
| `src/data/build_formal_candidate_space_v2.py:176` | 空candidate回退为文件内1-based数据行号，所有alias都可能触发 | 不能仅凭refine推断ID来源；必须保留原行序及文件SHA |
| `src/data/build_formal_candidate_space_v2.py:190` | 输入行先全部进入normalized，然后另建筛选后的actions | 可核对提供源表的行覆盖，但不能证明源表涵盖全部生成尝试 |
| `src/data/audit_runtime_action_attempt_mapping_v1.py:138` | 由selected action列出的source建立正式连接 | 不能从edges反推出全部source |
| 同文件`:173` | 全源索引用于解释非eligible/search排除 | 解释过排除不代表被纳入完整候选集合 |

既有合同也明确PASS与零outcome冲突门槛。本阶段没有运行这些旧builder/mapper，因为它们会读取结果和质量相关字段。

## 最小补齐数据：只需要清单，不解封整套标签

新的[合同](../../contracts/ranking_v6_source_roster_e36_v1.json)要求三个小型元数据集合：

1. **源清单**：电路、阶段、HF/HMF、H/M、candidate ID及其来源、source UID、action UID、原文件SHA、原始行号。每份表保留所有行，不能按PASS/eligible过滤，也保留没有映射引用的行。
2. **24文件目录清单**：六TRAIN × hf/hmf粗网格/整数细化，每个文件的SHA、数据行数；即使零行也必须明确列出。实际数据行覆盖2到N+1，不能漏行后重新编号。
3. **现有映射投影**：不同的source/action/circuit三元组。它不是重复session边，也不重新运行旧mapper。

上述字段不包含cycles、D95、F结果、PASS/FAIL、eligible、runtime或outcome_conflict。H/M是动作输入配置，不是质量标签。

接口检查精确字段、TRAIN范围、规范ID、配置一致性、原行号完整性、source唯一性、孤儿连接，并单独统计mapped/unmapped；不会因为某条无映射就删掉。声明文件哈希/行数相同仍不是来源认证。

## 三种完整性必须分开

| 级别 | 需要什么证据 | 当前状态 |
| --- | --- | --- |
| 提供的历史表内行覆盖 | 完整元数据导出、24文件清单、原行号及字节绑定 | 导出不可用，未做真实检查 |
| 历史生成候选是否齐全 | 生成器/配置/网格、refine父配置、尝试清单与源表对应 | 还需证据，不能由edges或PASS动作证明 |
| 结果读取前已冻结 | 先验输入与可信冻结回执、发生顺序证据 | 未认证；现在算SHA或查看mtime不能补造过去的冻结 |

风险为高：若把筛选后的集合当部署候选全集，会高估推荐成功率，且可能漏掉失败探索成本。源码筛选事实置信度高；真实遗漏数量、时间趋势和环境新鲜度本轮未测，不能编造比例。

## 后续按什么顺序推进

1. 取得上述无质量清单和原24文件目录清单。在当前权限拒绝下，不打开受限质量目录或通过替代路径读取；更合适的做法是在明确授权的来源端导出无质量投影。
2. 运行本阶段的覆盖检查，将全部历史source（包括无映射者）与E35映射对账；先逐条解释差异，不强行补边、不重新编号，也不补跑ATPG。
3. 独立核对生成/冻结依据。若只能恢复历史观察清单，就明确标记`RECONSTRUCTED_OBSERVED_ROSTER_ONLY`，不能宣传执行前全集或在线加速。
4. 最后再按原held-out规则安排质量连接与生产训练门禁。历史引用费用代理可用于其明确限定的历史回放问题，但不能替代论文希望证明的线上增量wall time；本次不偷偷修改研究目标。

## 测试和复核的真实状态

新增9项接口测试；父代理完整相关回归473项，其中468项实际执行通过、5项条件跳过，失败/错误0，耗时43.880秒。没有把重复测试叠加计数，也不称Linux零跳过验证。

首次独立复核读完代码、测试及合同，未报告I/O或范围阻断，并特别指出：如果导出者同时把roster和inventory按PASS过滤，两者仍可能内部一致；所以必须另核真实来源和生成证据。该次复核在准备独立测试时触发usage limit；原中断回执保留，不把它算成PASS。

恢复后，原独立复核代理已完成9项测试（0跳过/失败/错误）、动作分区守恒例子和四种alias回退检查，最终通过**接口与科学边界复核**。源码/测试哈希未变，沿用已通过的473项完整回归，不重复计数。见[恢复与来源定位回执](../../data/manifests/ranking_v6_e36_resume_20261016_r1.json)；[首次进度回执](../../data/manifests/ranking_v6_e36_progress_20261016_r1.json)保留为历史。这里没有做Notebook或真实数据分析运行；接口的精确可执行检查保留在`tests/test_ranking_v6_e36_roster.py`，不拿合成接口测试冒充实际清单覆盖。

## 不需要用户记住目录：已找回的来源线索

对仓库脚本、合同、文档及历史提交的有界定位，没有找到三组实际`--phase2/3/4-root`参数或完整生成命令。不能猜测根目录后直接读数据。

但已确认旧builder会生成`source_provenance_v2.tsv`，仅含电路、stage alias、原文件SHA、归一化文件SHA、行数和basename六列；`receipt_v2.json`的`sha256.source_provenance`绑定它。首批需要的是该文件六TRAIN×四alias的24行元数据及匹配回执，不是解封整个候选质量目录。它还不是完整逐source行清单，取得后仍须继续全行投影。

代码推导的候选位置是本地`runtime_training_staging_20260928/formal_candidate_space_v2_r1/source_provenance_v2.tsv`，**未核验该文件存在或可读**；父目录拒绝访问后没有改路径尝试读取。恢复脚本记录的A端Phase4原始根`/temp/jiangchuanc/multimode_ate_phase4_20260825_A`也不能直接当作formal builder的扁平输入根。

用户不记得路径不是实验错误；来源定位与记录由代理维护。当前仍需可读且获准的无质量导出，不能把没有找到的命令、文件或冻结时点编出来。

当前封存内容是源码结论、无质量清单合同、接口验证及完成的独立复核。实际清单连接仍被缺少可读导出阻断，E30训练门未放行。
