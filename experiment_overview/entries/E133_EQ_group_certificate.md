# E133：已有AES H→F前缀的完整EQ分组与覆盖率证据

## 最终结论：工具分类审计通过，真实H+F联合D95安全性仍未证明

独立终审已完成：106项选定回归通过，完整七文件、r2语法修复、逐行类别/键集合、全部45559组及统计均独立重算吻合；独立重算没有调用生产分组函数。检测集合、完整canonical集合和组映射三个SHA均与候选一致。还确认存在11226个跨极性EQ成员，不能加“同极性才能等价”的假设。

但有一个不能跳过的跨模式问题：F开始前通过read_faults -merge导入了H的检测状态。H的pattern检测A，而F把B列为A的EQ，并不能自动证明H的pattern也检测B。工具状态中的代表→EQ展开、完整集合和逐类统计即使完全一致，也没有证明这种跨模式检测信用保持。

因此只封存“合并后工具分类状态”的计数审计，文件data/manifests/ranking_v6_e133_observed_classification_proof_20261027_r1.json；它明确not_a_physical_D95_safety_certificate=true，以及：

- physical_HF_pattern_detection_union_verified=false；
- transfer_EQ_equivalence_preservation_verified=false；
- physical_HF_D95_certificate_sealed=false。

正式终审回执为data/manifests/ranking_v6_e133_final_review_20261027_r2.json。69062/71216只表示工具状态分类达到95%的数学门槛，不能代替真正的H+F pattern检测并集。本包没有达成物理D95安全证书这一结果，不把较窄的技术PASS当成真实目标完成；旧D95、E127失败、stage/action acceptance和训练状态都不改。

## 下一步：只补跨模式检测信用的实证，不重跑ATPG

从已有本地E128/E130来源中已找到6个额外工件的确切路径、字节数和原SHA：H的初始basic、最终MTFI/报告/统计，以及H→F的translated_status和translation_manifest，共7321426字节。它们尚未取回，也未假装已验证。

新提案contracts/physical_hf_detection_credit_audit_proposal_e134_v1.json合并了隔离审计器、反例测试、一次限定读取和独立物理推理终审：先恢复H自身可靠检测集合，再核对导入F的状态，对所有相关F等价成员检验检测信用是否保持；若不保持，只能用可证明的保守物理并集。任何涉及F分组稳定性、前后状态来源的推理必须给出证据；不能证明就仍记未证，不能拿总数匹配替代。

E134尚待明确批准，不能使用E133已经消费的单次访问。提案仍不允许Tessent/ATPG/故障仿真新运行、LSF、B、BLIND、训练或旧合同改写。它不保证能够仅凭这些工件完成物理证明；若不足，必须如实保留缺口，再讨论是否需要另行授权实际fault simulation。以下为终审前候选快照。

## 最新实际进展：七文件已取回，r2候选全量核验通过，待独立终审

唯一一次A端只读读取成功，七份正文共10404024字节，均匹配E130原始SHA；响应13876133字节，SHA-256 07bcc39f355d2fe007a981f39a33161bc40dd27000c3af7ca9856fe699d65d9a。reader源码与预审精确包一致，无远端重试、新工具或新时钟。原始响应、文件副本和回执保存在本地staging的v6_e133_eq_group_readback_20261027_r1，Git只保存代码和小型摘要。

第一次本地r1解析在REPORT_NATIVE_PATH失败：报告中5280行使用外层双引号包围含内部空格/反斜杠的路径。逐行诊断表明，只删除成对最外层引号即可与全部对应native键和类别精确一致，不需要unescape或修改内部字符。保留原393e919a源码、测试及失败记录，在两个全新r2文件内作唯一聚焦语法修复；读取器不变，也没有再访问A。

r2专项17项及新旧联合246项通过，均无跳过/失败/错误。父代理随后用七份真实完整正文得到以下候选结果，尚未封存：

| 核验项 | 实际候选结果 |
| --- | --- |
| 完整共同键集合 | report/native/basic/canonical各71216，逐键匹配、无重复/缺失/模式外键 |
| 报告等价组 | 45559组，25657个EQ成员 |
| DS组内EQ | 24931个；DI组内EQ为0 |
| 未检出代表组内EQ | UO组700个、UC组26个，均不计检测信用 |
| 展开后逐类统计 | DS65349、DI3713、AU15、UC45、UO2092、UU2，与statistics逐类一致 |
| 工具状态DS+DI计数（非物理联合证明） | 69062，整数门槛67656；PT/PD信用0 |
| 范围 | 仅既有aes_core:HF:h1终端post-H→F状态；不是F单模式或全部18动作 |

这里的EQ分类现在来自完整报告分组核验，不再只是E130中统计差值的相容推测；正式结论仍须独立终审确认。候选规范047d0217不变，候选摘要SHA为6df811677dafdd77bb625a2a62e5d02ac94389c86d70fcc5f71e113f2c4ca990；检测集合SHA为d7a2652d84538287d2541e1664dc4c5b09f0464c7179b2fc86440b7e29dd0a07，完整组映射SHA为050bbf119954293b86fb2e9c142b0afeebc34453f82bff5908ca17f22ca3cf6b。

候选文件data/manifests/ranking_v6_e133_actual_candidate_20261027_r2.json保持unsealed、independent_final_reviewed=false；旧D95/E127失败、完整stage与训练均不放行。下一步只做本地独立终审，不再取数。以下“尚无A访问”为读取前快照。

## 目标与授权

用户明确回复“批准 E133 整包”，记录contracts/eq_group_coverage_certificate_authorization_e133_20261027.json，SHA-256 cdfd9f7eca7f7c0eee875c486db091a1b93832c73092aa2e92810c94afddced2。原提案保留为待批准时快照。

本包不是重跑ATPG，而是核实已经存在的aes_core:HF:h1:F终端状态：哪些EQ成员属于合格DS/DI代表组，并能否在冻结共同集合71216个故障上达到整数门槛67656。只认证观测到的H→F前缀；F状态含此前合并信息，不能说成F单模式，也不能外推其他动作。

## 一次性读取边界

只允许A端7个确切工件，原大小合计10404024字节，原SHA均已由E130记录：共同集合manifest、canonical映射、F初始basic、F最终MTFI、F前后statistics和F报告。每文件8MiB、正文合计16MiB、响应24MiB；单次60秒、捕获窗口300秒、采样512MiB、1版本/1次访问/零自动重试。不搜目录，不访问其它电路、B或BLIND，不启动Tessent/ATPG/LSF/训练。

全部七份完整SHA验证后才发布本地副本，之后解析和独立终审只用本地证据，不重新取数。旧E127失败、旧D95合同和旧解析器均不改写。

## 实现与前置验证

新增scripts/read_eq_group_artifacts_e133.py和tests/test_eq_group_artifact_reader_e133.py：固定白名单、打开前普通文件/单链接/所有者检查、目录句柄锚定、完整流式SHA、原始响应先留存、全部正文校验后才写出hash-only本地文件名。读取器不做故障语义解析。

新增src/data/eq_group_coverage_e133.py和tests/test_eq_group_coverage_e133.py，配合独立候选规范contracts/eq_group_coverage_certificate_spec_e133_v1.json。真实N时先验证全部固定输入；同次日志/Tcl/任务来源绑定E128完整原响应SHA，不信任调用者提供的布尔mode。分组只来自report_faults顺序，不来自MTFI邻接，也不要求代表与成员同极性；逐键类别、完整集合、逐类展开统计全部对账。

完整共同集合、实际EQ成员、MTFI明确FALSE状态及同state报告生成顺序共同证明“观测报告是完整未折叠表示”；这不是伪造曾显式执行set_fault_mode，也不依赖默认值。检测信用仅按冻结DS/严格DI白名单，PT/PD及未检出代表组不计。

读取器10项、解析器12项专项通过；父代理选定新旧联合229项通过（0跳过/失败/错误），Python3.6 AST通过。解析器测试依赖已有本地E128 fixture，不是独立可移植CI测试；这些仍是实现证据，不是本次真实覆盖率证书。

当前正在做整包最终独立预审，本包尚无A访问，捕获时钟未启动。只有两个组件及规范均通过预审才执行唯一读取。读取成功也不直接放行D95：还须真实全量解析与独立终审，合格后另封覆盖率证据，不升级为完整stage、runtime标签或训练放行。
