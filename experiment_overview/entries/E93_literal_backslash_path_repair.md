# E93：保留路径内部反斜杠的聚焦修复

E92首次真实验证失败，独立审计已确认：相同输入SHA通过E88路径校验，但E89额外拒绝反斜杠，导致MAPPING_CORE_PATH。该推断不等于证明合法Verilog语义或Tessent接受。

修复单独放在 `prospective_fault_translation_v2.py`，不是覆盖已失败版本。原v1源码和测试已恢复为E91原SHA；E92读取器、控制器和r1四回执均保留，不自动重试。

V2仅允许路径内部的字面反斜杠，原样比较、原样输出，不反转义、不归一化、不解释。仍拒绝引号、NUL、CR、LF、TAB、首尾空白和以反斜杠结尾的路径；不声称拒绝所有控制字符。长度、SHA、集合、重复项、模式映射和类别规则不变。清单增加path_policy标记并采用v2 schema。

新增测试覆盖H→M/F三侧一致的内部反斜杠及输出逐字保留，三侧尾反斜杠、引号和NUL、CR、LF、TAB拒绝。v1/v2/E92合计38项专项通过，独立复核结论为PASS_SCOPED_PATH_POLICY_IMPLEMENTATION；Python 3.6 AST两文件通过。相关回归1,319项中6项跳过、零失败错误，72.438秒。回执见 `data/manifests/ranking_v6_e93_review_20261023_r1.json`。若后续执行，必须使用新core pin、新审查回执、新create-once阶段，不沿用E92 r1额度或改写r1结果。

上述是实现阶段快照。随后新E93入口已完成独立预审（51项组合测试、AST三文件通过），完整回归1,332项中6项跳过、零失败错误、75.314秒。未覆盖旧E92输入或回执。

## 新版本真实验证结果

独立预审与完整回归通过后，在新的create-once阶段 `v6_e93_translation_compat_20261023_r1` 实际执行一次只读计算验证，零自动重试。读取同一固定十个TRAIN文件共12,065,221B，SHA与E88/E90精确匹配；aes_core/spi的H→M和H→F四项全部返回PASS_COMPUTED_COMPATIBILITY_ONLY。stdout 4,337B、stderr 0、退出0，无超时/溢出。原始stdout按相同字节保存至 `data/manifests/ranking_v6_e93_input_observation_20261023_r1.json`，SHA为b461f3ede76e88e1b73c25ba616d3047b4d5c56c1bab317dd0c824fd0f000c22。四回执身份见actual_result清单。

这次证明该固定真实输入能通过v2解析与精确集合映射，不证明Tessent接受、电气语义或D95新结果。翻译产物仅在内存计算，没有落盘远端，没有新增ATPG、训练或模型加速结果；remote_termination_verified仍为false，不升级为进程树清理认证。下一步必须验证实际Tessent接受及ATPG资源约束，补齐真实runner，才进入18候选采集；随后仍需同策略家族数据、模型对照和累计ATPG成本比较。
