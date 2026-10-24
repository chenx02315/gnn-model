# E98 等待期间：六个 TRAIN 家族的数据资格盘点

## 结论与范围

本记录用于回答“接受测试之后，离模型对照还差什么”，不新增训练授权。依据已选取的 12 个小型合同和总览（合计 69,158 字节）的只读盘点，尚未看到任何一个 TRAIN 家族被明确认证为“可信运行前请求 + 同一 F 完成策略的结果 + 完整费用”全部齐备。**这只说明这些摘要没有完成认证，不证明原始证据不存在。**

未读取候选级质量/耗时数据、图正文或 BLIND 标签；未在 A/B 运行新采集或训练。E98 作业只做独立门禁后的最多四项无 pattern 接受测试；接受测试成功也不等于获得 ATPG 训练标签。

## 六家族逐项状态

| 家族 / 电路 | 已有摘要证据 | 仍需认证 |
|---|---|---|
| iscas89_s13207 / s13207 | E34 历史 session/lineage 内部一致 | 新请求谱系、同策略结果及完整费用 |
| iscas89_s15850 / s15850 | E34 历史 session/lineage 内部一致 | 同上 |
| iscas89_s35932 / s35932 | 同上；十选十的必然命中需单独报告 | 同上，不将必然命中解释为模型能力 |
| iscas89_s38417 / s38417 | E34 原 group 跨 stage 为 PARTIAL，不等于重试 | 请求谱系、调用归属及完整计费 |
| iwls_aes_core / aes_core | E34 历史内部一致；E84/E85 输入身份准备 | 输入准备不等于新策略实际结果 |
| iwls_spi / spi | 同上 | 同上 |

名单取自 `contracts/data_split_v1.json` 的正式 TRAIN 成员；其中历史状态字段不是当前全部门禁的汇总状态。不能仅凭旧 split 状态字段推断今天的执行资格。

## 后续依赖清单（不是执行放行）

1. **先取得 E98 实测接受结果。** 实际内存与 Linux/清理门禁先通过，才运行四项接受测试；失败保留证据，零自动重试。它仅验证工具入口，不产生模型效果结论。
2. **资格审计先于新采集。** 按精确调用来源恢复六家族的原始请求，逐项关联 action、attempt、stage、父结果及输入/工具/环境身份。未恢复请求保持未知，不能把实际生成 pattern 数改名为请求。
3. **新策略必须单独成 cohort。** E84 的 F 是一次 `TEST_COVERAGE_LIMIT=95`，不是历史最小 F-boundary。不能混池；请求 95% 也不证明共同故障分母下 D95 达标。新 ATPG 采集仍需明确执行授权。
4. **保留全部状态和费用。** 名单、运行前 ACK、开始/结束、失败、超时、未尝试及共享调用归属都要闭合；分别保留 cycles、ATPG wall time、翻译/setup/session 费用。缺失不补零，不筛选最快成功。
5. **静态特征先做定义资格验证。** 节点/边数量、时序比例、平均/95 分位扇出、组合深度均需可追溯来源；冻结节点、边、自环、单元分类、环与深度规则。未知不能填零。
6. **通过资格后才冻结训练预算。** 对照 A 使用七个请求特征与六个屏蔽槽，对照 B 仅启用六个静态描述量；同为 `13→32→32→1`、1,537 参数。六家族留一家验证、仅拟合折归一化、三个固定 seed；目标、更新和采样预算须先固定。目前训练预算仍为空，不具备训练放行条件。
7. **先区分拟合与迁移，再考虑 GraphSAGE。** 同时报拟合家族与未见家族排序。先完成相同 MLP 的表示消融；E30 历史估计器设计不能冒充本次新对照。最终仍以 D95、近优命中、cycles 和累计真实搜索费用分别评价，BLIND 保持封存。

## 关键来源身份

| 来源 | SHA-256 |
|---|---|
| contracts/data_split_v1.json | ffecd5093453f69c11263501b822ad7bb8f7eefd5da60dd7863331088f6fbcda |
| contracts/model_convergence_e84_v1.json | 0ba3dc3928dcb7ef096909ca8689e75f7022a7cb1c6a31ecb4cb961ee4db7698 |
| contracts/prospective_request_observation_e80_v1.json | 7dd67c93a4fb84f424fb5bce7cfe1867449fa08af967f86bb165b1be07929204 |
| contracts/prospective_structure_features_e85_v1.json | 7f821dfc282748cdf3857617b78c98a422e53d437b58d5226ea757fb531fa333 |
| experiment_overview/entries/E34_train_metadata_readonly_audit.md | 4e123caf43fc8b0969bf0222a515271dadcfa84626b08bef382111e77940cd0f |
| experiment_overview/SOURCE_EVIDENCE_GAPS.md | a11ac0fefdf4aa9505295171f60e24cb02459d6c1ff51e45c73c02d4a644de53 |
| experiment_overview/entries/E84_model_convergence_and_real_input_preparation.md | 111bba3ac1e1cc64a31597d85d7bd82e53ffc619538b9b7235698ffdea5a23e7 |
| experiment_overview/entries/E85_structure_and_real_input_trees.md | b21324ba1b53b7489eef64d6970389e48ff21096b65a16c0fcb5fe4edb68fcf1 |

本记录为依赖盘点，不声称全量原始证据恢复完成、D95 已通过、训练已启动或模型收益已改善。
