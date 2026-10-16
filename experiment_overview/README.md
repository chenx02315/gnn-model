# 实验结果总览

这里用于整体复盘，不存放完整实验数据、checkpoint、逐轨迹结果或 Tessent 导出。

当前主目标：固定 H64/M16/F4，在 D95 安全动作内推荐 ε 近优组合，降低命中前累计 ATPG wall time；ATE cycles 是不同指标。

## 阅读入口

- [E35映射与费用口径](entries/E35_mapping_metadata_and_cost_scope.md)：25,437条session完整分区，7组跨stage记录均无当前候选引用；3次失败均有范围外阶段排除记录。明确唯一session秒数与历史引用费用代理不同，未放行训练。
- [E34真实TRAIN计时审计](entries/E34_train_metadata_readonly_audit.md)：现场12文件SHA全部吻合，计时表/lineage各25,437行；s38417已定位7个group跨stage，3次失败的28.410秒保留，下一步核对调用归属，不放行训练。
- [E33历史会话图与计费口径](entries/E33_source_semantics_and_session_graph.md)：源码核对发现旧共享/重复语义不能直接接 E31；新增生成图诊断，区分独立 session 总量和逐候选 proxy，不是实际来源或训练放行。
- [E32本机文件冻结](entries/E32_local_file_freeze.md)：继续补普通文件读回及 callback 前置校验；只用临时生成文件，不是真实标签或训练放行。
- [E31切分、计费与连接](entries/E31_materialized_fold_and_accounting.md)：已补纯内存拟合集接口、失败/timeout/重试全计账本及六家族伪造连接验证；不是实际日志恢复或训练放行。
- [E28目标接线](entries/E28_joint_wiring.md) → [E29实际参数核验](entries/E29_parameter_chain.md) → [E30真实TRAIN方案](entries/E30_real_train_plan.md)：一次授权的三阶段已完成；前两步验证通过，第三步仅方案封存，正式训练未启动。
- [E27非均匀评分验证](entries/E27_nonuniform_risk.md)：6/6固定三档评分配对达到梯度判据；风险/正例误差4/6增大，未运行模型训练。
- [E26独立预采样基线](entries/E26_independent_pilot_control.md)：同每方法512条预算，6/6固定均匀配对改善；未认证大规模非均匀精度或训练就绪。
- [E25多正例风险信号](entries/E25_multi_positive_risk.md)：一次固定合成诊断完成；正例有信号但负例方向仍有噪声，不是训练放行。
- [E23接入审计与多正例数学核](entries/E23_real_bridge_readiness.md)：已补完独立复核和数值修复，保留首次中断/缺陷记录；不是训练放行。
- [E24合成接口接线](entries/E24_synthetic_bridge_adapter.md)：费用/输入分离、完整多正例集合、错UID和非FIT拒绝通过；未接真实reader或模型。
- [近期 v6 数值实验总览](2026-10-14_v6_validation.md)：每步目的、设置、结论、局限及证据链接。
- [逐步记录](entries/)：每一个步骤单独记录，不混淆实现验证和实际实验。
- [下一节点账本](NEXT_TASKS.md)：真实依赖、验收清单与仍关闭的权限，避免重复实验或直接跳训练。
- [逐步记录模板](ENTRY_TEMPLATE.md)：后续每一轮实验统一记录，失败与不确定结果也保留。

本次先回填已核验的近期 v6 步骤，不宣称已整理全部历史训练。历史 v4/v5 等结论仍以各自封存记录为准。

## 记录规则

1. 执行前记录实验 ID、假设、固定样例/切分、seed、样本量、预算、指标、判据和源码版本。
2. 执行后记录真实状态：实现通过、数值通过、方向通过、精度不确定、失败等不能混称“成功”。
3. 精度通过不等于方向可靠；合成样例通过不等于泛化或 ATPG wall time 改善。
4. 只放摘要、少量关键数字、证据路径/SHA、独立复核和下一步。原始结果留在专属 staging 或既有证据目录。
5. 所有已执行步骤都需保留，包括失败、程序性修复和未运行的限制。不事后删 seed、改阈值或挑最好结果。
6. 已封存步骤不覆盖；修复/复跑创建新版本并注明前序 ID。Git 同步代码、合同和小型总览，checkpoint 留在 B 端。

## 本轮边界

本地合成数值验证、一次B端E11参数探针、E12带偏置与E14无偏置的两次独立授权小型合成SGD拟合（均已执行并恢复参数、丢弃最终权重），以及E13只读诊断。不读取真实电路标签，不运行正式TRAIN、BLIND、LSF/Tessent；新增拟合或容器实验仍需具体授权。

最新补充：E22已完成追加授权的两组×3seed×24步实际合成拟合与独立复核，见[E22记录](entries/E22_paired_fit_completed.md)。全程1GiB/单worker/零重试，参数恢复、最终权重丢弃；本目录只收摘要，原始评分和轨迹留在专属staging/B端。历史步骤中的“未部署/待授权”描述保留其当时状态，以最新任务账本和新增记录判断当前节点。
