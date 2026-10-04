# 排序 v3：实现阶段与执行边界

当前阶段：实现与本地合成测试，不是训练运行。v2 原结果和模型不覆盖；本版不访问 VALIDATION、BLIND、A/B，不新增电路或Tessent作业。

## 已实现

- 六个 TRAIN 家族内部留一家族的确定性分折。每折五家族拟合，一个家族评估。
- 折内标签：`log(cycles / 同电路拟合集已测oracle)`。oracle仅用于拟合标签和事后评估，不输入推理。
- 同电路两两比较，低cycles候选的quality score应更高；相同cycles忽略。每家族最多4096对，按固定seed的SHA-256选择，不挑正例、不跨电路配对。
- 各家族pairwise softplus损失等权，避免spi候选多就主导梯度。不训练稀缺epsilon分类头，也不把quality score称为概率。
- 特征白名单、仅拟合五家族的归一化、拒绝拟合阶段传入留出家族outcome、候选MLP和GraphSAGE质量头的构造代码。
- 留出家族完整分数与排名绑定SHA-256后再回放；保持epsilon=1%、K=10。到首次命中即停止累计wall-time，否则记满10次成本。`best_cycle_regret_at_10`是离线前10候选集合质量，不冒充实际停止前已观测质量。

## 已测试与未验证

纯Python合成测试覆盖分折隔离、标签/特征边界、家族等权、配对上限、输入顺序确定性、无穷/NaN、unsafe拒绝、freeze篡改、10次预算和首次命中停止。

本地没有PyTorch，神经网络前向/梯度测试明确skip，因此模型执行门禁未通过。代码核心没有训练CLI，不存在自动解封训练权限。合同不是独立审核PASS。

## 下一阶段任务清单

1. 独立设计/代码复核：审查预注册协议、原始候选特征构造、oracle只作为label、pair sampling和不同模型公平性。修订必须新版本且保留本版证据。
2. 实现fold隔离数据导出与runner：每折拟合标签物理分离；held-out labels只由freeze后的评估步骤读取。核验现有v2 package/hash/graph_manifest，不直接把预测排名TSV作为训练输入。
3. 补齐XGBoost `rank:pairwise`基线、三seed聚合、固定启发式及fold receipts。树模型/神经网络的pair sampler不同，要记录而非声称损失完全相同；以数据边界、特征、折和评估预算公平为底线。
4. 在获准的隔离依赖环境做synthetic-only前向、梯度、重复seed与完整runner测试；不安装到历史环境，不覆盖旧checkpoint。
5. 数据防泄漏与独立复核都PASS后申请独立训练release，才执行6折×3固定seed的TRAIN内部实验；不得只挑最好折或seed。
6. 六折结果按家族等权汇总hit@10、best regret、首次命中累计wall-time和no-hit率。不因2%/5%统计更好而改变正式1%标准。
7. 再决定是否需要补电路/改图表示。现有VALIDATION已经用于v2诊断，应标注为已观察开发证据；不能称为全新独立验证。未来v3使用该验证集需要预注册一次评估且披露适应性，BLIND继续保留。

## 尚未执行

没有训练、调参、fold数据发布、remote部署或新盲测；没有证明v3好于v2。优先目标是验证新电路候选排序，再考虑成本策略，不直接用任意quality score除runtime。
