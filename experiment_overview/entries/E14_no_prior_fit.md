# E14：实际无偏置拟合的配对对照

## 结果先说

模型在这些简单合成任务上**能够学会排序**：同样24步，无−3偏置实际拟合后，正例前3命中从10/12提升到12/12，全部12组PL未命中风险下降。FIT六组正例最终均第1；UNSEEN六组最终位置为2、3、1、1、1、1。

但不是完整联合成功：风险和标准化成本同时下降只有FIT4/6、UNSEEN3/6，科学状态仍为NO_JOINT_IMPROVEMENT。高成本正例暴露风险/成本权衡，不能用排序命中改善宣称ATPG总耗时已下降。

这是实际重新拟合，不是E13从带偏置训练评分里减−3得到的反事实。E13反事实是10/12→9/12；E14真实无偏置拟合是10/12→12/12，两者不能混写。

## 唯一干预与配对条件

用户批准的新一轮一次性合成拟合，仅把训练/评价的固定offset由E12的−3改为0。四任务特征/标签/成本、三seed11/29/47、七特征MLP/1,345参数、CPU float64、24步SGD/lr=.2、mean(.5risk+.5normalizedcost)、32+32估计、K3与成本归一化均保持不变。

训练循环、初始化、VJP、梯度平均、采样函数与E12源码一致。E12采样case_id及namespace保留，实际记录三个初始参数SHA和144组控制流派生SHA均一致。共同随机流不等于相同轨迹：改变评分会改变PL/q抽样分布。

无偏置起点不要求risk≥.90，故不作为稀缺正例压力测试通过；仍保留原阈值的报告字段，不搜索初始化或重试。初始风险在普通命中水平而非E12约96%未命中压力条件。

所有三seed最终状态和六评分状态冻结后才调用精确报告oracle；无评价驱动的早停、选最好checkpoint、候选回滚或追加预算。

## 逐组结果

| seed | task | Δ未命中风险 | Δ标准化成本 | 联合改善 | 正例位置 |
| ---: | --- | ---: | ---: | --- | --- |
| 11 | fit_cheap | -0.409334 | -0.251824 | 是 | 1 → 1 |
| 11 | fit_expensive | -0.408550 | 0.001246 | 否 | 1 → 1 |
| 11 | unseen_cheap | -0.269001 | -0.156635 | 是 | 3 → 2 |
| 11 | unseen_expensive | -0.077828 | 0.018848 | 否 | 3 → 3 |
| 29 | fit_cheap | -0.441556 | -0.276774 | 是 | 2 → 1 |
| 29 | fit_expensive | -0.425889 | -0.019648 | 是 | 1 → 1 |
| 29 | unseen_cheap | -0.370127 | -0.208310 | 是 | 1 → 1 |
| 29 | unseen_expensive | -0.240049 | 0.001787 | 否 | 1 → 1 |
| 47 | fit_cheap | -0.178169 | -0.096145 | 是 | 2 → 1 |
| 47 | fit_expensive | -0.179167 | 0.024530 | 否 | 5 → 1 |
| 47 | unseen_cheap | -0.133361 | -0.077195 | 是 | 3 → 1 |
| 47 | unseen_expensive | -0.054136 | 0.003123 | 否 | 6 → 1 |

负值是改善。所有风险差值都为负；成本并非全降。FIT expensive/11、47，以及全部UNSEEN expensive成本上升，必须保留这些负面结果。

六个报告评分状态保留以便与E12结构一致，但PRIOR_ONLY_PL=UNIFORM_PL，COST_PLUS_PRIOR_PL=COST_PRIOR_PL，实际只含四个不同状态。重复对照不算额外独立证据。成本PL仍是−cost/maxcost的随机策略，不是确定性升序；top3是确定性排序指标，PL命中是概率指标。

## 这对下一步意味着什么

- E12的极弱拟合至少与人工不利偏置这一设置明显相关。在固定简单合成条件下，同架构同预算的无偏置拟合明显改善排序，不支持“接线失效/MLP完全学不动”的判断。
- 结论只限这四个人工任务与三个seed，不证明真实电路容量、GraphSAGE有效性或跨family泛化。
- 排序已能改善后，下一重点是成本与命中风险的目标定义，特别是高成本近优正例。不能同时扩电路、加步数、换架构来掩盖当前权衡。
- 可先在已封存评分上只读检查目标/公平基线；若再做训练对照，应一次只改风险优先或成本约束策略，另冻结预算与授权。不自动执行下一轮。
- 当前cost是合成attempt charges，既不是ATE cycles，也不是实测ATPG wall time。没有ATPG加速声明。

## 一次性运行与证据

B端固定Docker，1GiB内存上限、额外swap0、CPU1/worker1、pids64、无网络/只读挂载、120秒超时。执行一次、零重试；3次合成fit、72次optimizer update、144次control、9,216采样轨迹、名义工作165,888、72次精确评价。参数/RNG恢复，最终权重丢弃，不保存checkpoint，不读真实标签，不做正式TRAIN/BLIND/LSF/Tessent。

本地聚焦233项测试零失败/错误，34项是Windows/Linux或已有无Torch跳过。新增5项配对纯测试和1项staging测试实际通过；B端Linux入口11/11、零跳过。独立静态复核后才部署。

- B：`/ssd/cjc/gnn_model_v6_synthetic_fit_no_prior_20261014_r1`
- 本地：`C:\Users\86155\Desktop\new lab\runtime_training_staging_20260928\v6_synthetic_fit_no_prior_container_20261014_r1`
- 11条目压缩包25,889字节，展开92,135字节，SHA/条目/有界解包门禁通过。
- 源清单SHA：`9cf352a587e9ff719156de4634fad7c2e960275f4d04c1c2e5a2e3c93ea2d3a4`
- result.json165,324字节，SHA：`dc8d09347592c7cc7c84eeb28a38467f883bfe5faa31c788178c1deffe2c9e44`
- [小型结果清单](../../data/manifests/ranking_v6_synthetic_fit_no_prior_validation_20261014_r1.json)
- [配对运行合同](../../contracts/ranking_v6_synthetic_fit_no_prior_gate_v1.json)
- [纯标准库目标复算](../../scripts/audit_v6_synthetic_fit_no_prior_recorded_objectives.py)：记录评分72状态最大差约1.78e-15，无模型或采样重跑。

独立运行后审计已通过，见[回执](../../data/manifests/ranking_v6_synthetic_fit_no_prior_review_20261014_r1.json)：另写终止前缀PL评价器复算72状态，最大误差3.55e-15；配对三个初始权重、144控制记录、288派生随机流及6个step0 FIT原始评分SHA全部一致。目标复算从记录的分数开始，没有重建模型/VJP/SGD或采样。容器不存在由单独container_absence.json证明，原始result中的未核验字段不修改。版本与来源检查不是所有依赖的不可变哈希证明；本次未测峰值RSS。仅Markdown记录，无图表/HTML视觉验收声明。
