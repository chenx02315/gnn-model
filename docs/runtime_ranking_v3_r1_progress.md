# 排序 v3-r1：六折流程与模型适配器

## 本轮完成

- 六折流程：五家族fit-label加载 -> 拟合归一化/模型 -> 留出特征预测 -> 完整排名封存 -> digest确认 -> 留出label加载 -> 预算回放。
- 拒绝正式执行：CLI无生产入口；callback runner仅接受generated-synthetic声明，默认formal模式立即拒绝且不调用I/O。
- 神经排序fit/predict适配器，固定CPU、120epochs、固定三seed、家族等权pairwise loss，无early stopping。
- XGBRanker适配器，固定300棵树、深度4、learning_rate=.03、单线程。只在五拟合家族内生成非负整数relevance，以家族为query，group weights为1，不提供eval_set。
- 18份家族×seed回执缺一、重复或freeze损坏即拒绝聚合；报告所有家族seed指标的算术宏均值，不比较/平均跨fold模型的raw score。
- 新增create-once freeze文件层：独占创建，不覆盖历史文件；flush/fsync后回读并核对digest才返回确认。中途失败文件不作为成功回执，不能自动覆盖重跑。这是封存构件，不是完整原子事务或操作系统隔离。

## 已核实的接口语义

XGBRanker的`group`表示排序query的样本数，`sample_weight`为query组权重而非行权重；实现按家族与action_uid排序数据，提供五个group weights。参考 [XGBoost官方Python接口](https://xgboost.readthedocs.io/en/release_2.1.0/python/python_api.html)。本项目既有依赖锁记录xgboost==2.1.2；网页当前展示版本可能随站点改变，实际2.1.2执行兼容性尚待隔离环境测试。

树模型使用库内采样，不能宣称与神经模型的4096对/家族和macro损失完全一致。公平对比指相同输入特征、五拟合家族边界、seed、六折和评估预算；算法差异必须公开。

## 仍然关闭的门禁

当前机器没有torch或xgboost。合成测试中的mock fit/predict只验证流程和接口，不是模型学会排序的证据。真实模型前向/梯度/fit与重复seed需要dependency-enabled的隔离环境；不得把skip标记PASS。

callback顺序是一项代码边界，不是操作系统级信息隔离。正式runner还需要独立审核的物理fold数据分割、源package/hash校验、完整事务封存、环境锁与正式release；本轮未创建或发布真实fold标签。

旧v3合同、review request和v2结果不改写；新增v3-r1合同明确所有正式门禁false。没有访问远端、BLIND或执行Tessent，没有正式训练和新结果宣称。

## 下一步

在获准的隔离依赖环境完成synthetic模型执行/确定性测试，补齐物理fold包和原子freeze文件层，再提交独立复核。独立审核通过不自动等于正式六折训练授权。
