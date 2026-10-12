# V5 目标契约审计：源码事实与合成反例

日期：2026-10-12。范围仅限源码阅读和纯 Python 合成测试；未读取真实标签、checkpoint或远端数据，未导入 torch、拟合或调用 optimizer，未修改任何旧 trainer/loss。

## 先说结论

当前 head 目标希望“前十个候选里至少有一个 cycle 近优候选”，不是“尽早命中”，也不是“以最低累计 ATPG 墙钟费用命中”。不同家族完全相同的输入可能具有相反最优方向，这是可构造的数学反例，不能当成真实 TRAIN 已存在该问题的证据。

## 已确认的源码事实

来源：`src/models/ranking_v5_head_objective.py` 的 `build_recipe`、`family_logs`、`loss_reference`、`torch_loss`；`src/models/runtime_ranking_v3.py` 的 `FEATURES`、`feature_matrix`、`fit_normalizer`。

- `K=10`。每家族以最小 `total_cycles` 为 oracle，使用整数不等式 `100*cycles <= 101*oracle` 定义正例，即 cycle 不高于 oracle 的 1.01 倍。这里的 epsilon 不是墙钟 runtime 阈值。
- `build_recipe` 只接受 action_uid、family、total_cycles；拒绝 heldout_family 标签及额外 runtime 字段。
- 非保证命中家族的 head gap 是“最大正例分数减第十高负例分数”，损失为该 gap 的负值经 softplus。负例不足十个时该家族损失为零，但仍进入 macro-family 分母。
- 分数越高越靠前，同分用 UID 排序。`family_logs` 记录 first_positive_rank 和 Hit@10；正 gap 给严格命中证书，零 gap 不是严格证书。
- `loss_reference` 和 `torch_loss` 按家族均权平均，不按候选数平均。测试仅调用前者；对后者的说明是静态源码事实，不是运行验证。
- 当前七列归一化的均值与总体标准差在拟合候选行上计算，每行等权，标准差下限为 `1e-12`。因此候选更多的家族对 normalizer 贡献更大。**家族均权损失与候选计数加权 normalizer 是不同计算环节，不能互相替代。**

## 五项可复核合成测试

测试文件：`tests/test_ranking_v5_objective_contract.py`。运行命令：`python -m unittest tests.test_ranking_v5_objective_contract -v`。

1. 同一组 cycle 标签下，两组分数的首次正例分别排第一与第十，二者 Hit@10 都为 1，而且最大正例和第十负例的边界相同，head loss 也相同。这直接说明当前损失并不唯一确定首次命中位置。
2. 固定同一排序，首次命中排第三。人为指定两个外部 runtime 字典，包含执行首个命中的累计费用分别为 3 秒和 3001 秒。recipe、日志、loss 不变；向 recipe 行添加 runtime 字段被拒绝。费用由测试在 loss 外部显式相加，**不是模型预测，也不是任何真实 ATPG 测量**。
3. 构造两个家族共享相同七维向量 x、y；A 的 cycle 正例为 x，B 的 cycle 正例为 y，每家族十个负例。在任何仅依赖七维输入、且相同输入给相同分数的打分函数下，两家族的严格 head gap 互为相反数，不可能同时为正。这里证明的是表示可能无法满足相反偏好的数学边界；同分下的实际 Hit@10 还受 UID 排序影响，不能把严格证书与所有 tie 情形混为一谈。
4. 两个合成家族分别有 2、11 个候选。小家族为保证命中，loss 为零；macro loss 是大家族 loss 的一半，而不是乘以 11/13。另以这些行构造七维矩阵，规模列 normalizer 均值为 110/13，而非家族均值 5，验证两种权重不同。
5. 合成 oracle=100 时，101 cycles 仍为正例、102 为负例；heldout_family 标签被拒绝。

## 不能据此下结论的内容

本节点没有验证真实 TRAIN 的跨家族 cycle 排序方向、相同向量是否对应相反偏好、runtime 与 cycle 的实际关系，或改用成本目标是否改善结果。此前 feature-only 支持诊断即便通过，也不能提供这些标签方向事实。本审计不挑阈值、不改 K/epsilon、不选 seed、不训练，不把数学反例当成失败因果。

下一步如果要检查真实目标方向，应单独限定到固定 TRAIN、明确定义可读取的标签/费用字段及 join/hash、输出聚合、禁止 BLIND/VALIDATION/PILOT 和训练写入，再进行独立审阅。当前两个新增文件不构成真实标签访问授权，也不自动进入该节点。
