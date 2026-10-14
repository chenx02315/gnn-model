# E02：真实 scorer 参数梯度接线

- 问题：目标的分数梯度能否正确传回现有候选 MLP？
- 设置：现有工厂、1,345 参数、CPU float64、固定合成夹具；B 新隔离目录一次验证，单 CPU、内存硬上限 1 GiB、额外 swap0、零重试。
- 结果：非零参数坐标和完整目标链有限差分通过；完整链风险误差约 2.30e-11、成本约 1.22e-9（阈值1e-5）。
- 局限：未更新权重、不拟合、不读真实标签；依赖版本核验不等于完整原生库不可变证明，也不等于训练有效。
- 证据：[回执](../../data/manifests/ranking_v6_scorer_synthetic_validation_20261013_r1.json)、[独立复核](../../data/manifests/ranking_v6_scorer_independent_review_20261013_r1.json)。封存提交 `1755f21`。
- 原始日志 SHA：`f666fb7d8d57ce5bc0e4f9a073094afcdfb0f7be6930a541b2ef2ae0b7a32cbc`。
- 放行：只有合成接线验证，不放行 optimizer 或训练。
