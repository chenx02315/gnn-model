# E09：输入条件风险/成本界的独立 v3 验证

## 固定设置

- 两个 n6 单正例合成样例 mixed/rare，K3、seed11/29/47/83；每样例/seed pilot64、main16384，名义工作2,368,512，一次执行、零自动重试。
- 风险界沿用 E06，成本界使用 E08。完整范围、基线、方向、投影与哈希全部在 main RNG 前冻结，不使用 main 经验极值。
- 新 case-ID 前缀 `nonuniform-precision-v3-` 派生独立随机流。M144、alpha=.01、绝对半径阈值 .02、输出上限262,144 bytes均不变。

## 实际结果

- 精度 `PASS_FIXED_SYNTHETIC_PRECISION_ONLY`：144/144 真值在区间内，所有半径通过阈值，0 数值覆盖错误、0 精度不足。
- 方向 `PASS_FIXED_SYNTHETIC_DIRECTION_ONLY`：风险各自方向8/8认证，成本各自方向8/8认证，同时认证8/8。
- 最大半径 .0059008661，最大绝对误差 .0010819144。各自投影均采用上界严格小于0的判据。

| 版本 | 最大半径 | 风险方向认证 | 成本方向认证 | 同时认证 |
| --- | ---: | ---: | ---: | ---: |
| E05 / v1 | .01746637 | 4/8 | 8/8 | 4/8 |
| E07 / v2 | .01764501 | 8/8 | 6/8 | 6/8 |
| E09 / v3 | .00590087 | 8/8 | 8/8 | 8/8 |

## 可以与不能得出的结论

固定小型非均匀样例中，输入条件界足以在既定预算下验证全部梯度绝对精度及各自下降方向。此前的不确定与保守范围有关，不应据此断言“拟合失败”。

不能把上表当作模型性能提升率或严格同随机数方差消融：三轮随机流和 pilot 方向不同，模型没有训练。两个各自下降方向也不等于同一个有限参数更新能同时减少风险与成本。没有多正例、736动作、真实电路泛化或实际 ATPG wall time 改善结论。

成本仅支持0或[1e-6,1e9]；本固定门禁需成本归一化标尺>0，standalone helper的全零成本分支不是此实验样例。±1e-12保护不是形式化 IEEE 浮点证明。alpha=.01只适用于本轮144比较，不是全部历史实验的共同置信预算。

## 证据与衔接

- [冻结合同](../../contracts/ranking_v6_nonuniform_precision_gate_v3.json)、[小型摘要](../../data/manifests/ranking_v6_nonuniform_precision_v3_validation_20261014_r1.json)、[独立复核](../../data/manifests/ranking_v6_nonuniform_precision_v3_review_20261014_r1.json)。
- 原始248,151 bytes在 `C:\Users\86155\Desktop\new lab\runtime_training_staging_20260928\v6_nonuniform_precision_v3_20261014_r1\result.json`，不复制进总览。
- 原始 SHA：`fe6f3ec920a01c52720c46cb108aef04f3fa8d00267fafebbeb4ae9b84c5c403`。
- v1/v2原结果和不确定状态保留；没有 Torch、optimizer、远端、真实标签、TRAIN 或 BLIND/LSF/Tessent 放行。
- 下一节点：冻结一个受控有限更新的联合风险/成本判据，在独立合成输入上验证“同一次变化风险不恶化且成本改善”；通过后再接真实 scorer，不能直接跳正式训练。
