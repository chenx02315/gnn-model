# 下一节点：先检查输入信息，不重复训练

已完成18份冻结模型的真实只读复算；当前五个非保证命中家族仍为0/15 TRAIN留出命中。下面的检查先定位“特征支持不足/联合分布偏移”线索，不把它预先认定为失败原因。

## 已确认的源码事实

当前 CandidateMLP 是7→32→32→1。它只接收以下七列，而不是图编码或电路ID：

| 输入列 | 信息 |
| --- | --- |
| scheme_hf、scheme_hmf | 两个方案指示位 |
| log1p_h_limit、log1p_m_limit | 候选H/M限额的绝对尺度 |
| h_limit_fraction_of_circuit_max、m_limit_fraction_of_circuit_max | 相对该电路最大限额的位置 |
| log1p_common_fault_count | 电路共同故障规模代理 |

定义见 `src/models/runtime_ranking_v3.py` 的FEATURES及feature_matrix。适配器 `src/models/ranking_v5_v3_fold_adapter.py` 会丢弃graph_key等可选信息，metadata也不进入X。因此模型不是“完全没有电路差异信息”，但差异主要是容量/规模代理，不是显式逻辑结构。不能据此直接断言加GraphSAGE一定有效。

归一化只在拟合候选上计算总体均值/标准差，下限1e-12；没有clipping，按候选数加权而非家族等权。留出候选沿用拟合统计量。逐列在范围内并不意味着联合分布有支持。

## 小型、可复核的检查清单

1. 只读固定TRAIN package receipt和六折manifest，核对既有外部SHA、TRAIN角色、六家族、UID唯一连接和每折总计1706候选。
2. 仅允许读取 `fit_features.json` 和 `heldout_features.json`，禁止fit/held outcomes、图原文、模型、BLIND/VALIDATION/PILOT。不得复用load_bound_fold_request/现有adapter，因为它们会读取fit_outcomes。
3. 用相同UID顺序、相同七列与拟合侧公式重建normalizer；每折只做一次，不因三个seed重复读同一特征。
4. 汇总每列的拟合/留出范围、标准差下限触发、超范围数量、最大|z|及各拟合家族的候选数权重。HF/HMF支持须分开核对。
5. 计算跨家族完全相同特征向量的碰撞数量；在相同scheme内计算标准化联合空间的最近拟合支持距离。只报告分布，不依据已知失败标签选择阈值。
6. 输出小型聚合及来源SHA，不导出action UID、特征行、标签或checkpoint；单worker、既有内存上限、零自动重试。
7. 本地合成正反例与零I/O越界测试、独立只读实现复核通过后，才运行固定特征检查；若复核额度不足，保持本节点未执行而不是伪造PASS。

本节点不会训练、改normalizer、调epsilon/K、挑seed或扩充电路。特征支持检查不能单独证明近优排序方向或因果。新电路上下文/图摘要及对应消融必须在证据形成后单独设计，任何新训练仍需对应授权。

2026-10-12执行更新：本节点已按上述范围完成真实六折特征检查及独立聚合收据复核，并自动接续完成源码/合成排序目标审计（5项测试和独立复核）。原计划保留；当前结果见 `docs/ranking_v5_feature_support_result_20261012.md` 和对应validation/metrics manifest。未读取真实标签或训练；下一节点见 `docs/ranking_v5_next_target_diagnostic_plan_20261012.md`，真实TRAIN标签读取仍需新授权。
