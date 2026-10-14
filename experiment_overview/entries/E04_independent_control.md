# E04：独立 pilot 控制变量

- 问题：减去基线能否保留全部 UID 的正确期望梯度？
- 方法：独立 pilot 冻结风险/成本基线，main 使用 direct+(F-b)·grad(log q)。
- 结果：新增9项测试实际通过，全 UID 精确 oracle 期望不变、正例坐标逐轨迹不变、零成本与非法输入边界通过。
- 局限：这是实现/无偏性验证，没有进行该版本的大规模方差比较或 CI 运行；不宣称最优基线或普遍降方差。
- 证据：[回执](../../data/manifests/ranking_v6_conditional_control_validation_20261013_r1.json)、[复核](../../data/manifests/ranking_v6_conditional_control_review_20261013_r1.json)、[说明](../../docs/ranking_v6_conditional_control_result_20261013.md)。封存提交 `780ae9c`。
- 放行：支持 E05 精度实验，不放行训练。
