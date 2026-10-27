# E129：精确AU.SEQ非携带修复

## 目的

修复E127中F产物遇到的唯一未知故障类AU.SEQ。真实E128库存显示3条，统计表把它列为AU(atpg_untestable)下SEQ(sequential_depth)。它不能作为检出或跨模式携带的故障。

## 本地实现与验证

新模块 src/data/prospective_fault_translation_e129.py 仅把精确AU.SEQ加入NONCARRIED，不使用AU或DI前缀通配。source/target解析和translate均真正绑定新分类器；保持旧v2映射、物理路径、大小、SHA、去重、分母与严格DS/DI规则，EQ仍不按相邻行推断检出。

独立36项新旧翻译测试全通过、Python3.6 AST通过。真实证据是E128流式库存和有限样例，未回传的2520140B MTFI全文不能说已在本地完整重放；样例和合成完整流程通过不等于真实namespace、D95或工具接受通过。详见 data/manifests/ranking_v6_e129_fault_class_review_20261027_r1.json。

旧v2 SHA仍为2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961；新source SHA为f659ca52bc6c48645736162223d1f6a931c343d4dd6cafac690aaeff90a2c681。

后续E130在A端对本次完整H/F MTFI及冻结mapping作只读审计：E129真实完整F解析及namespace/去重均通过，H新旧解析结果相同。该新证据不回填本条最初“仅样例/合成”的历史时点；详情见E130实际回执。覆盖语义/D95合同仍未放行。

## 下一步不是重跑采集

当前更关键的是完整共同故障集合与计数口径资格审计。E130拟仅在原E127时钟内读取同一ROOT中9份冻结副本/现有产物，验证canonical键唯一对应、完整source/target集合、报告和MTFI计数差异；不改旧D95合同，不启ATPG，不训练。AU.SEQ修复本身不产生新的采集版本授权。
