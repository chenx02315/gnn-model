# E126：有真实证据的PT标签修复

## 已做完什么

本次E125完整回读已独立核验24/24文件及日志/ACK/进程/准备/summary关联。Tessent确实执行create_patterns并按1-pattern请求限制正常退出，先前的内部名称修复有效；随后失败来自自写统计解析器，不是Tessent运行失败。

旧E115仍保留原样。在独立E126模块中只把本地PT标签表改成实际第13行已见的posdet_testable，原顶层/子类边界、未知类/重复拒绝、共同故障分母与分区、pattern和完整原字节约束不变。不替换或正规化输入，不篡改报告SHA。

真实2681B统计现在可解析：分区合计71216，DS+DI=18323，PT64单独保留，不加入检出数。仍只证明统计解析，不代表完整STIL/MTFI/共同故障并集资格，也不把wrapper的11.875821秒写作ATPG内核耗时。

## 验证

E126/E115联合18项独立测试通过，Python3.6 AST通过；新旧完整选定回归277项通过，0跳过/失败/错误。原始回归小日志位于 runtime_training_staging_20260928/v6_e126_local_repair_20261027_r1/regression.log。源码、测试、真实统计与E125响应SHA及独立结论保存在 data/manifests/ranking_v6_e126_parser_repair_review_20261027_r1.json。

E126 source SHA：12fdb3e3cb7b52c32465f461fa63a6598f6bac555669d63540ac18e0bd3174a0。

E115 source SHA仍为102ed449c9f12f46edebd5ab31bb99b8e14c3f465b0ac70b5121606ad3617b0d。

## 后续边界

本轮没有重试Tessent或训练。E124一个版本已消耗，0任务提交/0翻译的失败状态不回填为通过。E126尚未接入新的获授权实际采集包。

下一整包先本地接好E126报告依赖、精确源码/新目录/新授权/新计时，再完成独立门禁；获新整包授权后才可在新目录从3自检开始采集18动作。提案为 contracts/prospective_pt_label_repair_proposal_e127_v1.json，PENDING不是授权，不会因目标自动继续而擅自重跑。
