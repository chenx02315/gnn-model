# E12 结论验证：可带限制分享的负结果

## 问题与证据

2026-10-14（Asia/Shanghai），核验一次固定合成拟合能否在拟合和未见条件改善风险、成本与排序。不是正式电路训练，也不检验真实ATPGwall time。

证据为三个seed共享模型、四个预定合成任务的全部记录。每组固定24次更新；没有丢弃失败seed、选最好checkpoint、评价后改变预算或重跑。

## 方法与关键复算

- FIT联合改善3/6、UNSEEN联合改善3/6；分母是task/seed，不是电路数。
- FIT标量目标6/6下降，但joint只有3/6；高成本正例暴露风险/成本权衡。标量目标下降不算安全联合改善。
- 全部12组正例初始/最终均第6，确定性前3命中0/12；PL命中是另一个随机指标。
- independent prefix枚举复算72个状态，最大误差3.55e-15；[脚本](../../scripts/audit_v6_synthetic_fit_recorded_objectives.py)只读固定SHA结果，不重建模型或采样。
- 对照向量固定，重复seed不增加四类固定规则的独立重复数量；成本PL为随机评分策略，不冒充确定性升序。
- 完整协议完成与科学NO_JOINT_IMPROVEMENT同时成立，没有数值失败假装训练成功。

## 必须说明的限制

人工−3偏置直接依赖合成标签，不是生产无标签机制；干净uniform/cost对照没有此劣势，同先验PRIOR_ONLY/COST_PLUS_PRIOR另列。不得做公平算法胜负或真实泛化推断。

参数恢复及SGD次数等由受审源码和日志支持；独立审计没有再建参数张量、VJP、optimizer或重新采样。峰值RSS未测；1GiB是硬上限。

## 复盘判断

现证据优先支持“有限预算下拟合/排序仍弱，并且目标允许两指标互补”，不足以单独认定跨电路迁移失败。下一步先只读诊断和重新定义目标对照，不原样增加训练步数、不立即扩电路。

完整数值、范围与SHA见[E12记录](E12_synthetic_fit.md)、[结果清单](../../data/manifests/ranking_v6_synthetic_fit_validation_20261014_r1.json)、[独立审计](../../data/manifests/ranking_v6_synthetic_fit_review_20261014_r1.json)。本次是Markdown记录，无图表/HTML视觉验收声明。
