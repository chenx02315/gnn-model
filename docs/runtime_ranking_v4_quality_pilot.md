# v4：先检验近优排序，再讨论成本策略

v3 已完成且独立审计通过，但没有证明 ATPG wall time 减少。当前不是等待 v3 运行，而是准备一个有边界的质量排序改动。

## 为什么只改一个地方

六个 TRAIN 家族的 1706 个动作只有 14 个达到 cycles 的 1% 近优目标。现有输入没有同家族特征碰撞；这不证明特征足够，也不证明稀缺正例就是失效根因。待检验假设是：连续 regret 的大量排序对可能稀释了真正影响 top10 命中的少量近优区别。

v4 只将 CandidateMLP 的拟合排序对改为“同家族近优动作优先于非近优动作”。epsilon=1%、K=10、六家族留一法、三固定 seed、七维特征与既有架构/训练参数都保持原值。每家族最多 4096 对，按 SHA 排序确定性截取；这是固定算力上限，不是调参结果。各拟合家族等权，不让候选数量大的家族主导损失。

当前纯 Python 模块只构造和核验 recipe，不拟合模型，不读取真实数据，也不绕过旧 runner 的冻结门禁。不能将纯函数测试称为训练完成或泄漏端到端验证。

后续已接入独立的 synthetic-only worker：只接收拟合家族 cycles、全部候选 allowlist 特征，留出 cycles 和 runtime 不进入请求。旧 MLP 的架构、120 epochs、Adam 参数与标准化方法直接复用；仅排序对改变。CLI 核验原始请求 SHA，并将 raw/canonical request SHA、pair recipe SHA 和 freeze SHA 写入回执。先保存 checkpoint 和持久化 freeze，再由合成 evaluator 读取冻结排序并选择留出生成标签。

本地 worker 的4项测试采用 fake fit/predict，不冒充真正神经拟合。Linux 合成 harness 另运行18个唯一家族/seed组合和6次同seed重复，核对排序及checkpoint SHA；合成数据只有每家族3个动作，所以即使命中也没有科学性能含义。B环境使用既有锁定解释器，只读共享依赖，不宣称新建独立venv。

## 连续执行清单

1. 封存 v3 的全部结果、磁盘 freeze 连接和独立审计；保留历史证据。
2. 实现并测试 v4 纯函数排序对：非法字段/数值、正负类缺失、重复 UID、留出家族进入拟合时全部拒绝；检查顺序与家族权重。
3. 独立复核合同、实现和合成测试。只提交代码与小型证据。
4. 下一执行阶段：接入新的训练 worker，继承旧架构/参数和 feature-only 留出输入；增加执行时 request SHA 绑定，跑合成子进程闭环并独立封存。
5. 经新的单一 execution release 后，在新的 B 隔离目录执行 18 次 TRAIN-only CandidateMLP 拟合；不重跑旧对照，不解封 VALIDATION/BLIND。
6. 按家族完整报告命中、regret 和累计 ATPG wall time。主描述剔除 top10 已穷举的 s35932；三 seed 不当成独立家族样本。若质量改善仍不稳定，保留失败结果，不继续任意调参。
7. 只有质量排序有可复现改善后，才另行设计成本决策；不能直接把未校准分数除以 runtime。

这不是“换一个损失就保证加速”。质量目标是 cycles 近优，搜索成本是真实 ATPG wall time，必须分别定义、联合检查。双方共同命中的成本配对只是条件描述，不足以证明总体加速；未命中时少花时间也不是收益。

## 当前权限边界

本地实现、测试、复核和版本同步继续自动执行。新损失不继承旧 v3 的实际训练 release。v4 已通过集成审核并尝试执行：r1 在0-fit阶段因路径门禁不兼容拒绝；r2 完成15/18份评估后因 `MEMORY_RSS_UNREADABLE` 监控竞态安全停止。原根、失败回执和部分结果保留，不在r2重试、不把15+3拼为完整实验。

用户随后明确授权门禁通过后完整重跑18项、不增内存、不再自动重试。只读r2代码快照Linux14项与生成fixture ML均通过，独立绑定release后在新真实r3根单次启动；9/18评估完成后再遇MEMORY_RSS_UNREADABLE安全停止。driver exit1、worker exit0、清理后无存活进程组，未观测到1GiB超额。失败证据已独立封存，不运行第4次、不分析9项部分效果、不拼接历史结果；详见 `contracts/runtime_ranking_v4_r3_recovery_plan.json` 与 `data/manifests/ranking_v4_r3_failure_audit_20261005.json`。A、LSF/Tessent、新电路和 BLIND/VALIDATION 保持关闭。
