# v5 放行与冻结顺序：逻辑门禁，不是正式训练

本节点新增独立 `ranking_v5_execution_boundary.py`。它没有 CLI、PyTorch 实例或远端执行器；用人工数据和注入回调检查训练/持久化/冻结/读取 held 标签的顺序。当前没有创建正式 release，也没有真实拟合。

独立复核已通过这一逻辑边界，之前复现的回调别名篡改、额外源码路径和浮点 seed 绕过均修复。父级 23 项聚焦测试通过（包含额外 2 项 kernel-gate 测试），复核者运行 head/kernel/boundary 共 21 项通过。完整回归 779 项、25 skip、零失败/错误、exit 0，87.581 秒；raw SHA `b3e0c0f3e35e24afaaa338c612f913feb03e292a14e073d4addbcd7709f1f817`。当前状态以 `data/manifests/ranking_v5_execution_boundary_validation_20261007.json` 为准；设计合同保留实施前快照，不是放行证据。

## 不允许什么

旧 r4 放行、synthetic scope、缺失审批字段、错误 package/source/gate SHA、额外 release 字段和非固定参数必须拒绝。源码清单精确包含已验证的 11 个 kernel-gate 输入加新 boundary，共 12 项；不接受盘符/绝对路径/多余条目或非 SHA 值。120 epochs、7 特征、3 固定整数 seed、Adam 参数、K=10、ε=101/100、单 worker、8 GiB AS、1 GiB RSS 配置及零重试保持不变。

这些是**声明与顺序校验**：审批 SHA 格式正确不等于存在真实用户授权，source map 相等不等于文件已经核验。实际调用者仍必须从封存证据读取并验证审批、复核、package、源码与环境身份，不能用自造测试对象解封训练。

## 必须遵循的顺序

1. 隔离请求/release/source map 的快照，验证允许字段与 fitting-only 标签、全部特征有限性及条目上限。
2. fit 只拿到拟合特征、recipe 和固定 seed，不拿 held 特征或标签；传入副本，不能改掉后续预测使用的归一化参数。
3. 计算预期模型 SHA；模型持久化必须回执完全相同 SHA，而非仅返回任意 64 位字符串。
4. 只用 held 特征产生排名；持久化 freeze 要确认确切 canonical SHA。
5. 回读 freeze 完整 payload 和 SHA 并复核，再允许可选 TRAIN LOFO held 标签加载和冻结回放。
6. 回执绑定预先验证的 request/release/source/recipe/model/freeze，不让闭包对外部输入的修改污染审计身份。

这里只能验证回调顺序。回调谎报磁盘写入、模型序列化身份、目录隔离或资源限制，不会由这个纯函数自动检测；实际 worker 必须提供文件 SHA 回读和物理门禁。它不是 OS sandbox。

## 尚未完成的物理执行节点

- 新 v5 worker/launcher：create-once 新 `/ssd/cjc/gnn_model_ranking_v5_train_*`，只读加载已放行 TRAIN package，拒绝 symlink/path/protected-root 漂移。
- 锁定环境与实时 combined-RSS 采样执行器：维持现有内存上限、单 worker、零重试；合成门禁的事后峰值检查不能代替这个执行器。
- 模型/拟合日志/freeze/receipt 的有界物理写入和 SHA 回读测试；不能将合成 helper 的身份转成正式执行身份。
- 实际新 worker 的合成集成门禁、独立复核、明确的新 18-fit 授权和新鲜 prelaunch。

都满足后才可执行目标函数单变量的正式对照。评价先看 s13207/s15850 的 fitting，再看 TRAIN LOFO held；不从 held 结果选择 epoch/seed/超参数，不进入 BLIND，不原样重跑 r4，也不立即加图或大量电路。
