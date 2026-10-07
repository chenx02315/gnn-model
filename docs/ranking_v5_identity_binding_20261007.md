# v5 数据与审批身份绑定

本节点继续输入适配层，而不是启动正式训练。

数据包入口为 `bind_v3_package_bytes`：20 KiB 上限、同一原始 buffer 的实际 SHA、拒绝重复 JSON key、复用既有 v3 总回执 schema。它校验固定 source/package 身份、六个 TRAIN fold manifest pins、角色/整数 seed、1706 个动作和 outcome、6 张图的计数。后续 caller **只能用 bytes 入口**；`bind_v3_package_receipt` 只是结构 helper，不可拿一个对象和声称的 SHA 当作实际读取证据。

已实际核验仓库中的 TRAIN aggregate 回执副本 `data/manifests/ranking_v3_train_export_20261004.json` 原始 SHA 等于固定 `964703dc...43868`，并解析得到六个 fold pins。这次没有访问远端 package，也没有读取真实 feature/outcome 分片或 held 标签；不能把本地总回执副本验证说成六个实际 fold 均已回读。

审批校验器 `validate_approval_integrity` 将审批和独立复核原始 bytes 绑定到 caller 从外部获得的三个可信 SHA：用户授权、独立复核、物理合成门禁。复核 subject 排除它自身回执 hash，避免循环哈希，但覆盖 release 的其余字段。旧 r4 scope、非 TRAIN roles、额外字段、float 计数/seed、重复 key、字节和 source 漂移均拒绝。

新审批证据 schema 是设计，不是已存在的用户批准。可信 anchors 的真实性仍需外部核验，不能从相同输入 JSON 自取后声称获得授权；函数回执明确 `authentic_user_consent_proven=false`、`training_authorized_by_this_function=false`。没有审批生成器、CLI、执行器或真实训练。

AgentFleet 独立复核：两个模块 IMPLEMENTATION_PASS，仅完整性实现。下一步将 bytes 入口、每个 fold 的普通文件/精确 SHA、现有 adapter 和正式 worker 串接，并补模型/freeze 回读后的 TRAIN LOFO replay。新正式 18-fit、prelaunch 与依赖共享路径来源证明仍未解封；单 worker、8 GiB AS、1 GiB sampled RSS、零重试不变。

最终完整回归 838 项、30 skip、零失败/错误、exit 0，92.298 秒；原始日志 SHA `306f55e975e9b92d19dc1ba2bdcade868ddac32fd68842cb22951ff0b1926fdd`。两新模块聚焦 13 项全部通过。源码/测试 pins 及本地 aggregate 检查边界见 `data/manifests/ranking_v5_identity_binding_validation_20261007.json`。
