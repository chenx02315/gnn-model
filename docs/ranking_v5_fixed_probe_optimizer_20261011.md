# 固定缺席探测修复与单次合成验证

本次真实合成 optimizer 验证已经通过；这仅证明锁定环境能够完成数值路径，不证明 ATPG 排序效果、跨电路迁移或正式训练成功。

## 授权与修复边界

用户批准固定 15 个精确顶层名称的缺席探测修复。早先 fx2trt 单名称批准未消费，与扩展名单批准合计只能验证一次。名单源码、调用者 frame/code、固定五条搜索路径均核验；仅新鲜确认缺席时返回 None，直接导入仍拒绝。不存在任意未知模块放行、不安装依赖、不改变旧核心 26 源码或数值 kernel。

实现和执行前独立复核通过。Windows 完整回归 1170 项、36 个平台跳过、零失败错误；Linux 单独执行 31 项、零跳过失败错误。新 B 目录部署 8 条目、96528 字节，并逐字节读回。

## 实际结果

新目录 `/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261011_r1` 只启动一次，exit=0，完成 120 optimizer steps、122 条拟合记录。全部 15 个探测各执行一次，probe 和 JIT 双证明为真。模型 7752 字节，留在 B；Git 不收 checkpoint。

采样 combined RSS 峰值 533086208 字节（约 508 MiB），11 次采样。保持 AS 8 GiB、采样 RSS 1 GiB、单 worker、单线程、1800 秒超时、零自动重试。采样不能排除采样间瞬时 RSS 超限；AS 与 RSS 并非同一指标。

原始 8 项证据均有界读回并记录 SHA-256；collector 未独立读取全局 once marker，不声称该项已独立重读。正式 fit、正式包读取、held label 读取均为零。

精确来源与 SHA 见 `data/manifests/ranking_v5_fixed_probe_preexecution_20261011_r1.json` 和 `data/manifests/ranking_v5_fixed_probe_optimizer_pass_20261011_r1.json`。后续先完成实际证据独立审计，再将现有固定 18 项 TRAIN 的入口按新证明链集成并复核，不直接复用过期 source pins；BLIND/VALIDATION/PILOT/LSF/Tessent 不在本次放行范围。
