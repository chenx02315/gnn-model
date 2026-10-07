# v5 实际合成执行与文件回读

在 B 新隔离目录 `/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1` 完成一次真实 CPU 合成拟合。72 个人工动作、60 个 fitting 动作、120 步优化、122 条 fitting 日志；不是真实电路训练，没有加载真实 TRAIN/held 标签或 BLIND。正式 18-fit 放行仍为 false。

## 实际完成

- 先独立复核源码和部署拒绝测试，再发送 33,582 字节的小型源码包：16 份源码/锁文件加 manifest，共 17 条目；校验 SHA、普通文件、展开大小、精确条目和新目录，禁止覆盖。
- 实际 launcher 调用 `python -B -m scripts.launch_v5_physical_gate`，由现有内存 guard 启动单 worker；保持单线程、AS 硬上限 8 GiB、采样 combined-RSS 上限 1 GiB、零重试。
- 模型落盘 SHA、freeze canonical/file SHA、完整 freeze payload、122 条 fitting 日志及 request/recipe/source/release 绑定均完成实际回读检查。合成审批明确 TEST_ONLY，不作为正式用户授权。
- 用时 3.172274 秒，10 次内存采样；combined RSS 峰值 539,160,576 字节（514.18 MiB），worker group 峰值 519,774,208 字节。采样不能排除 250ms 间隔中的瞬态超限，不冒充 cgroup 硬 RSS cap。
- 本地完整回归：805 tests、27 skip、0 failure/error、exit 0，98.357 秒；聚焦 26 项和独立扩展 47 项均通过，2 个 Windows skip 不是 Linux FIFO/符号链接实测证明。

人工数据 head loss 从 0.704895 降至 0.006132，只说明这个人工样本可优化，不能据此宣称 s13207/s15850 已学好、跨电路迁移成功或 ATPG 时间下降。模型文件留在 B，不送 Git。

## 保留的风险与边界

CPU 测试成功，但仍出现 CUDA initialization Error 2 out of memory warning；原始 stderr 保留且 worker log SHA 与本地有界回收副本一致。没有清理 GPU、隐藏警告、增加资源或重试。当前执行器不是抵御同用户恶意并发篡改的 OS sandbox。

解释器和 sys.prefix 固定为 v3 venv，但 torch 经 v3 的 `locked_shared.pth` 从 runtime-v2 共享 site-packages 导入。这证明共享路径存在，不证明外部包路径具有独立 SHA 封存/不可变性，也不是完全隔离的 v3 依赖来源。两份只读环境日志 SHA 已纳入 manifest；没有因排查而重跑合成拟合。

预执行独立复核只允许一次 synthetic gate；实际证据复核结论为 PASS_WITH_WARNING，保留 CUDA 与共享包来源边界。完整指标、源码 SHA、原始日志 SHA 与该回执状态见 `data/manifests/ranking_v5_physical_gate_20261007.json`。

## 连续推进的下一节点

实现真实 TRAIN 的 v5 caller：精确已封存 package/source 读取、真实新授权与独立回执验证、create-once 新输出目录、fitting-only 标签隔离、模型/freeze 先落盘并回读再加载 TRAIN LOFO held 标签。保留 6 家族 × 3 seed、120 epochs、7 列候选 MLP 和同样资源；仅改头部目标。实现与本地测试可继续，但这次 synthetic PASS 不会自动启动新正式 18-fit，旧 r4 权限也不复用。
