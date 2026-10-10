# v5 合成优化器验证：真实失败与下一步边界

当前结论：本次唯一授权的合成验证已运行并失败，18 项 TRAIN 未启动。不是训练完成，也不是模型排序结论。

执行前，独立复核通过；全量本地回归为 1102 项测试、33 项平台相关跳过、0 失败/错误。原 core26、依赖锁、模型结构与 120 epoch 数值配方没有修改。本地回归不替代 Linux 实际验证。

实际运行在 `/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1`，单 worker、8 GiB 地址空间上限、1 GiB 采样联合 RSS 上限、零重试。创建 Adam 时，PyTorch 经 `_dynamo` 导入分布式模板生成器；已安装的源码会创建临时目录并追加 `sys.path`，因此被固定五路径门禁拒绝，终止异常为 `V5_RUNTIME_SEARCH_PATHS`。失败发生在 INITIAL 日志和 optimizer.step 循环之前，没有成功合成 fit 或正式 TRAIN。

8 次内存采样的联合 RSS 峰值为 496074752 字节（约 473 MiB），未观察到上限触发。资源守卫停止并清理进程组，清理后存活成员为 0。采样不能排除短暂峰值；CUDA 初始化 warning 原样保留，但不是 traceback 的终止异常。实际临时目录名未记录，不对其路径或文件清理作未经验证的断言。

所有原始回执、日志及两个已安装 PyTorch 源码快照保存在本地 staging，SHA-256 汇总见 `data/manifests/ranking_v5_optimizer_failure_20261010_r1.json`。旧 TRAIN r1、此次 optimizer r1、授权级及 child 级一次性标记均不修改、不复用。

下一步先设计新版本的受限动态模板准入：显式将临时存储设在全新 SSD 子目录，限定模块名、生成器来源及模板内容，不能开放任意临时路径或关闭导入检查。设计、实现、独立复核与本地合成测试可与正式运行分开；下一次真实 smoke 需要新的单次执行授权。只有实际 smoke 和独立证据复核通过，才可能放行新的 18 项 TRAIN。BLIND、LSF、Tessent 和受保护目录仍关闭。
