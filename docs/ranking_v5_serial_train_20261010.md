# v5 固定18项 TRAIN 串行执行

历史原矩阵已完成源码实现、独立复核、完整回归、实际包部署及64文件读回，并执行一次真实串行启动。第一项导入门禁失败，验收完成0项，剩余17项未启动；已停止，不自动重试。当前本地修复是新候选，不沿用旧包或旧执行放行。

## 执行范围

沿用用户 `USER_ASYNC_V5_18_TRAIN_20261008` 条件授权：6个 TRAIN 家族 × 3个固定 seed，共18项；单 worker、线程1、AS8GiB、采样合计RSS1GiB、每项1800秒、自动重试0。不访问 BLIND/VALIDATION/PILOT，不运行 A/LSF/Tessent。采样RSS不是硬性cgroup上限。

父控制器先验证实际源码、授权、回执、CPU门禁及全部18份独立输入上下文，再运行第一个worker。跨父进程锁覆盖全矩阵；每个输出及标记均只创建一次。每项退出后独立读回资源回执、stdout末行与四个产物，失败立即停止剩余项，不原目录重试。

## 历史原矩阵已验证

完整回归1075项、33个Windows能力skip、0失败/错误、exit0。实际64条目训练包（36源码、8证据、18 prelaunch、2 manifest）经独立纯验证，大小93,065字节，外部SHA全部匹配。Linux实际CPU导入小张量门禁先前已通过，不重复运行；CUDA警告保留，不宣称GPU可用。

准确SHA、回归日志和审核边界见 `data/manifests/ranking_v5_serial_packet_validation_20261010_r1.json`。完整源码围栏核心26文件未改动；补充模块只在该围栏内以认证字节显式加载。

## 历史原矩阵执行流程（已执行并停止）

包审计通过后，部署至全新 `/ssd/cjc/gnn_model_ranking_v5_train_20261010_r1`，独立逐文件读回，再在固定解释器的新鲜门禁内启动一次串行矩阵。既有条件授权不要求每项重新询问。真实失败保留原始证据、停止未开始项；不能把产物一致性证明提升为数值预测有效或论文改进结论。检查点仅保留B端。

## 实际停止证据

首项 `iwls_aes_core / 20260824` 的进程exit2，日志为 `V5_CONTROLLED_IMPORT_INPUT_PACKAGE_PATH:distutils.core`。8次资源采样，合计RSS峰值496,820,224字节（约474MiB），cleanup后活进程组成员0。未观测到CPU RSS超限，采样不能排除间隙瞬时峰值；日志中的CUDA初始化warning保留，不能将它当作本次停止原因。父矩阵 `STOPPED_NO_RETRY`，验收完成0/18，剩余17项未运行。没有现场栈或阶段回执，不能断言数值fit是否进入，也不声称优化器或训练数值行为已经成功。

精确原始SHA见 `ranking_v5_serial_train_failure_20261010_r1.json`。下一步只读核对setuptools/distutils来源，形成窄范围修复和本地测试；不改B运行目录，不重新执行该根目录，不提高内存，不新增自动重试。

固定文件只读采样与独立审计支持以下静态机制：setuptools66.1.1默认启用local distutils，其shim把父包导向setuptools/_distutils；严格门禁仍要求标准库路径，因此发生拒绝。新本地候选仅在净child环境加入 `SETUPTOOLS_USE_DISTUTILS=stdlib`，不放行任何site别名、不修改导入围栏或依赖锁。修复合同 `ranking_v5_distutils_stdlib_repair_20261010.json` 不产生远端执行权限；原失败目录与旧源码SHA保留。

## 本地 distutils 修复候选

独立77项定向测试通过，3项Linux能力skip，不把Windows替代测试当实际Linux门禁。完整回归r1因本地discovery参数错误在测试启动前失败，原始日志保留；修复discovery后的r2通过1076项，但启动后增加了独立路径拒绝测试，所以不作为最终封存。源码和全部测试固定后重新运行r3，其结果以修复合同的最终回归字段为准。

最终r3：1077项、33个Windows能力skip、0失败/错误、exit0，211.722秒，日志SHA `2bff8eda9037c1aa3220d171c2c9235fc075fc88e4e9ba1ed16896d6d595f4bb`。这只封存本地修复，不冒充真实Linux优化器导入成功。

该候选未部署、未重新运行TRAIN；需要新明确的有界运行范围、新版源文件及训练包绑定、新鲜门禁和独立审核。建议先用一次受控合成数据120步优化器smoke覆盖CPU小张量门禁遗漏的真实路径，全部通过后才可按新授权运行一次固定18 TRAIN。
