# v5 父进程回执与完整调用链字节绑定

本节点继续为受控 launcher 补齐验收条件，没有启动真实训练。正式目标仍是减少命中 D95 安全近优组合之前的累计 ATPG wall time；不修改模型、目标函数、特征、seed 或拟合协议。

新增本地 `ranking_v5_caller_source_bytes_20261008.json` 封存 26 项 raw worktree SHA，170740 字节、31 项 lock；manifest raw SHA 为 `5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7`。它只是本地字节基准，不是生产包、B 部署证明或审批 trust anchor。Git checkout 换行转换可能改变原始字节，未来部署须重新核对/封存，不能跳过 SHA 门禁。

源码 helper 固定接收 26 项调用链/锁文件字节（包括自身和新增父回执 helper），要求外部独立取得的 manifest SHA、精确集合、每文件 SHA、每文件 64KiB 与合计 1MiB 上限。锁文件拒绝未固定版本、重复规范化包名、选项及不完整核心依赖。测试包含当前本地 26 文件与 31 项版本锁的实际字节校验，但不代表 B 端文件已经部署或对应依赖已经安装。

父回执 helper 对 guard 返回值与独立读回对象逐字段核验，要求严格类型、状态成功、exit=0、至少一次采样、合计 RSS 不超过 1GiB、AS/线程/单 worker/零重试策略不变、reserve 一致及有限正运行时间。可选 RSS 退出边界必须有成功 leader 和空 live group，不能通过退出边界伪造零采样 PASS。独立复核发现“正采样但合计 RSS=0”可通过，已聚焦修复：合计峰值至少为 1，允许退出竞态下 child 峰值为 0、parent 峰值为正。

两项 helper 都是纯函数：不读生产输入，不导入 Torch，不创建子进程。传入对象的 SHA/一致性不能证明真正独立读取、实际采样、用户授权或审计者身份。当前 25 个 Python 源文件覆盖静态发现的本地依赖，再加锁文件，共 26 项；这不是执行时 import fence。仓库使用 namespace packages，没有 __init__.py，未来 bootstrap 必须另核验搜索路径、模块实际来源和完整锁环境；若 launcher 增加文件，源码集合必须升级。

仍未实现正式物理 CLI、受控父 launcher 和串行 18-fit 调度，没有真实 Linux 正向回执。旧 synthetic 入口不改、不用于生产；既有历史模块与 v4 设计/证据不修改。正式放行仍为 false，BLIND/VALIDATION/PILOT/LSF/Tessent 不开放。

最终测试、SHA 和独立复核以 `data/manifests/ranking_v5_parent_binding_validation_20261008.json` 为准；完整回归 r1 早于零 RSS 修复，不能作为最终封存 PASS。下一步按 v5 设计继续受控入口与 import fence 实现，而不是原样重跑训练。

修复后独立定向复核 37 项、0 skip、0 failure/error，通过。最终完整回归 r2：901 项、32 skip、0 failure/error、exit 0、152.555 秒；raw log SHA `84706b8f9775c4a18988d8cd69778358ddf104977c75859fd756875ec28a4bc2`。日志路径相对仓库父目录的 workspace 根目录，不相对仓库。正式 worker module 仍以 CLOSED/exit1 拒绝直接执行。
