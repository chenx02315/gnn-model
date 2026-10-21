# E72：继续补齐 Linux 清理与内存门禁，而不是等待逐步批准

日期：2026-10-21。承接“继续往下做、控制内存”的要求。已连续完成本地实现、第一次独立复核、聚焦修复和新功能复测；本阶段没有访问 A/B、实验数据、checkpoint、BLIND 或运行 Tessent/LSF/训练。

## 先说结论

本地实现已能拒绝不满足隔离条件的运行，并覆盖成功、失败、带一个孙进程的超时场景；异常路径也必须清空进程组，不能只杀主进程。**这是已测试的实现，不是 Linux 实机通过。**

当前客户端是 Windows；有界检查确认 WSL 未安装（命令退出 1）、Docker 命令不在 PATH。实际调用门禁的 Windows 负向入口返回 78、`gate_pass=false`，而不是跳过后声称 PASS。没有为此自行安装 WSL/Docker、修改主机配置或借用新的远端执行权限。

## 已写成代码的东西

### 内存快照一致性检查

`src/data/prospective_linux_resource_gate_v1.py` 只检查调用方传入的 11 字段快照：cgroup v2、有限 memory.max、禁止 swap、OOM group、有限 PID 数、独立作用域和启动前 guard 等。拒绝 bool 冒充整数、`max` 无限值、未知字段与不一致限额。

即使提供一份完全自洽的伪造快照，也始终返回 `os_state_authenticated=false`，不授权作业或训练。512 MiB 只是这个纯检查器的设计容器上限，不是本次真实分配，更不是 ATPG 限额；实际拟执行的小门禁固定在更小的 128 MiB。

### 固定 Linux 微型场景入口

`scripts/verify_prospective_linux_lifecycle_v1.py` 不接收用户命令和输出路径，不是通用执行器。只包含：

1. 一个立即退出 0 的 Python 子进程；
2. 一个立即退出 7 的 Python 子进程；
3. 一个带一个有限寿命孙进程的超时进程组。

启动前检查 PID namespace 中自身为 PID 1，标准 proc/cgroup2 挂载，`/proc/self/stat` 和 `/proc/1/stat` 的 PID/启动 tick 一致，以及内核当前配置为 128 MiB、swap=0、OOM group=1、pids.max=16。每个场景前后要求只有门禁自己；入口不会自己创建 cgroup、安装限制或提升权限。

启动使用新 session；清理统一执行组信号、有限等待主进程、回收被收养的组内子孙、检查进程组清空。任一步不能确认就 `INCOMPLETE_STOP`，不启动下一个场景。三个场景只测试这种固定、不 daemonize 的 Python 进程组，不声称能处理任意逃逸进程树。

本次不做大内存分配/OOM 压力实验。即使未来通过，也只是读到了所要求的内核限制配置并验证这组微型进程的清理，不是生产 ATPG 内存认证。观察耗时含启动/清理开销，不能塞入 E65 的独占原子 ATPG 费用列；持久 prelaunch/reap 日志接入也仍未完成。

## 独立复核指出的缺陷与修复

第一次独立复核没有直接放行：异常路径的 finally 当时只杀进程组、等待主进程，缺少孙进程回收/组清空确认；另外对 `/proc` 是否属于本 PID namespace 的检查不足，测试偏向成功路径。

已作一次聚焦修复：统一 `cleanup_group` 接管所有启动后路径；补 proc/self/init 身份对照；增加超时孙进程、marker/identity 异常、持续残留进程、清理错误、subreaper 失败等 mock 测试。初始 33 项测试日志和初审发现均保留，不将它们改写成初版无缺陷。

修复后本地新功能 40 项通过（0 跳过/失败/错误，0.015 秒）；独立复核另跑 40 项通过（0.013 秒），结论为 `PASS_LOCAL_IMPLEMENTATION_ONLY`，明确不是 Linux 正向通过。

相关回归最终为 99 个模块、996 项测试，990 项执行通过、6 条件跳过、0 失败/错误，68.913 秒。既有相关套件包含以前的 tiny 本地子进程测试，不是本次 Linux 正向运行或 ATPG。初版/终版 focused 日志、回归日志、Windows 环境与负向回执、独立复核结论已保存为 `data/manifests/ranking_v6_e72_*`，并逐 SHA 封存。

## 下一步为什么需要一个整体执行包

现有 E70 只读文件额度已经耗尽，过去其他一次性 Docker/PyTorch 验证不等于本次新容器的许可；当前机器也没有可用 Linux。因此不通过偷偷扩大读取/启动范围来掩盖环境阻塞。

已准备 [整体范围合同](../../contracts/prospective_linux_lifecycle_scope_e72_v1.json)，将下一次必要授权压缩成一个完整的小阶段，而非逐命令询问：

- 只在既有 B endpoint 的 `/ssd/cjc/gnn_model_linux_lifecycle_e72_20261021_r1` 新目录；不碰受保护目录和 A 端；
- 先有界检查最多 32 条现有镜像元数据，最多 32 KiB；只能用已存在镜像，冻结 image ID/digest，不拉取/构建；
- 固定来源 SHA、容器选项并独立预审，再建最多一个无网络、无 GPU、非 privileged 的隔离容器，128 MiB、swap=0、pids=16，最多 1 MiB scratch；不挂载实验/模型数据；
- 一次运行固定三个场景，最多一个孙进程；总执行 watchdog 30 秒、回传 16 KiB、零自动重试；缺前提或失败就保留回执并停止，不放宽资源重跑；
- 执行前门禁、执行、回执独立审计、总览记录、SHA 与正常版本同步，均包含在同一个范围内，不再逐小步申请。

合同目前仍为 `user_authorization_received=false`。镜像和资源的实际状态未核实，因此还不是可直接启动的实填运行清单。授权该整体范围后，环境核实与精确清单冻结可连续推进；即使门禁通过，也不会自动解封生产 ATPG 或训练。

## 技术依据与证据边界

清理设计依据 Linux [subreaper 说明](https://www.man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)，资源检查依据内核 [cgroup v2 文档](https://www.kernel.org/doc/html/v6.6/admin-guide/cgroup-v2.html)。这些文档支持设计选择，不代替本环境的实机测试。
