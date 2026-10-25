# 绕过 LSF 的只读可行性核对（2026-10-25）

## 面向实验目标的结论

LSF 不是 Tessent 读取电路的必要条件。此次卡住的是已选择的作业启动方式，不能说服务器或 Tessent 不能用；但换成直接运行，也不能默默撤销现有内存、超时和清理条件。本次没有启动 Tessent、容器或新作业，没有取消、恢复或修改 Job 394238。

## 已找回的旧启动方式

固定本地快照 `../phase4_bootstrap/run_phase4_closure_batch_v2.sh` 通过 `module load mentor/tessent2021` 设置环境，外层以 `bsub -K -q normal ... /bin/bash -lc ...` 调用 driver。driver 的核心调用是 `/usr/bin/time -v tessent -shell -license_wait 5 -log ... -replace -dofile ...`。

这些代码说明内层工具命令可以与调度包装区分，且这份旧闭环批次启动脚本配置为通过 LSF 提交 driver。源码及字节身份不是某次历史批次实际执行的回执；它们不证明所有历史读取操作都走 LSF，更不能证明过去手动启动时已经具有本次批准的资源保护。两个快照字节身份与 E70 已存远端元数据一致：

- wrapper SHA `d1d04f1338af9ec76fffe0224a7b1a1f5ca7ea0bb262e5f2db117a070c5b9f50`。
- driver SHA `4394d366098c7c64614dced1cade709373b315fc3749a8f93404d5c496ecfb94`。

## 新鲜 A 端只读观察

通过已固定 A 主机指纹的 SSH，运行短小只读 Python 检查，helper 地址空间不超过 128MiB、CPU 不超过 5 秒，传输上限 8KiB、45 秒、无自动重试。仅读取有界 `/proc/self/cgroup`，并检查五个固定位置的元数据/访问 hint；没有目录扫描、写入或程序体读取。

- 主机 `bupt-vncs2`，账号 uid 1047；当前 SSH 会话 memory-v1 membership 在根组，没有 unified membership。
- `/sys/fs/cgroup/memory` 存在，但当前账号的 write-access hint 为 false。
- 固定位置 `/usr/bin/docker`、`/usr/local/bin/docker`、`/var/run/docker.sock`、`/run/podman/podman.sock` 均不存在。
- 检查退出 0，stderr 为空，无 timeout/overflow/write_failed/threads_incomplete；新增 Tessent、容器、调度作业和远端写入均为 0。

这是有限路径检查，**不是全机不存在 Docker、Podman、委派组或其他隔离入口的证明**。write-access hint 不是成功创建或资源生效证明。本次没有连接任何容器服务、安装软件、获取 sudo 或尝试写 cgroup。

E94 的旧能力回执已显示常规 cgroup 根不可写；新观察与该有限结论一致。此前仅以“尚未检查 A 端”概括不准确：已有部分检查，缺的是可实际采用的等效保护入口和生效证明。LSF 队列名额恢复本身同样不保证内存硬限制有效。

## 下一步收敛

1. 保留现有排队作业和旧证据；新的直接运行入口不能与它并发执行。
2. 优先获得管理员提供的**实验专属、可用的资源限制入口**：例如可委派的 memory 控制组，或明确可访问的受限容器入口。无需增加 512MiB 上限。
3. 确认入口后，先以无 Tessent 的小型合成进程验证内存、超时、清理，再独立复核新的直接启动方案；原来仅授权一个 LSF Job 的执行许可不自动变成另一条真实运行许可。
4. 只有启动方式、资源和去重条件均满足后，才讨论四项接受测试；不能把“找到 tessent 命令”升级为可直接执行正式采集或训练。

不把地址空间限额或采样 RSS 默认为整棵 Tessent 进程树的 RAM+swap 硬限制，不借绕过 LSF 降低现有约束。本次推进的是启动路径诊断，不是新 D95、ATPG、训练或模型收益结果。
