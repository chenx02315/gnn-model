# E73：实际确认 B 端可用，修正前一版 Docker 参数假设

日期：2026-10-21。用户批准 E72 整体 Linux 验证包后，已连续完成授权绑定、只读探针实现/测试/独立预审、一次真实 B 连接、回执审计，以及兼容修订的本地实现和独立复核。

## 实际结论：不是 SSH 或用户授权出了问题

B 端身份已核对，SSH 正常，Docker daemon 正常，cgroup v2 正常。**真正阻塞来自前一版方案错误地假设 Docker 提供 `--cgroup-conf` 参数。** 本机 CLI 帮助实测不支持；[Docker 官方 create 选项](https://docs.docker.com/reference/cli/docker/container/create/)也不列出该参数。

没有把错误参数交给创建命令去试错，也没有静默改变用户批准的条件。目前新容器数、实际 Linux 微型场景数、ATPG/LSF/训练次数均为 **0**；本轮未创建远端目标输出目录，不据此断言目标路径全局不存在。

## 本次实际读取了什么

只连接既有 `cjc@gpuserver.buptic.top`，使用原有严格 ED25519 指纹核验，禁止更新 host key。远端主机返回 `bupt-gpus1`，Python 3.11.2。

| 项目 | 实际观察 |
|---|---|
| Docker | `20.10.24+dfsg1`，Linux，cgroup version `2` |
| 只读命令 | 窄字段 `docker info`、有界 `docker image ls`、`docker create --help` |
| 镜像记录 | 32 条，达到上限主动结束 CLI；不读取第 33 条，不声称完整盘点 |
| 参数 | memory/memory-swap/pids/cgroupns/read-only 等存在；`--cgroup-conf=false` |
| SSH | 1 次，退出 0，stderr 空，未超时/越界 |
| 传输 | stdin 7,571 B，返回 4,710 B |
| 元数据读取 | 合计 20,650 B，低于 32 KiB；返回量另受 8 KiB 上限约束 |

镜像名/ID 并不证明其中有可用 Python，也没有通过名字猜测一个可执行镜像。没有读取镜像配置环境变量、运行容器、checkpoint、真实质量/耗时标签、BLIND、A 端或受保护目录。

因到达 32 条上限而主动结束 image CLI 的 `-15` 是预设截断动作，外层探针仍正常完成；不是容器或实验被杀。探针输出 `lifecycle_gate_pass=false`，不能当作 Linux 正向门禁 PASS。

## 探针本地审查与修复

第一次独立审查发现：若前两类元数据成功，但最后的 create-help 读取失败，代码可能保留成功状态。这在真实连接前已修复：异常路径强制 blocked；控制器还独立要求 schema、Linux 身份、无 reason、完整布尔能力表，拒绝残缺结果。失败/超时/字节上限均有 mock 测试。

早期单测还发现中文授权原文不能交给仅接收 ASCII 的旧解析器；改为先核对固定 raw SHA，再按 UTF-8 解析这一份固定本地回执。没有修改旧 E70 读取器或放松其边界。

最终一次实际探针使用已独立预审的 probe SHA `0c578acc...`、controller SHA `52617abd...`。授权、scope、复用 transport、request、START/END 与原始 stdout 的 SHA 均已关联。失败或已消费阶段不能换输出目录重跑；本次没有第二次实际 SSH 或镜像扫描。

## 已完成最小 v2 修订，但未越权执行

本地新版本 `scripts/verify_prospective_linux_lifecycle_v2.py` 保留 v1 所有进程组清理逻辑和资源值，只改一个行为：**记录内核实际 `memory.oom.group=0/1`，不再强制设为 1，也不宣称 OOM 时整组原子退出。**

- 128 MiB 硬内存上限、swap=0、pids=16、单 worker、三个固定微型场景均不变；
- 失败/超时仍须组信号、回收、组清空确认；外部精确容器停止与 30 秒 watchdog 仍是执行包要求；
- 不进行 OOM 大内存压力分配，不将这次门禁冒充生产 ATPG 或完整费用验证；
- 不安装软件、不拉取/构建镜像、不写宿主机 cgroup，不重新扫描镜像表；
- 原 v1、原授权和 scope 全保留，不改旧证据。

新版本及探针/控制器共 41 项 mock 测试通过；独立复核另跑 41 项通过（0.458 秒）。这仍是本地实现通过，**两个版本的 Linux 正向场景都没有实际运行**。

最终相关回归覆盖 102 个模块、1,037 项测试，1,031 项执行通过、6 条件跳过、0 失败/错误，118.660 秒。最终新功能日志为 41 项/0.864 秒；中间版本的 20 项及 1,016 项回归也保留，但不拿它们作为最终版本验收。相关旧套件中的 tiny 本地子进程不计作 Linux 正向门禁或 ATPG 调用。

## 唯一需要的新决定

原批准明确固定了 `OOM group=1`，因此不能偷偷把 v2 放进同一批准。已将唯一语义变更写入 [最小修订合同](../../contracts/prospective_linux_lifecycle_amendment_e73_v2.json)，其余资源、作业数、数据禁区和零重试保持不变，也不重置已消费的 1 次连接/32 条镜像记录。

批准这一个差异后，继续使用本次证据链：在已观察的记录中选一个既有镜像并补齐必要的窄字段身份→冻结精确 image/source/options→独立执行预审→一次容器验证→审计封存同步。不会再逐个文件、测试、命令申请批准；如果环境不满足固定前提，则只报告真实阻塞，不制造一个假的 PASS。
