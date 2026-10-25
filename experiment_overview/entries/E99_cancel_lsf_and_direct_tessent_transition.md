# E99：取消排队，切换为直接 Tessent 方向

用户明确要求“关闭排队，直接使用tessent，继续往下做实验内容，别搞lsf”。自此不再提交或恢复 LSF 作业；E98 旧合同和证据不改写，新方向单独记录。

## 实际完成

1. 先实际查询并严格匹配 Job 394238、名称、新入口及工作目录。初态 PEND；只执行一次该 ID 的 bkill，返回 being terminated；即时查询仍 PEND，未据 ACK 宣称终止。
2. 随后独立只读查询同一 ID，确认 EXIT，原文明确 TERM_OWNER。五个执行文件均 MISSING，未观察到 worker 启动；这不是 Tessent 自身失败，也没有新增实验结果。
3. 直接环境检查成功：原 `module load mentor/tessent2021` 后 `command -v tessent` 返回 `/cad/mentor/tessent2021_2/bin/tessent`。只解析工具位置，没有调用 Tessent。
4. 用户级 `systemctl --user show` 无法连接 D-Bus；`/run/user/1047/bus` 不存在。三个固定用户 memory 路径不存在。cgexec 确实存在，但存在一个工具不证明已有可用、受限且已委派的控制组。
5. 为避免把固定路径缺失推广为全机不存在入口，另作最多 64 项、单层 memory 根目录的只读元数据检查。此次传输退出码为 4294967295，stdout/stderr 均空，无有效报告；不推断命令未执行、不推断服务器不可登录、不推断不存在委派组，也未自动重试。

## 尚未解决的精确问题

LSF 排队已经关闭，不再是当前启动前置条件。缺的是**不依赖 LSF、且符合原 512MiB RAM 与 RAM+swap 总量要求的资源限制入口**。本次用户指令授权切换启动方式，没有明确撤销该资源要求，因此不能悄悄改成只轮询 RSS 或每进程地址空间限制。

原超时、单 worker、四项无 pattern 接受范围和零自动重试也未扩大。这里的“单 worker”不是禁止 Tessent 合理使用内部线程；不能为了通过资源证明，静默将软件改成不可用的执行方式。

若已有管理员提供的受限入口，可针对该确切入口验证；否则需要明确决定是否修改原内存硬限制。两种情形都先确认旧 Job 终态，避免并发重复执行。未进行新的 Tessent、ATPG、训练或 BLIND 访问。

## 回执与复盘位置

全部位于 `C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928/`，历史目录不变：

| 阶段/文件 | 大小 | SHA-256 |
|---|---:|---|
| v6_e98_user_cancel_20261025_r1/stdout.json | 4988 | a64c13d2d447157a886e11dbfe76fbcada4b1a1d5fc37e2f1dd4cb93c399c1dc |
| v6_e98_job_observation_22_20261024_r1/stdout.json | 3242 | e467bc8ad984214be4ba8429adea7e9bf4d7af76b349be4f962a7cf951737907 |
| v6_e99_direct_launch_capability_20261025_r1/stdout.json | 813 | d5ab5e8a8dae5051c8ff63b1961c54c40e279b4b92d7ade5b96cc14234892545 |
| v6_e99_direct_memory_inventory_20261025_r1/stdout.json | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |

每次操作另有 start、stderr、transport 小回执。取消证明只支持“该作业已结束”；环境检查只支持“能找到 Tessent 命令”；均不能升级为新电路读取成功、D95 或模型效果证据。

独立限定复核已核对四阶段回执、大小/SHA、取消终态及两份新记录，结论 PASS。复核未重做远端操作，不是直接执行或资源门禁 PASS。本地 UTF-8 JSON 与精确终态摘要绑定检查通过；检查命令的默认编码和相对路径问题仅在本地纠正，未重做远端取消或能力探测。
