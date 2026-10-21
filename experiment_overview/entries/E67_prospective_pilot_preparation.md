# E67：补齐试点执行包，本地能确认的先落实

日期：2026-10-21。状态：部分补齐，不能运行。没有访问 A/B、没有新 ATPG 数据、没有启动训练。

## 已经补了什么

以 E65 的 21 个未决字段为起点，本轮实际核实并填入两个 SHA：现有 E65 账本源码，以及现有家族切分合同。核对 aes_core / spi 分别仍属于 TRAIN 的 iwls_aes_core / iwls_spi。这里的“切分合同 SHA”仅固定当前文件和成员关系，不推断旧审计状态已经解除。

生成了一个新的准备包，原模板、历史合同和 E65/E66 文件均不改。另按旧研究合同把 ε=1% 写入新草案，合计补上两项哈希和一项草案实参，仍有 **18 个未决字段**，始终 `execution_ready=false`、`training_release=false`。账本库不是实际 ATPG 适配器，因此没有把 E66 dummy 的 SHA 填进真实 runner 字段。

增加可重复运行的本地准备脚本，只读取固定十个仓库源码/合同文件，每份最大 64 KiB；不扫描数据目录，不打开候选表、checkpoint 或结果标签。输出包含本轮真实读取的字节数和 SHA，以及填了什么、没填什么。

## 新试点规则已单独写清

- TRAIN 范围固定 aes_core/spi，H64/M16/F4、D95 不变。
- 同一候选清单比较固定规则、冻结模型、随机顺序；顺序必须在未来测量前固定，不能按本批结果选择。
- ε 保持既有 `runtime_training_v2` 的 1% 研究目标，不放宽到 5%。三个 seed 暂列 20260824/25/26 为设计常量，不认证旧训练的种子来源。这些参数尚未预注册或应用到真实执行。ε 命中指 D95 满足且 cycles 不超过本试点候选集最小值的 1.01 倍，不能称全空间最优。
- 单 worker、零自动重试；失败也收费，未知耗时保持不完整，绝不插补。
- 第一版统一关闭前缀复用、跨方法/跨会话 artifact 复用；新会话冷 artifact cache。OS page cache 并未受控，需记录环境和顺序，不能冒称“完全冷缓存”。
- F 搜索中的每一次探测都是物理 attempt，不能只给最终 F 结果计费。

## 为什么不能照抄旧参数

核实了 `runtime_policy_v1/v2`：v2 只修正历史证据，其余规则沿用 v1。v1 允许一次瞬态重试、耗时缺失时以 timeout 代填，并开启前缀复用。这三点与新的前瞻采集目标冲突，故保留历史合同不动，另立新试点规则，不做静默合并。

历史 `formal_candidate_space_v2` 明确按历史 PASS 测量筛选。它可用于理解字段，不能证明一个不依赖结果的前瞻候选集合。新清单需要从合法 H/M 结构坐标或运行前固定的生成规则形成，而不是从“已经成功的行”倒推。H64/M16/F4 是固定模式参数，不表示已经知道候选数或实际 pattern 上限。

旧训练包的 8 GiB 地址空间/1 GiB 采样 RSS 和 1800 秒 fit timeout 也不是 Tessent 的资源配置，本轮没有挪用。

## 剩余 18 项如何补

以下不是泛泛待办，每项有明确可接受产物。没有证据的字段继续为空。

| 字段 | 所需产物及验收 |
|---|---|
| candidate_domain_policy | 合法 H/M 坐标、HF/HMF 模式和 F 搜索/停止规则；不得引用未来质量选择域 |
| candidate_roster | 从上述规则生成的 aes_core/spi 固定清单；唯一 action ID、无结果列、SHA、条目数 |
| policy_orders | 三类方法对同一清单的排列；无缺失重复；模型输入/检查点先冻结 |
| seed_manifest | 区分候选随机顺序 seed、模型 seed、ATPG seed；提案不等于全部已固定 |
| shared_prefix_policy | 明确首试点统一禁用，真实 driver 确实不暗中复用；不能只填文字 |
| cache_policy | 新工作目录、无跨方法/会话 artifact 共享；复用查找与状态可核查 |
| driver | 选定即将执行的实际 driver/config 与部署字节，不拿当前 SHA 冒称历史执行 |
| runner_adapter | 真实原子 ATPG 进程的起止、身份、退出/超时/中断对账；不能用 dummy 替代 |
| environment_manifest | Tessent/系统/依赖、license/线程、实际内存守卫及新鲜观测 |
| storage_manifest | 新隔离目录、容量/inode、输出限制、停止后证据保留方案 |
| d95_fault_universe | 两电路的共同故障集合与映射 SHA；D95 的分母及验证规则可追溯 |
| frozen_model | 选定真实 checkpoint 与特征/模型版本、SHA；不按试点结果重新选模型 |
| external_preregistration | 对最终完整包的外部冻结回执，不是本地填一个 SHA 字符串 |
| execution_authorization | 对完整新目录、有限作业/attempt、资源和停止条件的一次整体授权 |
| memory_limit_bytes | 核实真实 ATPG 限额及守卫，不能借用读取器或训练进程的限额 |
| attempt_wall_timeout_s | 真实 stage 计时/清理边界；旧 60/30/30 秒只能作旧提案，不视为新校准 |
| max_physical_attempts | 连同 F 多次探测、确认成本与所有失败在内的硬上界 |
| candidate_count | 由运行前 roster 计算，不能由历史 PASS 数或猜测填入 |

依赖顺序：先候选合法域/清单，再策略排列及有限 attempt 预算；并行准备真实 runner 与环境资源；全部核实后才封存预注册和整体执行包。没有 runner 和清单时，不先设置一个看似完整的有限预算来掩盖缺项。

## 文件

最终版本针对性测试 10 项全部通过（0.031 秒、零跳过），相关回归 905 项：899 项执行通过、6 条件跳过、零失败/错误（38.169 秒）。较早一次回归期间版本还在修订，因此不把那份日志当最终冻结证据；原日志留在本地。最终准备包确定性由固定输入决定，不产生新 runtime 标签。完整相关套件包含 E66 原有三个 tiny 本地子进程测试，不是 Tessent。

- 新规则：`contracts/prospective_pilot_policy_v1.json`。
- 准备脚本：`scripts/prepare_prospective_pilot_v1.py`。
- 小结果：`data/manifests/ranking_v6_e67_preparation_20261021_r1.json`。
- 全量准备包留在本地 staging 的同名 E67 新目录，不覆盖旧实验。

本轮完成的是“两项本地证据哈希 + 1% 草案实参 + 新规则与冲突清理 + 剩余项逐项落实路径”，不是“所有真实配置已经齐全”。第一份 r1 准备包保留当时 5% 草案和 19 缺项状态；核对旧合同后更正为 r2，不覆盖原始准备过程，也没有据此运行真实实验。Git 收最终 r2 小结果。下一步优先核实候选生成规则与真实进程适配边界，不重跑训练，也不继续无目标历史日志追查。
