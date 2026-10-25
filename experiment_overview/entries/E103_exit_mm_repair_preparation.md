# E103：第二个、也是本整体授权最后一个修复版本

## 前件与边界

E102真实失败保留：只用了1次启动，AES导入执行诊断通过但内存采样失败，整包不通过。E103沿用用户同一次整体包答复，在新根 `/temp/jiangchuanc/multimode_ate_direct_e103_20261025_r1` 运行最多固定4项；包累计最多5次实际启动（低于授权8次上限），即使第2版失败也不再自动新增第3版或重用剩余启动额度。

派生授权 `direct_tessent_repair_authorization_e103_20261025.json` 明确version_index=2、prior_attempts=1，并绑定E102 log与summary SHA。不是伪造新授权，也没有再次询问用户。

## 修复依据与不确定性

上游Linux v3.10 [proc实现](https://github.com/torvalds/linux/blob/v3.10/fs/proc/array.c)在task有mm时才输出status内存字段，无mm时statm输出全零；[退出路径](https://github.com/torvalds/linux/blob/v3.10/kernel/exit.c)先exit_mm，后exit_notify；[任务标志](https://github.com/torvalds/linux/blob/v3.10/include/linux/sched.h)定义PF_EXITING=4。因此存在“仍不是Z、但地址空间已释放”的窗口。此为上游源码依据，不是现场EL7构建源码的完整认证，也不证明E102具体失败PID属于此状态。

独立复核指出线程组风险：组长退出不代表其他TID无内存。修复只在以下全部成立时新增EXITING_MM_RELEASED分类：原两次Vm字段读取仍失败；PID/start/UID前后相同；四个状态值合法；VmRSS/VmSwap字段名确实都不出现（畸形字段也不能冒充缺失）；PF_EXITING置位、stat vsize/rss为0、statm严格七个0；status Threads=1，且前后有界task目录都只含该PID。

该分类的rss_swap_bytes仍为None，不伪造成实测0，也不宣称进程已终止；既有owned-descendant cleanup仍必须成功。其他TID存在、身份变化、畸形字段、权限错误、没有完整证明均继续停止。原快速Z/X分支和aux读取FNF分支也增加线程组核查，避免从旁路跳过仍有内存的线程组。真正PID消失才可按消失分类。

正常live VmRSS+VmSwap读取和512MiB采样停止阈值不变，不用LSF、不恢复内核硬cap。每case重置peak/proofs/last_sample，避免写入前一阶段的过期样本。observation保存完整有界proof，case receipt最多8条示例并列出总数。既有告警精确例外和故障导入范围不变。

## 当前验证

125项本地测试通过，包括13项新sampler、9项新组合、10项新controller测试。真实bootstrap前缀只加载13个冻结模块而不执行工具，已检查模块选择、所有source属性和授权形状。起始本地候选错误选择旧模块已被测试发现并修正，旧候选包未发往A。

最终待审候选188989B，SHA `a13da5102a0a89a2bd8f21daf0acf04bf84f6f1e0761526fff5895eeb0da487b`。sampler SHA `17e4522849a386a268f7135f870e8d49bb190c032b819cf69f037fd27ee13cbb`；executor SHA `cdb3080f571bd706c24a6414cac4a2b67027ee888169aef879b3312235bcf097`。待最终独立复核及新根前件检查后自动启动，不把本地测试视为真实运行通过。

最终独立复核已通过：可执行限定PASS，独立125项相关测试退出0、AST3.6通过，13source/派生授权/冻结输入及E102失败前件一致。controller SHA `b2894d6fafb1d7921a2c8af6e51ded86272bc0b1cc3dda479903ceea1c753b78`。新鲜A只读检查确认root不存在、E102 summary SHA匹配/1次已清理、工具可执行，回执在 `v6_e103_direct_prelaunch_20261025_r1`。

精确包已调用一次，当前本地会话77347待观察。此时仅确认执行调用已发生，不预填实际Tessent启动次数或通过结果；不重传、不原样重试。

## 实际结果（覆盖上述等待观察状态）

会话77347已终止；远端结构化summary返回0、controller因passed=false退出1。实际启动2次。结果如下：

| 固定项 | 结果 | 真实证据 |
|---|---|---|
| AES H→M | 窄范围导入运行接受通过 | rc0、failure=None、cleaned=true，两条导入与尾marker完整，峰值采样420220928B（约400.8MiB） |
| AES H→F | 内存采样阈值停止 | rc-9、failure=SAMPLED_MEMORY_STOP、cleaned=true，5个活跃进程RSS+swap聚合694099968B（约661.9MiB），高于512MiB |
| SPI H→M | 未尝试 | 首失败停止 |
| SPI H→F | 未尝试 | 首失败停止 |

AES M保存到实际EXITING_MM_RELEASED证明：PID97013/start226101406，状态D，flags4202500含PF_EXITING，stat地址空间及RSS为0、statm七个0、前后task列表均只有该PID，测量值None。它证明E103这次观察到这种退出条件，不倒证E102具体失败原因。清理仍独立走原owned-tree流程。

AES F日志已完成设计读取及530个scan cells/4条chain识别，最后命令为add_processors localhost:1；没有两条read_faults或接受尾标记。不能把这项记为导入通过。694099968B是多个进程的RSS+swap采样和，不是独占物理内存，也不是内核OOM证明；共享页可能被重复计数。采样会超调，不是硬cap。

E103 summary4298B SHA `686edd06fc8d9c11e8563986b0d13a24a69a9ba1bcb37be50d2d52a30b8960e4`，原样保存为 `data/manifests/ranking_v6_e103_execution_response_20261025_r1.json`。9文件只读回读43123B，SHA `a451a0409aee9e470a65ebd2ce15313ef8b5c06976a0f45451d62850e01bf513`；两份工具log分别9623B/SHA `5fe275ab8cf80f3001f42b9b0a4154e8310030b8e2072de9d22a7c0e70aff7c0` 和5499B/SHA `06903ffe908c3320f0941833b36fe39a547c951dfc0f44ad9122b44ec2d34fe1`。原始小回执在本地 `v6_e103_direct_acceptance_20261025_r1`、`v6_e103_result_readback_20261025_r1`。

整个四项包仍失败，D95/fault_semantics_verified仍false。无LSF、无正式ATPG/训练/BLIND。两版本合计3次实际启动；版本数量上限已耗尽，不能拿剩余5次数字额度创建第3版本。

## 下一步候选（未获新授权，不执行）

四份已取得的历史common_readback日志均没有add_processors命令，却都有read_faults、report_statistics和exit；这支持下一版尝试移除不必要的额外worker命令，而不是先抬内存阈值。当前失败也恰好停在该命令，但不能据此宣称已证明峰值根因或删除后必然通过。

建议另一个有界低内存包：只验证剩余AES H→F、SPI H→M/H→F，不重跑已通过AES M；最多1新版本/3启动，保持512MiB采样阈值、单worker、原诊断规则、首失败停止、零重试；先实现、独立复核、新鲜检查后才实跑。不LSF、不恢复硬cap、不做正式ATPG/训练。此包不属于已用完的当前两版本授权。

最终9文件回读已获独立限定PASS：完整大小/SHA、summary逐字段、M导入尾标记与exit、F停止位置、清理及proof均一致。下一低内存方案也仅获“有证据的待验证候选”评价：历史common-readback不是本次translated merge，移除add_processors只是不再显式请求额外处理能力，不保证少一个OS进程或必然降低峰值。累计结果将保留新旧配置差异，不把跨配置结果冒充同一整包通过。

已一次性请求该新低内存整体包授权；答复前不实现为可部署包、不新增启动。本轮没有第三个修复版本实跑。
