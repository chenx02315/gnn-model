# v5 连续推进：冻结源码导入与真实 Linux 合成资源门禁

用户已经明确授权：全部门禁通过后自动执行固定 18 项 TRAIN，不再逐折/逐 seed 询问。授权记录另见 `ranking_v5_autonomous_execution_authority_20261008.md`；历史合同保留原状，不能依据新增授权跳过实现或安全门禁。

已经完成的本地真实隔离子进程实验不是模型训练：核验 25 项 Python 原始字节 SHA 后先全部编译，再安装专属导入围栏。src/scripts 命名空间路径为空；未知本地模块不回落到磁盘，预加载的 src/scripts 与重型 ML 模块均拒绝。普通 import 协议下，磁盘诱饵不被加载；退出移除围栏和新加载的专属模块，保留无关状态。stdlib 名称白名单不是 stdlib 实际来源证明，也不构成恶意代码或并发导入沙箱。

实际 v5 调用链定义加载了 21 个 Python 模块，worker 来源为封存内存快照。Torch、NumPy、SciPy、sklearn、XGBoost 均被明确拒绝。独立复核发现父验收层缺少 worker 来源必选项，已聚焦修复，同时要求 ML 拒绝确实来自围栏而非任意 ImportError。没有拟合、生产 package 读取或盲测；该围栏目前永远禁止 ML，不能拿它直接跑正式 18-fit。

B 端只读 metadata 核对：Python 3.11.2、31 项分发版本精确匹配 lock；解释器为既有 v3 CPU venv，全部依赖实际来自 runtime-v2 的共享 site-packages。读取 metadata 与 top-level spec 没有导入 Torch/NumPy，也没有访问受保护目录；这不是“全新独立环境已经验证通过”，后续必须绑定共享依赖来源并做新鲜 physical preflight。

当前新增 Linux launcher 只允许一次全新目录中的合成 SOURCE-IMPORT 实验。只读部署输入：26 项 core 文件及 manifest、围栏 helper、verifier；caller 对 launcher 本身另行 SHA 验证。父进程从封存字节加载既有资源 guard，通过固定解释器/环境运行 verifier，所有后代处于同一监控进程组，继承 AS8GiB；RSS 合计采样上限 1GiB、reserve 不变、零重试。结束后独立重读内存及 worker 回执并封存，不能只信子进程自报。

运输包精确 31 个普通文件条目；压缩 <=256KiB、解压 tar <=512KiB。B receiver 在创建新目录之前核对压缩包外部 SHA、完整条目集合、类型、逐文件 SHA 与 core manifest，拒绝目录穿越、链接、重复/额外条目及压缩炸弹。仅使用 /ssd/cjc 下新的 import-gate 目录，不覆盖、不自动换目录重试、不删除失败证据。相同用户竞态和目录项断电持久性仍不是本协议证明的安全保证。

最终结果以 `data/manifests/ranking_v5_import_fence_validation_20261008.json` 为准。Linux 合成资源 PASS 不等于安装 runtime/ML/模型质量 PASS。下一依赖是受控 ML 导入与训练入口，之后在新鲜独立复核放行下自动串行执行已授权矩阵；BLIND/VALIDATION/PILOT/LSF/Tessent 仍封闭。

实际 B 门禁已经完成并独立封存：一次执行、exit0，21 项封存模块，1 次 RSS 采样，合计峰值 38662144 字节（约37MiB），进程组峰值17690624字节。AS8GiB、合计采样RSS1GiB、单worker、零重试保持不变。取回的三项原始回执总计8533字节，SHA与B端一致；最终本地r3为932tests、32能力skip、0failure/error、exit0。r1/r2保留但不是最终版本证据。

独立审计最初在本地staging按文件名枚举遇到无关目录access-denied，未读其内容，随后仅使用明确取回路径。不能宣称所有诊断路径操作为零；实际门禁的生产package读取和MLfit仍为零。上述证据证明源码导入与资源监控，不证明模型已训练或ATPG时间已经改善。
