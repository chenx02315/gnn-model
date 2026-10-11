# v5 TRAIN v2 接入与验证（2026-10-11）

当前结论仅是实现、Linux 单元门禁与最终回归通过；不是正式 TRAIN 完成或模型排序效果改善。

固定 15 名称的缺席探测修复已在新目录完成唯一一次真实合成验证：120 optimizer steps、122 条记录、15 个探测各一次，独立实际证据审计通过。不得再次使用该额度。TRAIN 授权与合成验证授权是两个不同的 SHA 绑定。

## 本版接入

- 新入口、父控制器、打包器与 TRAIN JIT helper 使用全新版本；旧 core26、数值 kernel、依赖锁和历史运行不改。
- 固定六个 TRAIN 家族、三个 seed，共 18 项；每项使用独立私有 JIT 临时目录。单 worker、单线程、AS 8 GiB、采样合计 RSS 1 GiB、零自动重试，首次失败停止剩余任务。
- 产物验收前要求独立 admission sidecar。证明覆盖 fit 边界与上下文退出，不宣称在不可变核心的内部 save hook 取证；失败后即使留有模型文件，也不自动接受。
- exact source/evidence/envelope/archive 数量为 41/13/18/74。源和证据 trust map 必须由外部审核封存，不允许生成器自签放行。
- 独立复核发现路径保护允许非规范路径到达文件检查；一次聚焦修复后，点段、重复斜杠与受保护路径变体均在 I/O 前拒绝。旧失败和修复前回归日志保留。

## 验证证据

最终 r2 完整回归：1223 tests、39 平台能力跳过、零 failures/errors、exit 0；unittest 226.500 秒，外层 227.8009897 秒。原始日志 SHA-256：`9dd190a6e5a6e30deb9e22de477c029946b990520cbf70833a615d9e07edc673`。

新增四组 focused tests 合计 53 项、3 个 Windows 平台跳过。对应实际 Linux 门禁分别通过 26 项 TRAIN JIT helper 测试与 1 个原始 POSIX 父控制器方法，均零跳过、零失败错误、exit 0。后者仅证明该方法的私有临时目录行为，不是整个 TRAIN 集成测试。两种 Linux 门禁均不导入 ML、不读正式 package、不运行 optimizer 或训练。

由于额外 reviewer 槽位不可用，采用已有两个不同文件所有者交叉只读复核；helper/entry 由 parent builder 复核，parent/packet 由 entry builder 复核，不是作者自审。

详细 raw SHA、授权、固定矩阵、资源限制和待执行节点见同名 integration 合同。修复前 r1 full 不能代替最终 r2。

## 尚未完成

尚未生成正式放行的训练包、部署新 TRAIN 目录或启动本版正式训练。仍需 prospective release 的独立审核、exact packet 审核、运输脚本审核，以及启动前新鲜 once/环境/内存检查。旧 once 的缺席快照不是放行证据。BLIND、VALIDATION、PILOT、LSF 与 Tessent 不因本门禁通过而开放。
