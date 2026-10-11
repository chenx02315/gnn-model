# v5：固定动态模板准入与单次合成验证

目标是解除 PyTorch Adam 初始化的环境准入阻塞，不改变模型、目标函数、依赖版本或正式实验设置。旧 optimizer r1 与 TRAIN r1 的失败证据均保留。

本轮用户“授权”只补充一次新 CPU 合成 optimizer 验证。正式 18 TRAIN 仍须真实 smoke 成功及独立原始证据审计通过；本地代码、部署或测试 PASS 都不是 TRAIN 放行。

## 受限实现

只准入 `_remote_module_non_scriptable`，生成源码必须与 2355 字节固定快照逐字一致。两个安装源码固定 SHA、真实 loader/origin、模板函数绑定、TemporaryDirectory 对象、SSD 私有临时目录和缓存身份全部验证。普通依赖仍只搜索原五条路径。保存模型前及 context 正常退出时重复验证，仅清理自身缓存与路径，不开放通用临时目录。

新的 wrapper 使用原数值 kernel 和资源 guard。120 optimizer steps、122 条合成日志，正式 package/held label reads 为 0；单 worker、线程 1、AS 8 GiB、采样 combined RSS 1 GiB、1800 秒、自动重试 0。RSS 是采样监控，不声称硬 cgroup 上限。

## 已验收与证据边界

- AgentFleet 分离 helper 实现、入口实现、设计复核和执行前独立审查，均只负责指定文件。
- 主代理新增 44 定向测试通过，其中 2 个 Linux 专属测试在 Windows 跳过。
- B 端普通 Python 的 19 项 synthetic/helper 文件系统测试全部通过：skip=0、failure=0、error=0、exit=0。包含真实 Linux hardlink/symlink 检查，不执行 Torch，不读取正式包。
- 7 文件共 85427 字节部署到全新 `optimizer_gate_20261010_r2`，逐字节读回通过。旧 core、context、OBS、依赖锁与旧 optimizer 未修改。
- 独立审查发生一次本地 staging 递归文件名枚举误触受保护目录，返回 AccessDenied；未读取内容，随后改为精确文件路径。不声称本轮零访问。

真实 optimizer 与后续 TRAIN 的状态以本轮 manifest 及原始回执为准，不从以上实现/测试结论推断。

## 单次真实运行结果：失败，未重试

全量回归 1146 项，35 项 Windows 平台能力跳过，failure/error=0、exit=0；原始日志 SHA `87f2376f28d34dfff6c02e021e8a7ca4d2ec4ad3a0d320203a76dc458cba81dd`。两项新增 Linux-only 用例已在上述 19 项 B 测试内真实通过。

唯一一次 optimizer 验证返回 exit=1。在 Adam 构造阶段，PyTorch `_dynamo/trace_rules.py` 对第三方模块做 `find_spec` 缺席探测，`fx2trt_oss` 被未知 root 门禁拒绝。日志没有旧的 SEARCH_PATHS 失败，但也没有完整 JIT/optimizer 成功回执，不能把“越过旧拒绝点”升级为成功证明。

采样 9 次，combined RSS 峰值 506441728 字节（约 483 MiB），group 峰值 485167104 字节，清理后活成员 0。未观测内存越界；CUDA warning 保留，不是 traceback 的终止原因。没有 optimizer.step 完成，没有合成模型/拟合日志，正式 TRAIN 矩阵没有启动。新授权已消耗，自动重试为 0。

独立 raw 审计为 `PASS_FAILURE_EVIDENCE_AUDIT_ONLY`。下一步只提出精确可选模块缺席协议修复，不增加依赖、不放开所有未知导入、不重跑旧目录。设计合同 `ranking_v5_optional_probe_repair_proposal_20261011.json` 不构成执行授权；下一次真实 smoke 需要新的单次权限。
