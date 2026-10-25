# E98：指定主机无可调度槽位的真实诊断

## 结论

此前 Job 394238 的 `bjobs -l` 仅提供集群汇总排队原因，不能确定哪一项对应指定主机。本次经本地测试和独立预审后，仅执行了一次只读 `bhosts -l bupt-vncs2`，获得指定主机的直接状态：

```text
HOST  bupt-vncs2
STATUS       MAX  NJOBS  RUN
closed_Full    0      0    0
slots = 0
```

该次观察中主机没有可调度槽位；不能解释为现有作业占满，也不能把 `closed_Full` 擅自改称“管理员关闭”。本地回执文件落盘时间为 2026-10-24 18:46:09（Asia/Shanghai），不是远端签名时间。这是瞬时调度观察，不是永久配置结论；尚不能说明 MAX 为零的原因。实际作业是否运行/终止仍必须查询 Job 394238，不能用主机状态代替作业状态。23:10 后第 11 次独立作业查询仍为 PEND、五个执行文件均 MISSING，不能把早先主机状态冒充同一时刻的新观察。

## 处置边界与下一步

- 不修改主机、队列、优先级或资源；不再提交、恢复或取消任何作业。
- 保留当前 Job 394238，等待管理员确认 MAX 为零的原因并恢复可用槽位，或其他真实调度状态变化。当前授权仍不包含更换主机后新提交。
- 队列启动许可仍是原 intent 签发起 24 小时，不能重置或续签。即使槽位恢复，实际 worker 仍需验证许可、内核内存、Linux 测试与物理清理，才可进入最多四项无 pattern 接受测试。
- 本观察不涉及 ATPG、训练、BLIND、候选质量或真实标签，不构成任何模型收益结论。

## 执行与验证

诊断 helper 固定配置和 base SHA，验证主机及程序元数据前后一致；程序正文未读取，首次元数据明确标记为首次观察而非历史 pin 认证。客户端输出上限 8 KiB，响应上限 32 KiB；一次调用、零自动重试、零提交/恢复/取消。

独立复核补齐 controller 的客户端成功判定：非零、未知、None 或 bool 返回码都不算诊断完成，取证保留后报失败、不重试。最终 34 项相关接口/诊断测试通过。稳定源码后的全量日志显示 3,391 项、164.143 秒、OK（176 项条件跳过）；这不是实际 Linux 门禁通过。恢复执行时终端 session 83241 已不可用，未收回其进程退出码，故不虚构 exit code=0。更早一次未封存完整输出的全量命令退出 1，不能倒称通过，也不据截断输出猜测失败原因。

实际诊断退出码 0，stderr 0，无 timeout/overflow/write_failed/threads_incomplete。原始 stdout 794 字节，SHA-256 `350ff5fa3c896b1fac62a6ffbd8ff52e22a8ac071ed6ae488af721e778577133`。响应 2,350 字节，SHA-256 `a13e6da8ffd1dd220518b6d3701b2a9d765b2bbe058adce9a13172d637b275c1`。

原始小型回执目录：`C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928/v6_e98_host_queue_observation_20261024_r1`，包含 start、stdout、stderr 和 transport 回执。

全量本地回归日志为同一 staging 下 `v6_e98_host_queue_full_regression_20261024_r1.log`，62,985 字节，SHA-256 `4a0a6972379a635041066ac32b8dc3fed5072ed85e553c4458aecc5a7c07129d`。结果复核曾因独立代理额度限制中断，不能把该次中断计为独立复核 PASS。

额度恢复后的独立结果复核已完成：四份小回执、原始输出、base64、SHA 与日志摘要均匹配，最终总览准确性 PASS；不是实际 Linux 门禁或工具执行 PASS。响应原样副本归档于 `data/manifests/ranking_v6_e98_host_queue_response_20261024_r1.json`，与外部原件同一 SHA。

| 实现身份 | SHA-256 |
|---|---|
| helper | fd0aa4416f1b83d629f228d967e8edde3ef7ca018b24c27ab2a646ad687901f4 |
| controller | 0ea2a0c9393a4beac1cf6a27d0217e060f4757d080e3e6d1b7f2e8b0f3527fce |
| 精确 payload（24,441 字节） | 6c0b4b867992e50fc142060165637e70a90b6af13ffe623fd00065698cc5ad0c |

## 2026-10-25：保留排队后的监控维护

用户要求继续保留原作业排队。最初本地查询器预设的 16 个回执序号已用完；只把本地回执容量扩至 48 个，并让 controller 与 transport 使用同一常量。每个序号仍独占创建，不能覆盖旧回执；不增加作业、恢复次数、自动重试或 24 小时启动许可，也不修改远端部署。

远端 reader 完全未变：source SHA `ece65fa856dd35bea25b6ade86dda74c14862eba60edc76982a0e892113a5353`，精确 payload SHA `151898a7bf34b5cbacf367683e40e64622ea9993bf99ea9e043297f76f7bac64`；仍固定 Job 394238、五个执行文件及每次输出/时间限制。reader 中“1..16”的文档注释描述最初本地范围，不是远端执行门禁；本次不为改注释而改变已审 payload。

20 项相关监控测试通过；prospective 测试组 734 项、6 条件跳过、零失败错误、5.646 秒，进程退出 0。它不是全部 3,391 项历史测试的再次全跑，更不是真实 Linux/内存/Tessent 门禁通过。日志：`C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928/v6_e98_observation_extension_regression_20261025_r1.log`，SHA `2301181378836ad9c3c4659328424fb89b034f04566416683ef7399e0fff7c13`。

这只是保持已授权只读监控可用，不构成完成模型收敛目标或新增采集/训练授权。

限定差量独立复核 PASS：transport SHA `12f5b774837b31d934661a62a352f774cfc8e76714fb4fd3cabea4579e5c9bba`，controller SHA `2e8744ef2f9247024a88663e7628e068547c73df3e9f0ebecee1e721361b426b`。第 17 次实际只读观察仍为 PEND，五个文件 MISSING，无 worker 启动证据；没有重提、重新恢复或新工具调用。
