# 当前实验状态

更新：2026-10-20（E64 后）。此文件是可更新的当前入口；之前的 E57/E58 入口快照及其 seal 对应提交 `3f53814`，E60/E61 入口快照对应 `4bda05c`，E62/E63 入口快照对应 `4039011` 的原始 blob，而不是本次更新后的入口字节。实验原始小结果、代码和回执不重写；旧待办措辞保留当时状态，不改原 seal。

- E54–E56：来源链和 1780 配置映射通过，独立复核恢复并完成；已正常推送 `132291b`，不是仍在等待额度。
- E57：实际一次两摘要连接通过，16 条声明完整保留，8 正式范围 + 8 其他版本，独立小结果复核通过。773 项回归中 767 执行通过、6 条件跳过、零失败/错误。
- 仍未认证：实际调用谱系、完整累计 ATPG 计费、运行前候选/自适应生成策略冻结。未产生新训练目标或启动训练。
- E58：已找到并静态检查本地 Phase4 closure reference 源码。参考代码的细化会使用过去结果，F 搜索路径可触发多次探测，缓存也会影响本次费用；尚未证实历史实际执行情况。不能把固定候选全集、最终 F 耗时和完整在线搜索费用混为一谈。尚未认证历史部署身份。
- E59：独立固定门禁后，已实际一次只读核验 A 端该 driver 的当前字节身份：52,317 B，SHA 与 E58 reference 完全一致。不解码/执行源码，不打开其引用数据，不修改远端。786 项相关回归中 780 执行通过、6 条件跳过、零失败/错误。
- E60：第一次固定启动元数据读取实际返回 FAIL_CLOSED，无成功清单；实际触发点和读取进度 UNKNOWN，原失败完整保存，不原样重试。
- E61：独立一次解释器观测通过，A 端为 Python 3.6.8，缺少原读取器使用的两个新接口。这是当前兼容性缺口证据，不倒填 E60 的唯一原因，也不是目录审计通过。808 项相关回归中 802 执行通过、6 条件跳过。
- E60-r2：兼容修复后实际一次读取与独立结果复核通过；两个目录 74/41 个条目，仅选中 2 字节状态文件的元数据，正文读取为零，没有取得启动代码/job/SHA 锚点。829 项回归中 823 执行通过、6 条件跳过。保持内存 512 MiB、单 worker、零自动重试，日志/submit/status 正文仍不打开。下一步查本地启动代码配方，不扩大到结果日志。详见 [E60-r2 实际观测](entries/E60_r2_launch_metadata_observation.md)。
- 继续方向：定位 Phase4 aes_core/spi 同时期部署/启动记录，将历史实际 driver SHA、命令/job 与输出根绑定。当前文件相同仍不是历史执行或策略冻结的证明；完整计费与训练均未放行。
- E62：本地 `phase4_bootstrap` 找到真正的 `start_`/`run_` 启动脚本，原精确前缀可能漏匹配；两份源码小快照与独立静态复核已保存。取消不再必要的宽目录查找，未执行远端；三个草稿完整隔离保留。launcher log 混有七电路状态，不能按纯提交日志读取。详见 [E62 启动配方](entries/E62_local_launch_recipe.md)。
- E63：实际一次固定 wrapper SHA 核验及独立结果复核通过，A 端当前 2,323 B 与本地 SHA 完全一致。843 项回归中 837 执行通过、6 条件跳过。未认证历史部署/执行/冻结/费用。详见 [E63 当前 wrapper 身份](entries/E63_current_wrapper_identity.md)。
- E64：用户明确授权后，实现与独立门禁通过，实际只读一次确切混合 launcher log（1,511 B）。响应 NO_MATCH、目标行为空，未恢复 aes_core/spi Job ID；不据此判断历史运行不存在或猜测原因。855 项回归中 849 执行通过、6 条件跳过。原始日志未传回、没有其他电路状态/质量/耗时输出；不自动重读或扩展。详见 [E64 有限提取结果](entries/E64_submission_metadata_no_match.md)。
- 已继续完成静态补查：既有本地 SPI v3 repeat 修复 helper 不含 bsub，provenance 也不保存外层 Job ID/启动命令或 helper/driver SHA；已列最小所需的当时启动回执字段，不用它解释 E64 的 NO_MATCH。没有执行代码或打开引用文件。
- 当前下一步：本次一次读取授权已使用。其他来源需要能绑定当时 helper/driver、命令、job/PID、输入哈希及输出根的回执；不得无目标地重读混合日志。缺口仍未解除，训练、LSF/Tessent 仍不启动。

记录入口：[E56 复核闭环](entries/E56_r2_publication_review.md)、[E57 实际结果](entries/E57_formal_declaration_bridge.md)、[E58 源码线索](entries/E58_reference_driver_semantics.md)、[E59 当前源码身份](entries/E59_current_driver_identity.md)、[E60 失败保留](entries/E60_launch_metadata_failed.md)、[E61 解释器观测](entries/E61_python_api_observation.md)、[剩余证据与清单](SOURCE_EVIDENCE_GAPS.md)。
