# E102：有界整体修复包与固定四项接受验证

## 目标与授权

用户真实答复“授权上述有界整体修复包”，question `call_44e08e3076734ef8b533ec5ef5d0a096`。新授权存于 `contracts/direct_tessent_repair_authorization_e102_20261025.json`，SHA `c10785fabdee828c7113d8ed7a90f91dc79deb3e734d7bf66bcfd0f12a271ee9`；原false提案保留为历史。最多两个新修复版本、合计新增8次Tessent启动，每版首失败停止、禁止原样重试；不用LSF、不恢复内核硬内存上限、不做正式ATPG/训练/BLIND。

本版为第1版，最多4次Tessent启动，单worker、采样RSS+swap停止阈值512MiB、600秒/项、2700秒session、16MiB输出、128MiB命名scratch采样阈值。采样不是内核内存保证。固定顺序aes_core H→M、H→F、spi H→M、H→F。第2版若需执行，仍须保留第1版失败、实质修复、独立复核并使用新根；不得原样重启。

## 告警不是全部忽略

只读取得4个既有TRAIN模式日志，未启动Tessent：历史采集响应52753B，SHA `1b37434da83e2330d504e5781867bb18d2c050219cf808752d1c72c0eda7d04d`。四模式分别有5/4/5/4条启动告警，FN1为6/6/7/7，FN4为637/541/336/240，D7为16/4/16/4，M模式EDT开销26%/60%。逐模式记录，不泛化未知电路或模式。

历史库告警中的路径与E101当前库路径不同，因此没有将历史block原样当作新白名单；新registry明确使用E101实际当前路径的完整16行block，保留历史block hash及当前来源log hash。splitlines后以换行连接、不含末尾换行的当前block SHA为 `81fe896fa399f0f8b850a44915325939b1145ac4f55cef6c5ad47f44d93ce645`，不做任意路径归一化。

例外只允许恰好在首条故障导入前出现的该模式精确告警。变体、未知、新增continuation、导入后告警、error/fatal/invalid path均拒绝。库多行完整block也核验。导入两条命令的路径、参数和次序必须与固定Tcl完全一致，库/设计读取命令也须匹配；唯一尾marker必须在导入后。监督器另外要求rc0、failure=None、cleaned=true。

这只能证明“固定导入命令执行到尾标记，未观察到新导入诊断”，不是告警无害结论，不证明完整故障匹配数量、故障状态语义、D95或模型收益。结果字段d95_verified/fault_semantics_verified继续false。

## 本地验证与精确包

93项本地测试通过。独立复核发现的invalid-path变体和单行告警新增continuation拒绝遗漏已聚焦修复并加回归。12份source精确绑定、真实授权SHA、registry SHA、E101失败诊断及E85/E93输入SHA均在联网前核验。控制器固定新phase且不可覆盖，任何未知结果不重传；summary false也明确停止。

最终待审包179014B，SHA `5ec5a80e205435b2bba62f93b2f90dc88040dad3c399cb70f9f09daa903d937d`，旧178570B候选包作废未启动。源码/精确包最终独立复核仍待回执时，不得称实际验证PASS。

只读新鲜检查已确认bupt-vncs2/uid1047、新E102根不存在、旧E101 failure/synthetic_gate SHA匹配、Tessent可执行；原始小回执在本地 `v6_e102_direct_prelaunch_20261025_r1`。这不冒充旧进程的独立OS终止认证，仍需要新版本Linux清理自检及物化时的输入重读。

最终独立复核已返回：限定allowlist实现PASS、当前精确包可执行PASS；独立27项测试退出0，12份源码/授权/前件/输入/registry及AST3.6一致。controller SHA `fa7f919bfafd223dc27cbee3699c059928564a02bb03cd3112406adcd8a13465`。本次仅放行第1版、最多4项、首失败停止，不放大到质量安全结论。

已调用一次固定controller execute，精确payload同上；本地活跃会话54811，结果待观察，不重启/不重传。当前启动调用并不证明四次Tessent均已发生，实际次数待远端回执。

## 实际结果（覆盖上述等待观察状态）

会话54811已终止，controller退出1；远端返回结构化summary，transport远端退出0只代表结果返回，不是整包通过。实际仅1次Tessent启动；首项后停止，其他3项未尝试。

AES H→M日志9623B，SHA `3a3c320b466f84dafd1ea900a5f23d5bfbfda6ad2afb85261ddaef35aca63c07`。两条固定read_faults和唯一尾marker完整，导入后没有新诊断，diagnostic_acceptance.passed=true；但监督器failure=MEMORY_STATUS_LIVE_FIELDS_MISSING、returncode=-9、cleaned=true，故case/summary仍false。采样峰值418713600B（约399.3MiB），不能称超过512MiB或OOM。

观察回执在最终检查前已成功保存，source/runtime观察分离有效。远端summary2758B SHA `c19f095ba00657f408ebf6b1ef322024b2c544413dcd45bcc69faf31645fed0f`，原样另存 `data/manifests/ranking_v6_e102_execution_response_20261025_r1.json`。六文件只读回读27796B SHA `47a040ed6a91aace27efa81bbf1644c28f01f5a1307bf8dc1b682923df5a1743`，在本地 `v6_e102_result_readback_20261025_r1`；独立复核字节数/SHA与结果一致。

A内核3.10.0-1160.119.1.el7，无smaps_rollup。现场未保存触发错误的PID原始status/stat，故不能将具体原因确诊为退出竞态；仅作为后续E103最小修复的候选机制。当前整体授权已用第1版/1次启动；第2版仍须实质修复及独立复核，不原样恢复。
