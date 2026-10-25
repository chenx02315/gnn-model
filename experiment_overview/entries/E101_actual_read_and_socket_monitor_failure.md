# E101：已实际读取 AES，随后被 socket 文件监控误中止

## 目的与结果

用户明确答复“授权修复复核后自动执行固定四项”。本次不使用LSF、不恢复512MiB内核内存门禁，在新E101根实际执行一次。真实Linux三项清理自检通过，首项aes_core/H_TO_M已进入Tessent2021.2，读取库和设计、完成flatten，识别530个scan cells、16条scan chains；最后记录命令为add_processors localhost:1。

**整个接受包没有通过。** 运行目录出现Tessent进程的Unix通信socket，旧scratch监控只接受普通单链接文件，抛出SCRATCH_SINGLE_LINK_FILE_REQUIRED；其余三项没有继续。没有故障状态导入命令，也没有接受PASS标记，不证明fault import完成、D95、正式ATPG或模型收益。

## 实际授权和执行身份

- 原proposal的false历史快照保留；实际授权另存 `contracts/direct_tessent_repair_authorization_e101_20261025.json`，SHA `09da5b310935b975885e08bf35fd555c8453260808e2a739cb9ccbbc9d575f87`，绑定真实用户答复。
- 精确payload137698字节，SHA `e2eb6cbc8ea3a937d97becab809d38b4ea967e93f47738b95bc2786d1c3740d9`，独立可执行预审PASS。39项本地测试通过；原八份代码/E85/E93/失败前件SHA未改变。
- 新鲜只读检查确认旧E100 summary/cleaned匹配、E101根不存在、Tessent可执行，之后仅执行一次。远端根 `/temp/jiangchuanc/multimode_ate_direct_e101_20261025_r1`，旧E100根不动。

## 真实证据与清理边界

- 执行退出1，stdout0，stderr693字节，SHA `79b6c360974ea54e90e40a5cfdf6c2512ad5842abf0a9bca2bfb360c054f4218`。
- 只读回读16235字节，SHA `5ac08f01cc71332f938666e7d574d19ed8c464119ebab803b7a72576539d3f20`。synthetic_gate361字节SHA `f5de66d56d6d6c418fc450c5f2b2001e1a06d92492b2370422a778430cd2d2ae`，三项passed/cleaned均true，包含实际setsid子孙PID/startticks/pgrp/session采样。
- direct_tessent.log8863字节，SHA `2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d`。head4096+tail8192重叠3425字节，已完整重构并核验字节数/SHA，不根据截断输出补造结论。
- 唯一特殊叶为 `scratch/aes_core_M/pvmtmp.1047.63195.bupt-vncs2.0`，S_IFSOCK(49152)、nlink1、size0。后续仅lstat该确切节点，确认uid1047=current_uid、gid1050，未连接、打开或跟随它。
- trace到E100固定源码line316，表示supervise已经返回，并经过其require(cleaned)。这是已核验控制流的清理证据，不是独立OS终止认证；由于最终scratch检查先抛错，没有case receipt，不能补造工具returncode、峰值或完整单项wall time。failure的cases_completed=0不等于零启动：本次只有第一项启动尝试，其他三项未尝试。

## 已看到的告警，不静默放行

五类告警都发生在故障状态导入之前：属性模型未匹配、FN1×6、FN4×637、D7的16个稳定高时钟端口、EDT初始化开销26%。只是分类，不擅自解释为质量无害。旧accepts_log仍会拒绝这些告警；修复socket也不能声称整项能通过。

日志含内部“EDT Pattern Generation Phase”字样，不能概括为没有任何pattern相关计算；本次未提交create_patterns或正式候选ATPG生成命令，也没有证据证明已生成/导出正式测试向量。

## 本地最小兼容修复与下一步

新 `direct_runtime_compatibility_e102.py` 仅提供纯分类：普通单链接文件保持原规则，额外识别已锚定scratch内、当前uid、单链接、size0、精确pvmtmp命名的Unix socket；不打开/连接socket，不跟随链接。其他socket、外部uid、符号链接、FIFO、硬链接或异常size仍拒绝。新 `direct_scratch_monitor_e102.py` 将该分类接入冻结监控器的副本，继续计费并核验前后元数据；未改写旧源码，也未接入远端执行入口。

同一helper对日志做有界告警清单（至多128条、数字解析有界），每条reviewed_for_acceptance=false，warning_acceptance_policy_changed=false。未知告警保留UNKNOWN，不统一忽略。加入新监控器的原有10项回归及2项socket测试后，合计58项本地测试通过；没有新增实际启动。

后续还需在新版本中先持久化已返回的supervise观察/日志SHA，再做最终scratch检查，避免这类失败丢失case观察；逐项审核告警后才能改变接受规则。E100/E101实际现场、源码和失败记录不得改写为PASS。

监控器副本独立只读复核：限定实现PASS，独立运行旧monitor10项、新monitor12项、helper7项共29项PASS，rc0；AST3.6通过。新source SHA `8ef6652bcf18867f3a5db44aad103f3734ff7b886a3d04912274c5ed150b4174`，新test SHA `f6784eaf017c5bfb036fc58692e78272951856be9e3a713b277ea347c561b0f0`。仅本地metadata mocks，不构成远端执行放行。

已一次性询问整体修复包：最多两个新修复版本、合计最多新增8次启动、每版本首失败停止、禁止原样重试，不做正式ATPG/训练/BLIND。提案 `direct_tessent_runtime_repair_e102_proposal_v1.json` 保持user_authorization_received=false。明确答复与代码/精确包复核前不再执行。

原始小回执在本地staging的 `v6_e101_direct_acceptance_20261025_r1`、`v6_e101_result_readback_20261025_r1`、`v6_e101_socket_identity_20261025_r1`。诊断已独立只读复核，PASS只指证据一致和原因定位，不是接受实验PASS。
