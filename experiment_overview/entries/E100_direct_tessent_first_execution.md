# E100：撤销内存硬门禁后的首次直接执行

## 结论

这次不再排队，也没有使用LSF。真实Linux的成功、超时、setsid子孙三项清理自检通过；随后首项 `aes_core/H_TO_M` 启动尝试被监督器 `MEMORY_STATUS` 中止，returncode=-9，cleaned=true。其余三项未启动，零自动重跑。

监督器累计采样峰值65,986,560字节（约62.9MiB，含监督器及采样子孙），不构成超过512MiB的证据，也不是真实瞬时峰值保证。捕获输出0字节，未确认Tessent完成电路读取；空日志也不能证明工具绝未执行。-9不能直接归因为OOM。

## 授权、实现和前置验证

用户“撤掉保护吧”承接上一问：撤销512MiB内核RAM+swap门禁，直接运行并保留采样监控/超限停止。授权 `contracts/direct_tessent_authorization_e100_20261025.json` SHA `7ee57c9ec8477768b38bf4f6d746e1f30abb75d5fe33f12b74684a53afdce249`。仍保留单worker、每项600秒含清理、总2700秒、四个固定无pattern接受项、共享16MiB输出和零自动重试；采样不是硬隔离。旧E99未豁免是此前快照，不回填。

新根 `/temp/jiangchuanc/multimode_ate_direct_e100_20261025_r1`，启动前实际确认不存在。旧Job394238已EXIT/TERM_OWNER。复用固定E85/E93输入、隔离TSDB复制、精确翻译和SHA；不改历史输入。DirectMaterializer明确记录kernel_memory_cap_enforced=false，不伪造Job ID或内核预检PASS。

初审发现枚举上限阻断清理、父链归属、输出预算、scratch终检、最后期限和精确标记等问题，集中修复；末尾补齐带前缀诊断拒绝及全部预检后Popen前时钟复核。最终15项本地测试及Python3.6 AST通过；prospective组734项、6条件跳过、退出0。不是全部历史测试重跑，更不替代真实Linux验证。

独立最终可执行预审绑定：source `92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58`；controller `5964f30794b8838a4111946ba78f267338e626f2742603233c778897a462dc0a`；payload128043字节SHA `8bcc02419f9ef384acc04ebba35a6401f0528b1f299a03ac8b4f45d574a8278a`。

## 实际结果和回执

- 三项真实自检均清理通过。setsid场景在超时前由监督器确认own-tree中的PID/startticks/pgrp/session，不只相信READY字符串。gate361字节SHA `73abb6a99d8a3d79e3a67ec66caff540e4a9c353ad1c3715e2f373d0902b032b`。
- 首项直接启动尝试1次；保存receipt前耗时3.6868165秒，failure=MEMORY_STATUS，-9，已清理，输出0字节。
- 总包passed=false。外层进程退出0仅表示返回了结构化失败结果，**不表示接受测试PASS**。其余三项NOT_ATTEMPTED；ATPG生成、训练和BLIND均未进行。
- 执行响应859字节SHA `c76e1db86563019eacb27e0b96f90a9375a252aba187369f5e97e3389f564953`；三文件回读响应2252字节SHA `aa3249d86a54346ef27a118b844af31d4a834dbc22535f23a8ba8fb63af5626c`，逐字段一致。
- 本地回执在staging的 `v6_e100_direct_acceptance_20261025_r1` 和 `v6_e100_result_readback_20261025_r1`。合并日志不冒充独立stderr验证。原始现场保留。

## 聚焦诊断和尚未放行的修复

旧sample只检查读取前stat是否僵尸，读status后仅比较PID/startticks。纯mock可复现“前stat活、后stat已Z、status无Vm字段”被误判MEMORY_STATUS。**这证明机制存在，不证明现场具体PID或唯一根因**，当次没有逐PID诊断，不能补造。

最小修复单独在 `src/data/direct_memory_sample_e101.py`，不改E100已执行源码：绑定expected startticks，结合前/后stat与status识别退出；退出测量为None，不伪造活进程内存0；短暂缺字段仅请求5ms后再读一次，持续live缺失仍拒绝，PID复用拒绝。5ms不是实际墙钟上限。新增8项与原15项合计23项本地测试及AST通过，独立小helper复核PASS；尚未集成、没有物理Linux验证或新Tessent调用。

已一次询问是否授权修复复核后在新目录完整执行固定四项，最多新增四次启动尝试、首失败停止、零自动重试。未答复前不自动重跑。目标未完成，也未证明D95或模型加速。

## 后续本地集成（仍未重跑）

`direct_tessent_acceptance_e101.py` 将已审sampler接入固定新ROOT `/temp/jiangchuanc/multimode_ate_direct_e101_20261025_r1`。复用E100不可变的进程/物化逻辑，只在新隔离进程内临时绑定新ROOT、修复后的Descendants、原生新授权校验器及repair_binding发布；异常后六项globals完整恢复。E100磁盘源码、授权、旧ROOT和失败结果不修改。

E101显式拒绝旧E100授权及 `contracts/direct_tessent_repair_e101_proposal_v1.json`，后者user_authorization_received=false，不是执行放行。真正的新授权必须来自已发问题的明确用户答复；字段形状和source属性本身不认证人类同意，未来控制器仍需绑定实际答复、源码字节和精确payload。summary格式沿用E100格式族，新ROOT和repair_binding区分E101，不重命名旧结果。

30项相关本地测试及Python3.6 AST通过，独立限定复核PASS。E101 source SHA `e01c19f2025df4a962314c0c7a4cca50ee0b108a460e386861d92518535bb72c`；test SHA `61ca044297313bb3dae68ad1a4c0e116ea1a212f01a83ffdaaca2c72438d34fa`。E100仍92f991…、sampler仍8a4e81…；没有新的controller、远端部署、物理Linux验证或启动尝试，不将本地集成PASS称为实验PASS。
