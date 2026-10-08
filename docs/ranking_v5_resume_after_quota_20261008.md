# 额度恢复后的准确续接点

2026-10-08本轮连续执行遇到工具侧明确usage limit：`/root/train_artifact_readback`、`/root/frozen_import_fence`均返回额度耗尽，工具提示当地16:55后可重试。不是等待用户逐项授权；用户固定18项TRAIN条件授权已存在。恢复时间是工具提示，不是已经创建的定时唤醒，也不保证届时额度可用。

## 已封存，禁止重复运行

- 本地HEAD `bef70ee`：实际Linux源码导入门禁、原core26、31条目有界运输与条件授权。r3=932tests/32skip/0failure/error/exit0。
- B目录 `/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1` 已完成一次成功门禁，不能覆盖或换目录自动重试；合计RSS38662144字节。
- 新鲜metadata实际只读调用一次，raw日志SHA `9aa1d1daf394eb1cb9f2a4cc291e74a4a003badfc04fcb19f599041244bc0db4`；独立审计通过metadata-only，不是ML/训练PASS。
- runtime observations保护缺口已聚焦修复，10项测试通过、独立PASS。源码SHA `0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8`。
- artifact readback不合理计数/负cost/regret缺口已修复，15项测试通过（1Windows真实symlink能力skip）、独立PASS_IMPLEMENTATION_ONLY。源码SHA `3f38c50afc13db7a0edc3258aa9074a34d54dd5938034c73d89bdb1cc379d920`。允许replay=false的完整性回执不代表完整正式fit；matrix验收须另要求replay=true。

## 未完成且未部署

1. `ranking_v5_locked_runtime_imports.py`由实现代理写入，额度结束时未交付最终复核结果；按未封存代码处理，不封存为PASS、不远端执行。当前source SHA `74ce161ebc72ab3e7ce0cacfbee9cdf6f582a3a1679abef0b525ed4240a63e02`。
2. `scripts/run_v5_train_single_fit.py`实现代理报告18项定向测试通过，改为固定 `prelaunch_{family}_{seed}.json`，但独立复核尚未完成。CLI/source SHA以当前worktree复核为准，不能依据代理自报就部署。
3. 未实现serial18物理matrix launcher；没有生成真实正式release、独立review、完整supplement seal和fresh physical prelaunch信封。
4. 正式18项训练次数仍为0。没有BLIND/VALIDATION/PILOT、LSF或Tessent执行。

主代理在额度报错后对当前四模块做一次本地有界验证：54tests、1Windows真实symlink能力skip、0failure/error、exit0，7.013s；`v5_runtime_entry_partial_20261008_r1.log` SHA `f2e6d308ee44e528a53dfa77e0d5b44ad3aec49f5fc5254631207c924cbb0076`。不作为完整回归、独立复核或实际Linux/ML正向证明；向独立reviewer发起只读复核请求，若额度拒绝则保留待复核状态。

随后reviewer仍可运行，发现controlled imports两项缺口：subpackage输入路径验证迟于PathFinder，以及缓存module的file/loader未与spec一致。主代理继续做一次聚焦修复：finder查询前精确parent路径准入，cached file/loader/frozen bootstrap alias一致性拒绝；新增2个隔离子进程测试。context+CLI当前31tests通过（6.098s），新版SHA和完整回归/独立复核以最后回执为准，旧54项日志不能封存修复后版本。两名实现代理额度错误不意味着所有主代理/复核工具均不可用；保留真实能力区别，不宣称已自动停止全部工作。

## 恢复后的执行顺序

最新补充：主代理与reviewer仍可用，已继续完成context聚焦修复及独立31项PASS；CLI独立IMPLEMENTATION_ONLY通过。修复后完整r1=988tests/33skip/0failure/error/exit0（164.851s），raw SHA `64d667972255fac66ebac8e5294e45aaf1afc9ef81a213ecce69189f3d33f7df`。上方74ce旧context SHA、未复核状态及54项临时日志均为历史阶段记录，不是当前封存依据。当前新增CPU runtime gate/4项packet的12项本地测试通过、待独立review；未远端部署或训练。不得因为两名builder额度结束就宣称主工具全部不可用。

最终续接点已改变：runtime gate r1一次实际失败（sitecustomize），一次-I -S聚焦修复经18focused及1006full tests/独立代码和精确包PASS后，r2实际再失败（typing.io缺ModuleSpec）。两次raw负证据独立审核PASS，远端STOP_AFTER_INITIAL_AND_ONE_FOCUSED_REPAIR，禁止第三自动尝试或TRAIN。current详细状态见ranking_v5_runtime_entry_validation_20261008.json。不是额度阻塞，也不是等待原18项授权；是Python3.11伪命名空间兼容性未解决且已达到门禁重试边界。没有正式fit，模型仍未生成；不得用旧resume顺序直接跳过真实失败。

先git status/HEAD及明确文件SHA恢复状态，保留用户无关untracked内容；完成controlled imports并测试，独立复核imports与单次CLI；接通serial18父guard和产物/内存独立读回，首失败停止、零重试；完整回归及新鲜受限ML/环境门禁；绑定真实条件授权与独立release-review/source/环境证据；全部门禁通过才自动运行固定18项，无需逐项再问用户。保持singleworker/threads1/AS8GiB/combined sampledRSS1GiB，不提高资源上限。

Git只收代码、小型合同/指标/SHA，不收checkpoint或大量数据。本轮已封存源码门禁提交不推送；后续未封存代码保持worktree，不制造半成品远端变更。见current_execution文档和runtime_ranking_v3_execution_ledger账本。
