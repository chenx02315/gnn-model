# 2026-10-10：连续推进torchgen精确兼容与新单次CPU门禁

用户明确要求开始对应实验并连续推进；承接上一轮具体下一步，记录为精确来源修复、审核后一次新CPU门禁。旧单次授权与失败目录不复用。保持worker1、threads1、AS8GiB、combined sampledRSS1GiB、timeout1800s、零自动重试。

## 来源证据

只读固定B环境的torch-2.5.1.dist-info/RECORD（上限2MiB）及torchgen/__init__.py（上限64KiB），没有导入ML、没有读取生产数据。RECORD1282288字节，SHA256 `6e4c4e1e9cc00f7cc054969ae419e26c9a7b95c0be50914b54bb870200ee56cf`；其中torchgen/__init__.py记录的SHA256与真实348字节文件一致：`8a2ad3a46dfc59c0ac34c8446e2d5d83bfe369dea9b64feecd9f81cda1811725`。wrapper为`../runtime_training_staging_20260928/v5_torchgen_ownership_20261010_r1.log`，SHA256 `7a14c413fd2b5b59c3c8c3e2b4aa29aba83086d25f8ae53a1f287cfbcc89167a`。这是安装来源证据，不是全部依赖内容封印。

仅增加`torchgen -> torch`精确发行包映射，不添加pin、site路径或通配根。合法来源通过；tmp/保护目录/其他包来源/../路径在文件检查前拒绝，torchgenx/torch_other/packaging仍在finder lookup前拒绝。首定向命令错写两个测试模块名导致ImportError，保留终端失败，纠正命令后43tests/0failure/error/exit0，4.507s；该错误不是源码或远端门禁失败。

最终源码SHA `1490829940cd851ac3e2d75467a37ac6608eef82bd03b01faa5e8113531b31ff`。候选包为`v5_torchgen_packet_20261010_r1.tar.gz`，SHA256 `beab004b45f280106960ca69e8d1370c6921d9e9cb7154ab7f5d794ce67cee66`，11635compressed/51200tar/4regular entries。

## 依赖节点与停止线

1. 来源核实、定向测试已完成。全量回归、独立代码/精确包复核pending，不部署未通过版本。
2. 全部通过后，在新`/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r2`一次运行CPU导入/小张量门禁，独立回读并审计小型原始证据。若失败，封存、零自动重试，不启动TRAIN。
3. 若实际门禁PASS，不停在小步骤：继续实现并审核18项串行矩阵父入口、每fit独立来源/授权/release/prelaunch绑定及模型/日志/freeze/receipt回读，首失败即停止。
4. 既有18项条件授权不替代release或数据门禁。完整矩阵入口、独立复核、新鲜环境门禁全部通过后才能运行指定TRAIN；BLIND/LSF/Tessent仍不开启，checkpoint不进Git。

## 实际结果（覆盖上方pending）

独立51项、精确四条目包审计通过；源码冻结后全量1008tests、33skip、0failure/error、exit0、119.220s，日志SHA `f39e79900f25459f9b48a541f649b75330eabcd8925edd3e564d1a2f2ca9bdef`。实际部署并运行新r2一次，exit1。torchgen映射问题已越过；Torch `_pytree.py`用`importlib.util.find_spec('optree')`探测可选C++实现，当前未知root异常中断了这个本应返回不存在的探测。源码只读摘录和两个固定site的PathFinder探测证实optree不存在，没有导入ML或安装任何包。

guardSTOPPED_NO_RETRY、3samples、combined368873472（约351.8MiB）、group348254208、cleanup0，非内存超限。本版实际gate1、retry0、fit0、formal_training_release=false；原始证据manifest为`ranking_v5_controlled_runtime_failure_20261010_r2.json`。旧目录保留。

下一节点不再盲增root白名单。需设计精确“可选模块不存在”探测协议，直接import未知模块仍拒绝，不能让finder返回None后落入其他finder；不能安装未锁定optree或放宽所有site包。候选是只包装特定`util.find_spec('optree')`的absence语义，在新鲜固定路径无缓存/无spec前提下返回None，其他探测走原函数，context退出恢复。独立原始失败审计PASS_FAILURE_EVIDENCE_AUDIT_ONLY；独立复核认可该设计方向，但要求每次全部固定路径的新鲜absence检查、缓存/污染/直接import拒绝、异常恢复和嵌套拒绝测试。已形成有限设计合同`contracts/ranking_v5_optional_negative_probe_design_20261010.json`，明确设计非实现，不部署候选。本次单次远端额度已用完，不能自动再试。
