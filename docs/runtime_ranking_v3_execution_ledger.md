# v3 执行账本：持续推进的边界

核心目标：在未见电路上推荐较优的D95安全H64/M16/F4组合，减少首次命中1%近优组合前的累计ATPG wall time。不能用未命中的低耗时冒充优化成功。

## 已完成

- v2负结果诊断封存。
- v3家族内pairwise排序核心、六折流程、神经/XGBoost适配器与全18家族seed回执宏汇总。
- synthetic物理分折包与冻结后留出标签加载门禁。文件hash、源manifest外部digest、精确fold成员均检查；禁止覆写原包。
- synthetic磁盘端到端18回执通过（mock预测，不是训练结果）。

## 单一环境权限阻塞

本机Python3.13，没有torch或xgboost；项目既有ML锁为Python3.11相关环境。未发现docker，可执行wsl存在但WSL组件未安装。应用bundled-dependency查询工具报告不可用。没有安装系统组件、下载另一版本Python或访问远端。

当前缺少明确获准的依赖齐全隔离执行环境，真实神经forward/gradient/fit与XGBoost兼容性/同seed复跑都不能验证。不得伪造ML PASS，不重复跑mock制造进度。

最小下一权限请求：允许使用B端一个全新`/ssd/cjc/gnn_model_ranking_v3_synthetic_*`隔离目录，仅部署代码和生成合成数据、验证现有锁定版本的模型测试；不读取任何真实电路/BLIND/历史checkpoint，不提交LSF或Tessent，不启动正式六折训练，不访问受保护`/ssd/cjc/multimode_ate_gnn_v1`。先检查可用空间/版本/源码摘要，发现冲突停止，不修改历史环境。

## 得到上述权限后的连续链

隔离环境与版本锁检查 -> 全部真实ML合成测试和三seed确定性测试 -> 修复一次有证据的聚焦失败并完整复跑 -> 物理fold层与执行接口独立复核 -> 源码/合同/审核回执封存同步。

真实TRAIN数据导出/正式训练需要后续独立release，不能用合成环境授权替代。BLIND仍关闭。已有VALIDATION属于已观察开发证据，不称作独立全新验证。

所有已完成节点不因再次收到“继续”而重做；遇到未授权边界只提出一次具体权限请求，不自动访问远端。

## 2026-10-04：环境阻塞解除，合成执行封存

用户批准上述合成环境范围后，已在B的新目录`/ssd/cjc/gnn_model_ranking_v3_synthetic_589b340_20261004_r1`完成测试。没有读取真实电路、BLIND或历史checkpoint，没有提交LSF/Tessent或正式训练。

- 初次源码包17个常规文件，经SHA-256和有界解包后执行30项测试：0跳过、0失败、0错误、退出码0。
- 不改首次封存源码，另建extensions扩展测试：3项测试全部通过。覆盖六留一家族折 × 三固定seed × CandidateMLP/GraphSAGE/XGBoost，共54次生成数据拟合；另外验证同seed预测和模型参数/booster字节复跑一致。
- 六折真实模型集成测试使用内存冻结回执；磁盘冻结/物理分折门禁由初次测试单独覆盖。不能声称54次流程均为磁盘端到端。
- Python3.11.2、numpy2.1.3、torch2.5.1、xgboost2.1.2及完整依赖锁核验通过。新venv只读共享旧锁定site-packages，并非复制了一套独立依赖；设置禁止写pyc，未修改旧环境。
- 本地回传核验通过：原始日志digest、父子回执连接、封存源码清单、扩展测试源码digest均一致，详见`data/manifests/ranking_v3_synthetic_integrity_20261004.json`。此项是执行者完整性核验，不是独立代码复核。

下一节点为物理fold层、模型接口和证据的独立只读复核；之后才能申请真实TRAIN数据release。独立复核及正式release仍未通过，BLIND与正式训练保持关闭。合成PASS不提供近优命中率或累计ATPG耗时改善的科学证据。

## 后续授权与 r2 固定执行入口

用户已授权：独立复核通过后不逐节点暂停，继续TRAIN-only数据导出、门禁和六折实验。BLIND、VALIDATION标签和新增LSF/Tessent不在此次范围。

独立复核发现并推动修复：扩展启动器/子回执缺固定hash绑定；通用回调不足以证明持久化冻结；normalizer未严格拒绝非法尺度；实际源导出与evaluator回执字段不兼容。历史合成回执不覆盖，新增r2完整性回执封存。

新固定worker子进程只接收拟合标签、全部候选特征和无outcome图；固定evaluator在ranking文件fsync及完整fold SHA回读后才打开留出标签。此为科研数据流防泄漏，不宣称阻挡恶意同用户代码。真实源导出绑定已审核v2输入摘要，仅投影六TRAIN家族；允许读取既有features/graph manifest中的VALIDATION元数据以筛选，但不读取其标签或图JSON。

代码独立复核已PASS。B端r4新目录23次测试执行零跳过/失败，其中4次是被重复发现的exporter测试，故只有19个不同测试；直接worker覆盖54模型拟合+18启发式，子进程端到端仅覆盖18启发式。该范围已独立封存。为了验证所有正式模型的子进程路径，r5正执行全部72个toy子进程/评估流程，且移除了重复测试发现。r5通过并独立封存前，不使用预备source release导出真实数据。

### r5 合成闭环和真实数据门禁已完成

r5已完成19个不同测试，零跳过、失败、错误；直接worker54次模型拟合+18启发式，完整子进程54次模型+18启发式端到端，已独立readback封存。新B正式目录`/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1`依赖预检PASS，仍使用新venv共享只读锁定依赖。

真实TRAIN-only导出已执行，source SHA `b89b455ace9d545c0afd54fe9fded98e4db4abd56f58fe09a0cce28b88215d9c`，package receipt SHA `964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868`。独立审查实际新包的1706 UID、六图、24 shard、六fold互斥/全集、D95与正finite cycles/runtime全部PASS。审核只重读新包，原源文件SHA由固定exporter核验，不冒充第二次源目录复哈希。

本地focused回归47 tests、4个缺ML依赖skip、零失败；标准`python -m unittest discover -s tests -q`全回归退出0。自建staging回归wrapper先因模块搜索路径失败，失败日志保留；不改模型代码，改用标准命令完成全回归。skip不充作B ML PASS。

执行release已create-once并绑定r5代码/ML回执、独立data review、package SHA和固定源码清单，最终独立链接检查进行中。只有该检查PASS后才启动一次性固定训练；不自动重试、不覆盖checkpoint、BLIND/VALIDATION标签保持关闭。

### 真实 TRAIN-only 六折实验已启动

最终独立复核已返回 `PASS_TRAIN_ONLY_EXECUTION_RELEASE`。固定执行release SHA为 `ad6b7721ae543cb0eb37765394d249922a6a114d49ecbb78d46b006d9a285205`。上述“检查进行中”是历史节点，不再是当前阻塞。

新B目录已启动一次性监督进程 PID `2050273`，回执见 `ranking_v3_train_launch_20261004.json`。预期六家族 × 三固定seed × 四方法，共72份评估（54次模型拟合，18次启发式）。最新现场检查为进程存活、12/72完成；这不是最终结果，不据此宣称命中率或ATPG耗时改善。

用户授权已覆盖复核通过后的自动衔接：运行监控 -> 完整回执/摘要核验 -> 独立结果审计 -> 中文结果汇总 -> 版本同步。不逐步等待“继续”。仍不打开BLIND/VALIDATION标签，不新增LSF/Tessent或自动重试；checkpoint保留B端，Git只收代码、合同、小型指标和摘要。

## 2026-10-05：72/72 完成，结果独立审计与归因已通过

监督进程结束，exit=0、retries=0；四方法各18份评估全部完成。独立证据复核核对26源码条目、12审核源码hash、请求/worker/fold身份、72磁盘冻结排序与标签replay以及四汇总，全部一致。summary SHA `feb8c4b795bab044649538dee115a8668051f0cbd0424ca4644360014bc39357`。

本地r1回传只收148个小型结果/审核记录、不收checkpoint，SHA `6f3336eb3acbbf87609ceff6e26141258956e0606f861f0673721ac2d1d91660`。复核要求进一步把每个持久化freeze文件连接到回传包；保留r1，新增schema2回传包，72个freeze文件只返回SHA/bytes，SHA `01468f838e4ef923b72028f8a59c2a5430d8e2b2faf13745fe87dc43806bcad8`，独立复核PASS。r1/r2的148个parsed record完全一致；不改变训练或结果。

已按描述性计划执行逐家族命中、top10重叠、seed排序稳定性、共同命中成本和非穷举敏感性，不筛选seed、不重排、不修改epsilon/K。计划明确记录headline已经观察，不冒充实验预注册。collector本地重算允许1e-12纯浮点求和差异：Python3.13补偿求和与B封存Python3.11约1e-13差异，身份/UID/hash/grid仍精确一致。

实质结果：XGBoost命中12/18，启发式6/18，MLP/GraphSAGE各3/18。剔除只有10候选的s35932，分别9/15、3/15、0/15、0/15。XGBoost非穷举平均累计cost约942.6s，启发式约940.3s；共同命中的非穷举s38417每seed多约227.885s。因此 **ATPG_RUNTIME_REDUCTION_NOT_YET_DEMONSTRATED**，不能写“GNN成功加速”。固定启发式与XGBoost每家族三seed排序相同，不把重复seed当独立家族。

本地完整回归先完成648 tests，新增collector测试后再次完整回归653 tests、22 skips、0 failures/errors，exit0；新增collector持久化freeze拒绝测试与归因测试合计8/8 PASS。Windows/缺ML等skip不替代B真实执行审计。报告采用指标诊断+技术报告技能，保留逐家族与成本反例，而非只报宏平均；报告图表数据由实际本地SQLite汇总生成，原始数据/查询均保留。

已自动进入下一节点：只读检查现有TRAIN候选七维特征是否存在同一家族内不同动作特征碰撞，核对近优正例数量与家族内常量。先定位信息表达和成本失配，再冻结下一版方案；当前不启动新训练、不访问VALIDATION/BLIND、不新增电路或ATPG。

特征诊断已完成并独立核验：1706个动作、14个1%近优正例，家族内7维向量1706个全部唯一，无动作特征碰撞。图/common-fault值家族内恒定，H/M两个变换并非独立信息；不能据此声称GNN无用或已找到失效根因。

自动进入v4本地设计：仅改变CandidateMLP近优正负排序对，固定旧epsilon/K/seed/特征与架构参数，家族等权、SHA确定性工程cap。v3-r2合同为历史证据，不覆盖；另建v4合同与纯函数合成测试。该模块没有训练runner或实际执行权限，后续集成/合成闭环/新release不冒充已完成。

v4本地kernel独立复核PASS：4项纯合成测试通过，包括准确epsilon、非法输入拒绝、超cap置换确定性、家族等权及评分方向。最新全量回归657 tests、22 skips、0 failures/errors、exit0（58.965s）。只封存本地实现，不宣称v4实际训练、泄漏端到端门禁或耗时改善。

## 2026-10-05：v4 synthetic-only worker 与实际 Linux 合成闭环

已实现新worker和固定合成harness，不改封存v3代码。worker严格拒绝非synthetic scope、额外字段、留出cycles/非法数值；fit normalizer只使用拟合家族。沿用旧CandidateMLP架构、120 epochs、Adam及seed，仅改变质量排序对。CLI将真实读取request的raw SHA与canonical SHA写入回执，先保存checkpoint/持久化freeze，再由harness评估留出生成标签。

独立代码复核PASS后，在全新B目录`/ssd/cjc/gnn_model_ranking_v4_synthetic_445af8f_20261005_r1`执行实际神经模型子进程。仅克隆既有新实验的39个代码文件并叠加5个新代码文件，不读取其真实数据；7319-byte tar.gz经SHA、5条目、单文件与解包总字节门禁后提取。环境复用旧锁定venv解释器、禁止写pyc，并非新建独立依赖。

实际合成18个家族/seed组合加6次相同seed复跑，24子进程全部exit0，重复freeze payload与model.pt SHA一致。生成数据每家族3候选，不能用合成命中率主张效果。execution receipt SHA为`f1faa7237bed0d7beb7e4e3fb429b51c74199542eee87a4090c9276fb22517c5`；deployment SHA为`a31d4a560c2a96230c76145d7599f0576c7d81659d111dcfa44cc7387fc09fb3`。

本地完整回归661 tests、22 skips、0 failures/errors、exit0；本地8项kernel/worker测试中神经调用使用fake adapter，不冒充本地ML执行。Linux实际24次拟合是另一个证据层。结果独立回读正封存；真实v4 runner/execution release尚未建立，不启动真实拟合，不打开VALIDATION/BLIND、A或LSF/Tessent。

独立结果回读现已PASS：5个overlay/39个base code SHA、24组request raw/canonical连接、固定argv与exit0、24组持久化freeze再评估、6组重复checkpoint/排序全部核对一致。Linux同环境8项focused测试0skip/0fail/0error。原始execution receipt的pending标记不覆盖，由新增SHA-bound independent review回执消除本阶段审核挂起；不是实时训练release。

## 2026-10-05：低内存真实 v4 执行 r2

用户授权连续推进并控制内存。实现真实TRAIN-only worker/driver，复用已封存1706动作包，只运行18次CandidateMLP，不重跑旧对照；raw/canonical request SHA、fold source SHA和精确6×3 grid均绑定。标准化、oracle/排序对仅来自拟合家族，持久化freeze验证后才读取该fold留出标签。

资源保护：单worker串行、各库1线程、0.25秒采样父+worker进程组RSS，超过1GiB停止；child RLIMIT_AS硬上限8GiB/core0，宿主/cgroup余量至少max(4GiB,10%有效总内存)，启动再留1GiB余量；超时1800s、停止本进程组、保留日志、不自动重试。采样不能保证瞬时RSS零超调，也不能控制其他用户分配；没有清缓存或改共享主机swap/cgroup配置。

独立复核先发现dead-leader仍留子进程的漏洞，已修复为检查整个进程组并确认无存活成员，补Linux实际压力/超时/遗留子进程/AS和线程证据。生成数据真实ML smoke峰值combined RSS557162496 bytes（约531MiB），成功，不能代替真实数据峰值或性能结论。

r1启动时输出路径门禁与launcher的`ROOT/experiment`不兼容，0fit失败，原目录与exit/log完整保留。一次聚焦修复只接受新B root的experiment子目录，补launcher兼容测试；另建r2，不在r1重试或覆盖。r2 Linux13/13 tests0skip/0fail/0error；本地全回归674 tests/25skip/0fail/0error。独立release精确绑定13代码hash、review、smoke及launcher均PASS。

当前r2新B目录`/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r2`已单次启动，supervisor PID2449282；release SHA`70c458c9d4f70f87ab2fc12a220b46e325154480326051ae93fc7abc66127f31`。预期18份评估、0重试。继续监控内存/进度 -> 完整结果独立审核 -> 与封存v3基线对照 -> 版本同步，不等待逐步“继续”。此启动记录不是完成或加速证据。

### r2 安全停止：最新权威状态

r2 最终 exit=1，15/18 份评估完成，0重试；第16项 `iwls_spi_20260824_candidate_mlp` 触发 `MEMORY_RSS_UNREADABLE`，并非记录到的内存超限。已完成任务 combined RSS 采样峰值592502784 bytes（约565MiB）；停止项峰值569974784 bytes，worker exit=0，但安全回执仍是STOPPED_NO_RETRY，清理后live_group_members=0，不把worker exit0冒充完整driver成功。

exit原始SHA `992e10b329a59657918ca617fb5b05533ff38ba4f4c6dcd87f7e56e21fe29bed`；失败memory原始SHA `ce05463fae23dc180a8a1df032c4acac7554d57fe7761ad440b119e1cd0fd2a5`；driver traceback SHA `b7ac830715bdb832a5d9cc95779f4d3d995c224ab48a6af153189b280e342c47`。原B目录及部分结果保留，不覆盖、不续跑、不选择性报告15项效果。

独立代码复核识别退出竞态：group枚举时活跃，读取status时已zombie，VmRSS消失。最小本地修复仅在二次stat证明Z/X或进程已消失时计0；仍存活但RSS不可读、坏stat或权限错误继续fail-closed。新增竞态单测，focused14tests通过，Windows3项Linux执行skip不视为Linux门禁通过。当前不部署修复，不进行第三次真实运行；需新Linux资源门禁与独立release复核后再决定新的执行方案。

修复独立只读复核 `PASS_RSS_RACE_FIX_CODE_GATE`；本地完整 `unittest discover -s tests` 回归 exit0。执行release记录为历史已执行绑定，不适用于当前已修改guard源码；当前合同已撤销新的执行放行。

## 2026-10-05：RSS 修复 Linux unit-only 门禁

继续请求后完成新隔离门禁。独立部署审核先指出import来源/失败回执缺口，已补生成空package markers、固定ROOT模块来源断言，以及仅为本次新目录create-once写失败receipt；已有目录不修改。只传2个源文件、4015-byte tar.gz，SHA `1c35b67a813843daa91fdc46c73696364d56d6fcfba1d60727e580e9a42b4fd7`，严格条目与字节门禁。

在 `/ssd/cjc/gnn_model_ranking_v4_guard_gate_dfbd25c_20261005_r1` 用隔离 `python3 -I` 实际执行7 tests、0skip、0fail、0error、exit0、gate_pass=true；覆盖退出race、内存停止、超时、遗留子进程、硬AS限制与线程环境。环境Linux6.1.0-47-amd64、Python3.11.2、GNU sort9.1。原始receipt SHA `49460c9f357b1fdc26ff03c0dbebf75044463e5e4109f917ceaa3a7393338a65`，小型log SHA `5c8d3b76fca802e19b8aa036408a7d4351077deca63128bcbea64c1cdd9ba100`，imported guard路径精确为该门禁ROOT。没有模型拟合、数据读取或真实release。

新增r3恢复计划为PLAN_ONLY：保留r1/r2，不续r2、不拼15项加3项、不挑最好/最快success。若通过后续集成合成ML、资源与独立release审核，并解决两次失败后的第三次运行升级边界，拟在新根重跑固定18项；当前没有注册或启动第三次真实训练，资源上限未提高。

Linux raw log/receipt/archive/deployed source/import origin/资源门禁与目录无数据均经独立只读回读PASS；parent复核本地原始receipt SHA一致。本地full regression679 tests、25skip、0fail/0error、exit0（70.213s），log SHA `f3f12656c227cea165e54b28918b2b31021ac39b620e0c3390653c9a9984542e`。r3计划scope复核PASS，修正quality-pilot旧“尚未启动”叙述为r1/r2事实。此阶段仅Linux unit门禁封存，没有新的训练release。

## 2026-10-05：r3 集成门禁与新授权

用户明确批准：全部门禁通过后自动完整重跑18项TRAIN，不提高内存上限、不再自动重试。不是恢复r2，也不拼接部分结果。

代码集成r1的审核重放意外生成7份Python缓存，完整inventory门禁正确失败；43份源码SHA没有变化。原目录、缓存与失败receipt保留，未删除缓存或放宽门禁。另建只读r2代码快照，43份源码文件0444、目录0555，独立审核后仍无pyc。snapshot SHA `e79b38fe79eb4ca69ac6299775769bb9b6267c64c595fef287c7fa45c1e345f1`。

该只读快照Linux实测14 tests、0skip/fail/error、exit0，actual-exit receipt SHA `84221c712987296fca64482c8dc5234fefed25e6ca67cf1224b88fb2e4deb648`。生成fixture单次ML smoke PASS，combined RSS574844928 bytes（约548MiB），receipt SHA `0b67c8526902377a8e5715c85cc6dfcae361ce53e1afefc9723de0376e68768c`。独立复核PASS_R3_RELEASE_PRECONDITION：代码、raw/canonical request、拟合UID、持久化freeze重放、模型hash与进程组清理均通过。不是实际效果证据。

本地完整回归698 tests、25skip、0fail/error、exit0；日志SHA `f095b3e80591cf0efdbd43d14490c867ffb95b7352eb6897d9b91188782917c7`。在全新真实r3目录生成固定TRAIN18项release SHA `6a6afccb5ff0ff4973049d227982f4ce000ae48379ccd1c04033c84079c0ad2c`，绑定13源码与独立回执。最终launch绑定独立复核通过后自动启动，不等待下一次“继续”。VALIDATION/BLIND、A、LSF/Tessent仍封闭。

最终独立绑定PASS_R3_EXECUTION_RELEASE_READY；随后单次启动supervisor PID3712850，真实root `/ssd/cjc/gnn_model_ranking_v4_train_dec61b0_20261005_r3`。固定18项、单worker、0retry，源代码使用上述只读r2快照。继续监控到完整结果与独立审核；启动本身不证明效果。

### r3 再次安全停止，禁止继续自动重跑

最新实际状态：9/18评估完成，driver exit1，0retry；第10项 `iscas89_s38417_20260824_candidate_mlp` 再次触发MEMORY_RSS_UNREADABLE。已完成项采样combined RSS峰值589377536 bytes（约562MiB），失败项574992384 bytes；worker exit0，但guard状态STOPPED_NO_RETRY，清理receipt live_group_members_after_cleanup=0。这不是记录到的超限，也不能因worker exit0忽略失败。

exit SHA `5939d5745ec05414620dcbefa460b18c7a65c5219c43f6aa19ba4bca4742d2f2`，driver traceback SHA `499c7149bf6656bb0062423e837618b5791b78b3d9ff6281d345596883bb8a70`，失败memory SHA `475286662eb9cf08056656b39ff28c5ec474a61452e387bccc8e0cbb00cb1516`。原root和所有部分产物保留，撤销新的执行权限；遵循用户“不再自动重试”，不运行第4次训练、不提高内存上限。不把9项结果用于完整效果比较或报告。

独立失败回读确认10个worker/freeze/model、9个evaluation、10份memory，以及当前失败进程组无存活成员。退出边界竞态是与证据一致的解释，缺少当时status/stat快照，不能断言瞬态内核状态。后续建议先本地补“VmRSS缺失后leader已退出且group无存活成员”的测试与诊断记录；持续存活且RSS不可读仍必须失败，不能一律算0。新的真实运行需单独决策，不自动申请或启动。

有界收集器和未来比较器本地实现已完成；比较器拒绝重复/额外/缺失grid、NaN/inf/非法metric，仅对共同命中计算条件成本差。因真实r3不完整，未使用它收集或比较9项部分效果。最终本地完整回归702 tests、25skip、0fail/error、exit0，日志SHA `5da5a60e29ecace04f630093cacc3f457c6264742b8458211379d41c546cd0d9`；这只是代码回归，不是训练完成证明。

独立最终review补发现双v3 manifest一致性检查遗漏GraphSAGE；已改为全部72单元比较，新增GraphSAGE单独变异拒绝用例，4项focused PASS，独立PASS_COMPARATOR_FAILURE_SEALING。补丁后再次完整回归702 tests、25skip、exit0（63.216s），raw log SHA `3f054b95b8b237e9fd67c68620c83fe08d73b9a0270020eac5d2b31a75aead34`，封存回执绑定最终版本。

## 2026-10-05：退出边界修复与 unit-only Linux 验证

“继续”后只推进资源观察修复，不进行第4次真实训练。新增专用异常，仅在worker组内VmRSS缺失且stat格式合法时允许进入退出边界核对；waitpid-backed poll确认为exit0且整个组无存活成员才完成。仍存活、遗留子进程、非零退出、父进程RSS错误、权限或格式异常均安全停止。未增加RSS/AS上限，没有采样重试或worker重试，不伪造零样本、不抹去既有峰值。小型诊断保存PID、stat状态、退出码、group数量和至多16个PID。

独立本地复核PASS；focused12 total、9pass、3Linux-only skip。新的两文件tar.gz仅5244 bytes，SHA `b34f5a8fddddd4f61a46daf2b4bccaeff9925444eb1a381a581e4d586fcdaf91`，新unit根 `/ssd/cjc/gnn_model_ranking_v4_exit_boundary_gate_30664e2_20261005_r1`；python3 -I实际12tests、0skip/fail/error、exit0。receipt SHA `570ea61dbdd9d45c25693a908f2b517fe35bedeb869a3f754f6f620dd34982be`，raw log SHA `1cdde150ae6c62a1ba4d09e356d7aa2d98cd934b02cfeab586ce99159cb59abe`。退出竞态单测使用受控模拟，Linux另实际执行轻量子进程压力停止、进程组清理、地址空间与线程限制；没有真实PyTorch拟合、数据读取、LSF/Tessent或训练release。

本地完整回归711 tests、25skip、0fail/error、exit0（80.575s），raw log SHA `a63e96f4f689b98da7e08b61d9e18fda5414e577008868ead00034eeec023497`。历史r3仍9/18失败，原roots/receipts不改，不能以此unit PASS宣称真实ML竞态彻底消失或ATPG加速。新的真实运行仍未授权；下一验证层应是新源码绑定的合成ML集成证据，而不是沿用旧release直接重训。

Linux门禁独立封存PASS_EXIT_BOUNDARY_UNIT_GATE_AUDIT：实际raw receipt/log、导入来源、原始5244-byte两项归档及deployed源码逐字节一致。合成ML集成验证和新的真实release尚未完成；门禁封存不自动撤销用户“不再自动重试”的限制。

## 2026-10-05：退出边界合成 ML 集成独立封存

用户批准上述下一验证层，本次只执行生成 fixture，不是第四次真实 TRAIN。新根 `/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1`，11996-byte、7-entry tar.gz，SHA `fc072f82e2f14ab07f5a6afb1834c0ad76c494fb27e57c6e7ee4a601c3848ab6`。43份代码哈希绑定、文件0444/目录0555，复核前后无pyc；没有修改旧根、安装依赖或访问真实数据。

Linux focused 实际19tests、0skip/fail/error、exit0，raw log SHA `3897ade430f130bb21e51d4ad8693db06264322faee1ede0b9bd9a7d5b73d612`。随后仅一次 CandidateMLP 合成拟合：18人工动作、15拟合UID、3留出UID，固定seed20260824，留出标签未供应worker；raw/canonical request、依赖锁、持久化freeze/model哈希与回放均独立回读一致。smoke receipt SHA `16d8b76b07c01b115e6a4843d266e2411d88dd1a9dee4f7a4185e956706b2958`。

单worker、线程1、零重试，采样combined RSS峰值530558976 bytes（约506MiB），仍采用1GiB RSS采样停止阈值与8GiB地址空间硬上限；exit0、进程组589053无存活成员。独立结论PASS_SYNTHETIC_EXIT_BOUNDARY_ML。此smoke未报告退出边界分支触发，不能证明瞬态竞态完全消失；人工耗时也不是ATPG wall time或加速证据。

本地完整回归716tests、25skip、0fail/error、exit0（81.770s），raw log SHA `80486df416eff331df4ac38d070e59e08aea1a1e151120647c4b696c217aeab3`。历史r3仍9/18失败且保留，不拼接、不用于效果分析。本阶段封存不授权第四次真实训练；新真实运行必须另有明确授权、新源码绑定release和独立启动前复核。VALIDATION/BLIND、A、LSF/Tessent仍关闭。

## 2026-10-05：第四次完整 TRAIN 的明确授权与 fresh release

用户明确批准第四次完整18项TRAIN：新放行门禁、独立复核通过后自动启动，保持1GiB sampled combined RSS、8GiB地址空间硬上限、单worker/线程1、零自动重试。新root `/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4`；使用已合成集成封存的只读43文件code snapshot，不续旧run、不拼部分结果。

独立B只读预审PASS_R4_REAL_RELEASE_PRECONDITION：43源码/13执行anchors无漂移，1706 TRAIN动作及outcome、六份manifest的全部shards/graphs哈希一致，拟合/留出UID互斥，既有venv31项依赖锁一致，资源余量通过。TRAIN数据包仍SHA `964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868`。

启动器独立审指出手工supervise可绕过Popen失败与重复调用的风险，已补父pending回执fsync后hard-link原子发布、5秒PID/exact-binding握手和一次性claim；receipt绑定launcher/package/output/code/release，失败与pending亦阻止重试。monitor限制10KiB并拒绝所有路径symlink。release prep校验fixed cwd/review/smoke/source/resource后才create-once新root。15项focused通过，独立PASS_R4_LAUNCH_AND_RELEASE_PREPARATION_CODE_GATE。

发布命令曾发生shell引用SyntaxError、snapshot未包含旧release-creator的import错误；均在ROOT创建前失败、未启动任何TRAIN。新prep改为直接使用snapshot内real-worker的相同release schema校验，绑定本次明确授权；没有放宽门禁。fresh release已生成SHA `ad5dd0e57459ee74ba018aebe72bc8e6f9f95dcc63cf8ce44941f167813e96cb`，review SHA `928bc23624949e381e96022c715c697baa6cd9d87339a87b1ec7e7b5bb70fc9b`。旧失败根不修改。

最终本地731tests、25skip、0fail/error、exit0（79.018s），raw SHA `b9642fa89bcd574a0e3b586c36477634505d4a1d6c4a0e56f2f87a10e90cfcfa`。等待独立fresh远端release/launcher绑定最终门禁；此记录尚非训练启动、完成或ATPG加速证明。

随后独立PASS_R4_EXECUTION_RELEASE_READY，远端再次核对release/13anchors/43只读inventory、外置launcher/monitor、package/smoke、fresh无intent/claim/experiment与资源余量。按明确授权单次启动supervisor PID753397，启动receipt绑定release `ad5dd0...e96cb`、package、CODE、launcher及固定18项。零重试，继续监控到完整退出及独立结果审计；启动不证明效果。

### r4 完整执行与独立结果审核通过

实际18/18、driver exit0、零重试/零资源停止，采样combined RSS峰值605978624 bytes（约578MiB）；保持原阈值。独立PASS_R4_COMPLETE_RESULT_AUDIT：18份worker/model/freeze/evaluation/memory完整链，request raw/canonical SHA一致、拟合UID及cycles与fold一致、无留出标签供应，18份freeze readback及TRAIN-held replay与评估一致；所有18进程组无存活成员，43源码/13anchors无漂移、无pyc。

exit原始SHA `fd2454fa90c611b1e2ce91d0d5448c86ee2930a2d697dd46b6422a9e82851b26`，summary原始SHA `8767092df21fafe3a48a13253563c0b86457b4d0c01f736888c763a54655d9d9`。只证明此次完整执行与连接可信，不证明竞态永不复现、模型较优、ATPG加速或盲测泛化。旧r1/r2/r3失败证据不改，不使用部分结果。checkpoint保留B。

收集器独立复核后只导出白名单标量汇总，单JSON≤200KiB、合计raw≤2MiB、投影≤300KiB且create-once；拒绝非完整grid、exit/release/worker/memory不一致与nested metadata，不导出requests/labels/graphs/checkpoints。封存阶段全回归736tests、25skip、0fail/error、exit0（87.038s），raw log SHA `e74a59fe9988b72f0e9670ca4300d2fe6a3ed50cc6b9dbb5d2ddd8c0684ffaa3`。本次只授权这唯一r4，不自动新增模型实验、解封VALIDATION/BLIND或启动LSF/Tessent。

实际一次受限导出完成：58569 bytes、59条（5份顶层及18×evaluation/worker/memory），SHA `55253ab1685b683dc93469407ac4422d57cc142f07e836497a943e02ad74e353`。本地逐字节校验一致，checkpoint仍在B，JSON无candidate labels、模型权重或请求数据。完整结果可用于下一阶段固定基线效果比较，但本封存尚不提出加速结论。

补外置收集wrapper的fixed cwd/hash/20KB有界读取与拒绝测试后，最终739tests、25skip、0fail/error、exit0（89.237s），raw SHA `f60069c600ff384cd65a1078bc1eba75c2f938b0772179a515e091e00786f612`。

小型汇总最终独立PASS_R4_SMALL_RESULT_SEALING：59项结构与6×3网格、release/exit/summary原SHA、result-audit全部连接一致；无请求文件、模型字节、labels/outcomes、feature rows、graph payload、分数或freeze排序导出。此次完整18项TRAIN和证据封存完成。

## 2026-10-06：r4 固定对照，负结果不包装为加速

在本地对完整 r4 汇总与既有 v3 r2/legacy 汇总做精确 family/seed 对照。三份输入 SHA 固定；18 个 v4 单元、72 个 v3 单元完整，两个 v3 留存汇总的比较指标一致。不修改历史比较、不拼接旧失败运行、不新增拟合/远端作业或访问 BLIND。

独立重算确认：非穷举 15 项 v4 CandidateMLP 命中0，v3 CandidateMLP命中0，XGBoost命中9，固定启发式命中3。v4 mean top-10 regret 21.90%，平均计费ATPG成本891.90秒；较低成本伴随未命中，不是加速。非穷举共同命中配对为0，因此配对成本差为null而非0。全18项v4仅s35932命中3次，和XGBoost共同命中的每次计费成本高97.58秒。seed不是独立家族，TRAIN内结果不证明BLIND泛化，也不选定最终模型。

新比较 JSON SHA `7c98563021441f7b82af678b10c12bc7dab7b9c881bad9f6fa50bb38a516ed1c`。技术报告的图表从实际SQLite聚合产生，原生报告validate后render成功；小型报告JSON同步保留。报告生成器使用标准库，无新ML依赖和训练入口。独立审计确认重建与封存JSON一致、SQL与比较聚合在1e-12内一致。

继续完成本地实现路径检查：损失softplus(negative-positive)与降序freeze一致、normalizer只拟合fitting rows，r4仍七特征CandidateMLP，不是GraphSAGE；13执行源码anchors与release全部一致。未发现上述符号/归一化接线错误，但不能据此断言优化收敛。复用既有1706动作/14正例/无精确碰撞审计，不重复完成节点。新增后续诊断设计，下一问题为拟合分离度与跨家族尺度外推；当前没有epoch loss轨迹，不能插补或用第五轮拟合重建。本次不提供新真实训练/BLIND/LSF放行。

## 2026-10-06：仅推理的拟合/迁移诊断与历史模型身份补查

按用户“不直接重跑训练”要求，单次读取现存 r4 路径的18份权重，仅推理；0 fit、0 optimizer、0 held outcome files、无远端写入/BLIND/VALIDATION/LSF。18份 held 输出与旧 freeze 精确一致，峰值RSS423108608 bytes（约404MiB），单worker/线程1、零重试、未提高限制。原始小型诊断97109 bytes，SHA `d4c10136f72d2bd58004b3aa2354c8aba9a793394d133dab0041b9221b1d63c3`。

独立数值复核通过：非穷举拟合观察36/60、留出0/15；s13207拟合0/15、s15850为1/15，而s38417为14/15、aes_core/spi均15/15。重复折与seed不是独立家族。结果提示拟合内目标弱与迁移落差并存；无epoch轨迹，不证明收敛或因果。focused5项、完整750项（25skip、0fail/error、exit0），完整日志SHA `3c76f9ccc4dd4382b42321993ce10ca6c2cb57992e0b8cbb598e72fec695e8b0`。

独立门禁 **BLOCKED_HISTORICAL_MODEL_IDENTITY**：旧worker/evaluation未保存历史权重SHA，当前SHA加held-output一致不能证明训练完成时原权重身份。额外只读检查原worker也未发现该锚点；不事后伪造、不重训补证据。汇总PASS仅指计算和既有receipt连接，不能覆盖此BLOCK。报告明确限于当前路径权重的描述性排查；本阶段不启动新训练或发布正式原r4因果结论。

随后独立复核找回已提交的 `ranking_v4_r4_result_audit_20261005.json`（SHA `a6002053d39a32c6ed71ba35722e2d166aeb4d638eb3c056ae071f8cfcedded7`），其原始模型映射聚合承诺 `58db84f0f4b4ea445208def7963ea5a3c02317833f7a329b474a33f5ed53874b` 与本次18权重逐token重算一致。因此上段初审身份阻断由既有历史证据闭合；没有事后制造锚点或重跑推理。新增历史audit/release/exit/package/script pin与篡改拒绝测试。最终解释仍是拟合弱与迁移落差并存，不是因果或收敛证明。

补身份门禁后的focused6项、完整751项（25skip、0fail/error、exit0，67.324秒），最终日志SHA `6391591cef4b33a369d99c7a0aab7e25322fa00352dd49d94304558435d3af68`；原始诊断与汇总精确重建一致，真实推理仍只运行一次。

最终独立 **PASS_R4_READONLY_FIT_TRANSFER_DIAGNOSTIC**：历史身份门禁是summary前置强制检查，篡改拒绝有效，初审疑问已由既有历史证据解决，无remaining must-fix。封存仅诊断，不是新训练/BLIND放行或ATPG加速结论。

## 2026-10-07：排序目标与电路信息覆盖检查，仅本地

未重训/推理、未访问A/B/BLIND/VALIDATION/新图。校验旧diagnostic/summary SHA、模型历史映射及5份原执行源码anchors。六家族全部正负配对数均小于4096（s13207为586、s15850为548），没有cap漏掉正例，每拟合家族20%宏权重。合成分数反例独立公式确认：pair softplus从0.313262降到0.069857时，首个正例可由第1掉至第11；这是目标不保证top10的证明，不是实际失效的因果证明。

实际r4 real worker未传graph，只有7列CandidateMLP尺度/方案特征；共同故障数、绝对与相对H/M可间接体现电路尺度，但未供应拓扑。pair loss没有ATPG runtime成本，runtime仅在freeze replay累计。图是否有效和目标改动是否收益均未知。后续设计分离目标、上下文、成本对照，不原样重跑、不批量加电路。

本地3focused通过、全回归754项/25skip/0fail/error/exit0；日志SHA `9f97f8feb9905463e9f0dad71c997a9affadd0670db0090c8758a8b3dcb1745d`，汇总SHA `b83e957dd6abd3947497db68727c383cecf24fcd8c64284f40f6d4376843ad13`，精确重建。没有新独立agent review，不冒充正式门禁。训练、BLIND、新ATPG测量均未解封。

## 2026-10-07：隔离v5头部目标与fitting日志实现，torch门禁待执行

实现最大正例score与第10负例score间隔的macro softplus目标；不改ε/K或旧trainer，不加图/成本组件。旧反例在新目标中由错误偏好改为正确偏好；提供拟合INITIAL/EPOCH/FINAL日志，记录首正例rank、前排负例数、hit/regret、gap/tie、天然命中零信号，拒绝held标签、伪造recipe、非法score/overflow。天然命中家族仍保留macro分母并显式标记无目标信号，不能冒充拟合成功。

focused9项、完整763项/25skip/0fail/error/exit0（98.792秒），log SHA `24e5e7a70bf8afbd6f4ea16f4c9a5061eb66c673ddec5031530f61e3495f6936`。本机torch不可用；有限差分只证明标量方向，不是自动求导证明。新增显式generated torch门禁脚本且语法检查通过，但尚未执行，不skip冒充PASS。没有训练/推理/远端访问或新独立复核。状态PASS_SCALAR_REFERENCE_ONLY_TORCH_GATE_PENDING，不放行真实训练、BLIND或Tessent。

## 2026-10-07：B实际torch合成门禁与连续封存

用户指出B既有Docker/PyTorch环境并授权继续对应实验。只读检查确认Docker20.10.24及已缓存NVIDIA PyTorch镜像；既有v3 venv已可导入torch2.5.1+cu124，无需启动容器或安装依赖。使用现有锁定Python3.11.2，31项distribution版本精确一致。源码经STDIN在内存加载，固定/ssd/cjc cwd与解释器、3个source/lock SHA，不部署远端文件、不读真实数据/图/checkpoint。

单次实际合成门禁exit0，0fits/optimizer/retry，CPU float64前向/活动边界梯度/天然命中零梯度断言通过。RSS412598272 bytes，线程1/interop1，8GiB AS硬限制/1GiB RSS观察阈值未提高。raw log SHA `96e49e67ae197316b84504a7a6292221565e952131c8b654e35e358be2773d05`。

同时保留CUDA初始化Error2 out of memory warning，不能报告无警告环境。后续只读容量快照未显示主机/GPU容量耗尽，不能据此断言原因或瞬态状态；没有屏蔽warning/重试/提高cap。真实CPU断言与环境caveat分开记录。未做新独立agent复核，审核请求READY不是PASS。

自动继续完成11focused与765全回归（25skip、0fail/error、exit0），log SHA `1b8d2f7a1e710c1e2cf0a5504789e1973bafa4c7acd3bcffa414eef86331a805`。封存receipt SHA `46e389da754070c376368890d1beb1234fc83e19e97ba500c90e0ec83bd46e06`。另准备只改头部目标、7列/seed/120epochs/optimizer/资源不变的18项受控对照设计；仅设计，trainer尚未接入，不启动新真实训练/BLIND/LSF/Tessent。旧pending合同和证据不改。

## 2026-10-07：v5 synthetic训练接线与日志，连续本地实现

新增隔离kernel，保留旧r4与已封存objective SHA。拟合侧归一化/7列MLP/Adam/seed/120轮不变，head loss作为唯一优化目标；旧完整pair loss仅日志诊断。专用synthetic scope、无CLI/真实release/held推理/远端写入。scope自身不证明合成来源，后续实际执行需外部来源门禁。

本地17focused通过；完整771tests、25skip、0fail/error、exit0（84.990秒），raw log SHA `dac993ba8c784b02b286b2322f648b2718d7dfa6cdf78f57bbce8b389f27591f`。mock验证120优化步及122条拟合汇总日志；held标签拒绝、held特征不影响fit、日志无动作UID/分数向量。不是实际tensor优化循环或训练确定性验证，没有独立复核回执。新增真实fit=0、远端调用=0；下一节点仍为独立复核与单独的新synthetic integration gate。未放行18fit/BLIND/LSF/Tessent，未增加资源或重试。

## 2026-10-07：v5实际synthetic kernel执行与独立封存

AgentFleet独立只读复核 objective/kernel/builder，修复执行前 wall-time/CUDA fence遗漏后允许单次CPU synthetic门禁。11份源码/lock均绑定；72人工动作、60fit动作，两次预计划同seed各120steps，122条拟合日志/fit和权重完全一致。远端exit0，2.39478秒，峰值RSS522153984bytes（498MiB），AS8GiB/CPU120s/外层timeout180s，单线程，0retry，真实fit=0，远端artifact写入=0。

CUDA初始化Error2再次出现，raw stderr完整保留；独立复核为PASS_WITH_WARNING，不宣称cleanCUDA或真实电路学习收益。原日志SHA `647e83f7381f9a4e3434cda4435426348a1a12975c5ea50ddae89f22c72199cf`。program SHA为发送前逻辑源码，不冒充远端stdin字节捕获。外层argv/exit另在manifest记录工具回执来源。

修订后完整773tests/25skip/0fail/error/exit0（69.635秒），log SHA `0b14520f289faba176705c38e3e33edcfecc097c47a41351ca53251dc253db36`。独立复核了实际raw log、11pins和封存文字，补齐全回归绑定后可本地提交。正式18fit仍未放行；下一节点为新真实release/freeze/receipt门禁实现，不复用r4放行。

## 2026-10-07：v5放行/冻结逻辑边界与独立修订复核

隔离实现callback-only boundary；严格v5 scope、package/gate/hash和12项源码清单，保持120轮/3seed/7列/Adam/K/ε/单worker/资源/零retry协议。模型持久化需expected SHA精确回执，freeze需canonical SHA确认并完整回读，之后才允许可选TRAIN LOFO held标签加载。请求不接受held标签，所有特征先做有限性检查。

复核实际复现了额外盘符路径、浮点seed及回调可篡改验证后对象的绕过，均修复并复测。内部输入用快照/预hash，fit取得prepared/recipe副本，保留normalizer与receipt identity。独立PASS仅purecallback逻辑，未冒充CLI/physicalstorage/sourcefile/审批证明/真实trainer。父23focused通过；复核者21项（未包含额外gate2项）通过。完整779tests/25skip/0fail/error/exit0（87.581秒），raw SHA `b3e0c0f3e35e24afaaa338c612f913feb03e292a14e073d4addbcd7709f1f817`。

本节点真实fit=0、远端访问=0，无BLIND/受保护目录访问。物理v5 worker/launcher、实际文件SHA回读和运行中combined-RSS限制尚未实现；正式18fit release仍false。
