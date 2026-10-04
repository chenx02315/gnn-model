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
