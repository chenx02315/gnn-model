# E135准备：重放已有F向量，直接证明F自身检测

## 最新实际结果：首读失败，整包按约定关闭

唯一实际A调用正常连接并通过主机、UID和boot核验，远端运行约0.1116秒，采样峰值12832768字节。SSH返回码为0；失败不是无法登录服务器，而是读取协议返回capture_complete=false。

已取得旧F tester.stil的hash-only回执：443378字节，SHA-256 333d9f9bd359cf9066501a41e748b2182f5c787ffd46e112c7b5c5c2c6c5eae2。文件为UID1047、普通文件、单链接；实际reader完成流式哈希及身份复核，但没有导出STIL正文，不能冒称本地独立重算、历史字节身份或256个pattern已核验。

随后在READ_REFERENCE阶段触发PREOPEN_SIZE_CAP。源码的尺寸条件是非零且不超过32MiB，检查位于参考文件os.open之前；响应没有返回具体尺寸，所以只能说大小条件失败，不能断言必定超过32MiB或写出猜测尺寸。PDF正文未打开，库、Fbasic和TSDB的本次核验也未进行。

原始响应1471字节，SHA-256 fe9ae9a634558d0a9ee8e5a6f349bfc34d2521469c60cf36ec2f543a101d53e0。其后本地validate_response正确拒绝COMPLETE_A_CAPTURE_REQUIRED，原始回执已先保存。独立失败证据复核为PASS_FAILURE_EVIDENCE_AUDIT_NOT_EXPERIMENT_PASS，见data/manifests/ranking_v6_e135_failure_review_r1.json；实际失败清单为ranking_v6_e135_initial_read_failure_r1.json。

已创建本地closed.json并保留初始时钟/原回执。按用户批准的首失败停止和零重试，E135整包到此关闭：只消耗1次A连接，Tessent、自检、ATPG、训练全部为0；不能使用剩余2次连接去补读或自动抬高文件上限。本地仿真worker虽完成14项模拟测试，仍缺手册/时钟/运行规格冻结，未实际运行，也不是物理覆盖证据。

下一方案会针对“命令资料获取”本身收敛，优先避免整份大PDF驻留内存；新的实际访问或工具运行需单独有界授权。旧E127/E133/E134结果和E135失败均保留，下方准备和待执行描述为此前快照。

## 最新状态：已获整包授权，真实入口开发与预审中

用户明确回复“批准 E135 整包”，实际授权为contracts/physical_f_pattern_replay_authorization_e135.json（SHA-256 03f0da9fec34c21433737fe51ee79e69aea7d2e8c7df94e333a78ca9be3d69b3）。旧提案、未授权核心及旧审核回执保留历史，不改成事后已批准。新包装层独立检查本次授权，并复用被冻结的只读核心；不改旧核心AUTH_SHA=None。

源身份/手册读取包装层与单会话F仿真worker正在并行完成。全部本地门禁和独立预审后才开始首次A调用；当前没有新服务器读取或Tessent启动。授权覆盖的后续步骤会自动衔接，不再逐小步等确认。下方“尚未授权”描述的是此前快照。

## 为什么下一步改用这条路径

E134已经把来源缺口定位清楚，不再重复其六文件读取或汇总数字对账。继续核对本地已封存的E128脚本和真实F日志后发现：旧F运行在导出faults.mtfi之后，还执行了导出tester.stil的命令，并正常到达PASS和exit。最后的工具报告记有256个test patterns。

这只是一个有来源的现成向量线索：尚未核验该文件现在是否存在、完整SHA、内容完整性、STIL依赖或实际可重放数量。不能把脚本写过某个文件名当成文件已认证，也不把256直接当成STIL所有setup/flush序列的数量。

## 实验目的与对照

在新F4会话里，只加载冻结的完整71216故障全集及合格baseline DI，不加载任何H导入状态或旧F post状态。使用经过完整身份验证的既有F向量做fault simulation，不调用create_patterns、不重新生成ATPG向量。

这样得到的F DS/合格DI来自实际F向量仿真，不再受H导入标记扩展的解释问题影响。再将其与E134的H已证明18323个故障逐键取并集，以67656为D95整数门槛。它只验证这个既有AES HF:h1，不代表18动作、全部电路、模型泛化或ATPG加速。

对照对象是E133/E134的69062个合并工具状态：可以列出哪些状态获得独立F仿真支持、哪些仍无支持，但不能把新的外部向量仿真耗时记成旧ATPG耗时。即使重放覆盖略低，也不得豁免95%门槛。

## 一次整包的计划

1. 一次有界只读核实确切STIL及F输入身份；从手册内部链接已定位到确切tshell_ref.pdf候选，读取后核对2021.2 stuck-at导入/故障仿真命令，不再泛搜文档树。
2. 完成新执行器、合成测试、独立代码/命令/输入审查与3项Linux进程自检；所有前置条件满足后，自动执行唯一一次F仿真，不再逐小步等确认。
3. 一次有界导出完整前后故障状态、组报告、统计和导入数量记录；独立复算H并F、保存真实成功/失败及SHA，再同步小型记录。

整包范围见contracts/physical_f_pattern_replay_proposal_e135_v1.json：最多3个A连接、1个Tessent会话、单worker、维持512MiB采样阈值，单工具1800秒、整包3600秒、首失败停止、零重试；新目录隔离，不用LSF、不接B/BLIND、不训练，不改历史。整包时钟从第一次新A连接起算，读取后的本地审阅不会重置时钟；本地执行器/测试先尽可能完成，再消耗远端窗口。若STIL缺失、命令/依赖未证或重放失败，不得偷偷退回重新ATPG。F4指四链scan模式，不是只重放四个pattern。

## 当前已完成与未完成

已实现纯本地证据计划编译器src/data/physical_pattern_replay_plan_e135.py及测试，实际从完整E128和封存E134输入生成新线索记录data/manifests/ranking_v6_e135_existing_pattern_lead_r1.json。旧E134来源与结论不改。

科学独立审阅认为：在完整输入身份、干净前态、实际完整仿真、DS/DI规则与独立集合核验均通过时，这条路径能证明保守HF下界，不需要新ATPG。它不是对当前真实覆盖率已经达标的结论。

尚未得到E135整包明确授权，没有新增A访问、没有读STIL正文、没有启动仿真。执行器和确切stuck-at/STIL命令仍未完成验证；当前仅为准备阶段，不称execution-ready。

## 后续本地准备：读取核心和干净前态规范

已新增src/data/physical_replay_source_reader_e135.py及虚拟文件系统测试。核心仅认两个固定路径：旧F的tester.stil只流式计算完整SHA、不导出正文；tshell_ref.pdf最多32MiB且完整校验正文SHA。打开前拒绝特殊文件、链接、错误所有者及超限文件，核对打开前后文件和父目录身份；这仍只是本地可测的核心，没有SSH/controller/payload入口。AUTH_SHA保持None，高层collect在任何I/O前拒绝。

真正的主机、时钟、512MiB进程树资源守卫、固定F依赖身份和一次性调用账本仍要由获授权后的包装层提供，不能把注入tick的模拟测试当成Linux实测。

新增contracts/physical_f_replay_measurement_spec_e135_v1.json将前态要求固定为三份完整快照：导入STIL前、导入后但simulate_patterns前、仿真后。前两份只允许冻结baseline DI集合，DS必须为零，以防读入向量时夹带历史状态或隐式仿真。旧F_basic和完整映射的独立重算确认允许基线为3713个DI（DI.CLK1062、DI.SCAN2120、DI.SEN531），集合SHA为bbbf25513062cb7b6a0eccb23e9dc017529b84ff0080368701829d0fbab8bd74。这是未来验收的旧输入基线，不是新F会话已经通过的实测。

独立复核覆盖12项读取核心、7项计划、3项规范测试，共22项通过；主代理21个相关模块242项回归通过，无跳过/失败/错误。完整测试不是整仓库测试，也不是新工具执行证据。没有新增A连接或授权；仍待此前提出的一次E135整包确认，不重复请求小步骤授权。
