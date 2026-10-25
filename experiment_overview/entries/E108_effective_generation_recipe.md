# E108：真实执行器的离线生成配方

## 本轮推进

前一轮证明组件能连接，本轮开始准备真正执行时要用的字节与路径，而不是增加第二套runner。保留E81/E86冻结意图，新建独立execution envelope，把实际Tcl摘要、固定launcher、argv/env、结果位置和父翻译声明连接到原binding。没有创建A端目录、SSH、Tessent进程或训练。

## 源码不是重新猜出的Tcl

限定只读两份已有本地源码：`../phase4_bootstrap/stage_mapped_common_atpg_no_tsdb_v2.tcl`与`stage_mapped_incremental_atpg_no_tsdb_v3.tcl`，分别3096/4134字节，SHA与E68/E70/E81记录一致。将原样副本纳入版本化templates，历史原文件不修改。Git为四个新增源码/测试文件设置精确字节保留规则，不改变全局行尾。

每份原文精确删除一次`add_processors localhost:1`整行，除此之外不改；派生源码分别3069/4107字节，SHA分别为`9b78e5c874fd2d4eb8987ac534d9c5414606184f8aea0012971130891ad1d92f`及`1a9d4435551919b34c5beb4a142120df0322fcf209ebd493cfe2e70d92e42967`。这延续E104的变更方向，但E104只实跑了导入接受，不证明新生成流程的峰值内存。

两脚本仍各包含一次`create_patterns`，以及统计、pattern、STIL和MTFI导出。它们只是受控的源码字节，本模块没有执行它们的接口。

## 绑定内容

- 仅接受冻结E84中精确的Tessent槽位、动作、模式、请求和父/翻译task ID；翻译槽拒绝当成Tessent调用。
- E86键集、bool flags和control类型严格核对；按H/增量及槽位检查前序/父/翻译摘要的条件必填64hex。原样携带lineage声明，但不认证这些摘要的真实性，也不把翻译小引用的摘要当作原生MTFI文件摘要。
- 旧base recipe保持原摘要，不把“意图中的旧Tcl”改称“实际执行的新Tcl”。新envelope同时记录两者摘要及明确的单行变换。
- 新根固定为`/temp/jiangchuanc/multimode_ate_prospective_e108_20261025_r1`，由旧配方前缀精确迁移所有绝对路径；相对PHASE保持一致，Tcl实际输出目录与envelope相同。
- launcher使用已记录的绝对路径和期望摘要，不依赖PATH解析；后续真实执行仍须新鲜核验文件身份。
- H/M仅有PATTERN_LIMIT，F为冻结的coverage95；输出七类报告路径和增量pre-statistics路径明确。未来环境必须清空继承变量再设置，不把该要求冒充已经执行。

## 验证与仍缺的部分

8项专项及131项最终相关组合回归通过，零跳过/失败/错误。48个阶段在人工父输出/翻译回执下逐一编译，冻结计划与binding不变。反例覆盖原文改动、派生脚本被追加命令、摘要被重新签但任务/配方不同、bool槽位/control、缺失或错误lineage摘要、非E86键集/flags、错误父/翻译ID和翻译冒充Tessent。独立复核指出lineage格式与control类型两处缺口后已聚焦修复。首次一个反例夹具误选不同H请求，导致在构造阶段报错，已改为相同H请求的不同动作后完整复跑；不是一次Tessent失败或远端重试。

仍未完成真实materializer接线、物理输入/二进制身份核验、采样/超时/清理监督、持久运行账本与实际报告方言/大STIL回读。只读核对确认旧E100/E104复用的supervise在Popen时没有显式env参数，会继承环境，不能直接把它当成已满足新环境规则；应在新版本处理，旧代码不修改。原Tcl输出的统计与patterns报告如何提供真实pattern计数也需核验，不能只拿合成文本声称方言通过。`resource_budget=null`、`execution_authorized=false`，既没有把E105合成backend变为真后端，也不沿用已经用完的E104三启动许可。

后续继续复用E104的已实跑监督和输入准备，接到这一精确配方及完整费用记录。正式48次Tessent＋30次翻译仍需一个明确的整体资源/执行许可，不在本轮启动。
