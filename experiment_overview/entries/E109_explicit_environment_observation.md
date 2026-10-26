# E109：显式环境与失败观察保留

## 为什么要改

例如父进程残留`PATTERN_LIMIT=999`，或者携带`BASH_ENV`、`LD_PRELOAD`，不能让下一次ATPG不知不觉继承这些变量。E108要求清环境，而旧E100/E104的Popen没有显式env参数，所以本轮在新文件中接出环境明确的私有监督原语，旧代码不修改。

## 已实现

`prepare_launch`复用可信E108编译结果，只接受显式提供的六种运行环境变量；stage控制来自冻结请求，HOME/TMPDIR设为专用cwd声明，locale固定为C。搜索路径必须全为绝对规范路径，拒绝空项、当前目录和相对路径。环境最多32KiB；不读取os.environ。

私有`_observe`保留原select/read/采样/已知句柄清理的流程，Popen明确传入env、关闭stdin、分开进程session并合并输出。即使有人重算对象摘要，env=None、loader变量或相对PATH仍不能进入Popen。摘要只证明对象内部一致，不认证许可或真实来源。

本轮没有新增CLI或可放行的controller。私有原语本身不是权限边界，不能交给不可信客户端直接调用；未来controller必须绑定真正的compiler产物、实际runtime profile、资源、独占目录、物理输入/源码和持久扣账/启动意图。

## 失败与费用如何保留

采样、scratch、超时、输出限额、启动异常和清理不确定均保留观察结果，供controller先持久化再停止，不在保存前直接抛掉已有输出。未知spawn只尝试一次，无重试。清理失败不会被写成cleaned=true；未启动或时钟区间不可用时保持null，不补零。

原语只管理传入的输出字节余额，不扣ATPG/翻译次数，因此不会与已有持久账本重复扣账。原始时间是Popen调用前至清理返回的monotonic秒区间，包含wrapper而非仅Tessent PID或create_patterns。准备、复制、翻译、报告解析及回执IO不在这个原子区间里，完整session仍需另记；清理未确认时，它仅是已观察前缀，不能当完整runtime。

观察返回记录只存环境摘要与变量名，不返回license配置值。prepare_launch为了启动而返回的内存对象包含原始env，不能当作可公开回执；真实profile值不得进入公共结果或Git。actual_atpg_runtime_ns仍为null，OS身份、完整费用与环境真实性均未认证。

## 验证范围

13项专项全部使用假的Popen/selector/read/进程对象，没有真实spawn、Tcl或实验服务器操作。144项最终相关回归零跳过、失败、错误。覆盖父环境污染、env=None/重签注入、超时、采样和scratch失败、清理异常、未知spawn、输出截尾、启动前失败及回退时钟。独立复核同组13项和AST3.6通过，结论仅为本地实现/Mock范围。

## 下一步

已核对旧E102封存器：它只接受H→M/F、旧字段集合且要求cleaned=true，不能直接保存本轮新增字段或清理不确定记录。下一接线需要在新文件里适配H/M/F及不确定观察，不能删字段或倒填cleaned来迁就旧接口。当前原语也未返回经OS认证的PID/启动身份，这一部分仍需真实后端补采，不得把known_process_handle布尔值当作身份。

接可信materializer与实际runtime profile、唯一持久启动intent，再把这些观察接入费用和产物回读。真实Linux进程行为、资源采样/清理、实际Tessent环境和报告方言需要未来整体包的物理验证；本轮没有这些证明，也不新增正式采集许可。
