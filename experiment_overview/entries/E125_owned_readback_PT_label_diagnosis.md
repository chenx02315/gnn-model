# E125：本次自有产物回读与统计类别标签定位

## 结论

这次停止不是Tessent命名错误复发，也不是内存越限。首个AES H的进程观察为returncode=0、failure=null、cleaned=true；其后解析器拒绝统计表第13行 `PT (posdet_testable) 64`，因为旧E115代码固定要求PT标签为`possibly_testable`。两种字符串不同，因此触发CLASS_LABEL_OR_DUPLICATE。并非重复类别，不能删除该行或把64个PT故障算作已检出。

## 实际回读

原E124窗口内，E125独立16项测试、AST3.6和15模块惰性装载复核通过后，一次只读回读固定24份自有文件，24/24成功。没有Tessent/子进程启动、显式文件写入、额外历史报告、B端或训练操作。

原始body共75270B，回读worker+子进程采样峰值13107200B，单调时钟2407945.166255342至2407945.561140398，约0.395秒。回读响应SHA-256 b5765db14b6f9ae3ab0a0d19791723badc693e113d6c1af4ed0817c72a2fdbac；首H统计2681B，SHA-256 6a2c43dda14dc5c383ef50312b1af4682908db9649b1a5a13a29016e0094903d。完整原始数据仅留staging，Git保留小型索引与摘要。

本地已逐份重新解码核对全部24份size/SHA。进程观察预期stdout、实际stdout、独立ACK及Tessent日志一致：24566B，SHA-256 9dbf49ab6f65bead2d2b9ca63142a49207aba20b313c1a32ecd2c65a56ecf096。最终独立产物复核单独记录，不能以本地核对代替独立结论。

最终独立产物复核已PASS：全部24份body重算一致，observation→stdout→ACK→spawn/preparation和远端summary→本地原summary一致，两个Tcl与E123修复字节一致；tool token、H模式、语义UID和尾部PASS marker唯一正确。独立确认create_patterns确实执行且按1-pattern限制正常退出；这不把整包失败改成接受通过。

## 资源与结果边界

首H监督区间约11.875821秒，范围为Popen前至清理返回，含身份回调，不是ATPG内核耗时。进程树采样峰值393453568B（375.2265625MiB），未达到512MiB采样停止阈值；不声称硬内存隔离或完整峰值保证。

报告顶层类别总和71216与共同故障分母一致；DS14610+DI3713=18323，PT64单独保留。H阶段仅报告1条生成pattern；这不是完整HF/HMF动作的最终D95结果。整包仍0任务提交/0翻译，不能释放训练数据或声称模型收益。

## 接下来

在新E126纯解析器中精确支持本次已见的`posdet_testable`标签，保留重复/未知类/分区/截断校验，验证PT不进入DS/DI检出计数，保留原raw SHA；旧E115和E124源码不改。完成本地回归与独立复核不等于授权再次采集。本包一个版本已用完，不原样重跑、不得借剩余启动次数恢复。
