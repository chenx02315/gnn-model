# E81：把请求、Tessent 配方、报告与预算串起来

日期：2026-10-22。当前完成的是**离线阶段适配原型和合成串联**，不是可运行的 Tessent executor。本轮没有新 SSH、容器、真实报告读取、ATPG 或训练；提议中的新远端目录没有创建。

## 这一步的实际推进

E80 已把请求与实际产出拆开；本轮继续实现两件事：根据请求生成固定 Tcl/参数配方，并把给定报告文本解析回独立观察；同时按预声明任务槽分别扣减 Tessent 与状态翻译的额度。

例如，请求 H 上限为 4，日志必须回显 `ATPG_PATTERN_LIMIT=4`，报告可以实际只生成 2。解析后保留请求 4、实际 2，后者不会反写新特征。H/M/F 的报告字段进一步连接到 E80 的 action/attempt/stage/request-hash 和父前缀谱系，而不是靠数值碰巧相同连接。

## 固定阶段配方

- H 使用已核对的 common Tcl，M/F 使用 incremental Tcl；参数只能是固定请求控制，不能传任意 shell、环境或输出根。
- 输出、日志、隔离 TSDB 和翻译路径都包含 circuit/run/attempt。同一 attempt 名称在不同 run 下不会碰撞。
- 增量阶段显式列出“转换为目标模式原生故障路径”的前置任务，绑定父 attempt/结果 SHA。它不是免费操作，翻译实现与实际产物认证仍未提供。
- `PATTERN_LIMIT`、`TEST_COVERAGE_LIMIT` 和 FULL 三种控制互斥。普通与增量 Tcl 的 MODE/RUN_ID 标记名称不同，解析器分别检查。
- 返回值只是 argv/env/路径配方；没有启动 API，不检查/创建这些目录，不认证库、网表、TSDB 或可执行程序，也不宣称内存/timeout 已受控。

## 报告解析的检查

解析器只接收有大小上限的文本字符串，不打开真实报告文件。检查唯一 pattern 数、DS/DI、FU、整数 TesterCycle 和精确 stage/run/control 标记；TesterCycle 是 ATE cycles，不是 ATPG 时间。

正式统计的 FU 必须等于声明的共同故障全集。M/F 还须提供 pre-ATPG 统计，核对 pre-FU 及已继承 DS+DI 最低值。这个最低值仍是调用方提供的声明，没有被冒充为已认证的故障映射。

独立预审发现并实际修正三处反例：控制回显与请求不同仍被接受；`TesterCycle:123.5` 被截成 123；FU 不符或缺失未被拒绝。新增回归覆盖这些情况，早期 r1/r2 演示保留为中间证据。日志中的 `invalid pin_pathname` 即使没有 ERROR 前缀也会被拒绝。

报告语法是在已知 Tcl/参考 driver 和合成文本上限定的严格子集，**尚未在实际 Tessent 报告方言上完成资格验证**。解析成功不代表真实报告、D95 或安全准入认证。

## 预算扣减原型

`DeclaredTaskBudget` 冻结明确、有限且有顺序的任务槽。每个槽先扣次数与 timeout+cleanup 声明额度，再返回 token；一个槽只能结算一次。M/F 的 Tessent 槽必须依赖同请求的成功翻译槽，两个种类分别计数。同一种类/请求绑定不能靠换 task ID 重复消费。

失败、超时、取消不退款、不重试；未知耗时/清理会阻断后续槽。用完额度记为“预算耗尽/截尾”，不是 D95 不可行；观察到超出声明额度时保留该数并停止，不把实际值截成预算值。

**这只是内存状态原型。** 重新构造对象会重置 RAM，不提供持久额度、崩溃恢复或真实启动许可；token 始终 `launch_authorized=false`。已知结算前缀的区间和也不是完整计划/session 时间或可训练的 ATPG 标签。真实 executor 仍需要持久扣账/ACK、运行时资源守卫和自适应请求的晚绑定。

## 合成串联结果

同一组构造输入演示了 H→M→F 三个配方、三个报告解析、E80 观察连接和五个预算槽：3 个 Tessent 阶段 + 2 个状态翻译。报告字段实际取自解析器输出，不另用手填结果替代。

构造的三个 Tessent 区间各为 5，两个翻译区间各为 4，因此观察器中的 Tessent 合计 15，而任务账本合计 23。这些都是人为整数，不是纳秒实测；示例用于说明不能漏掉翻译费用。预先已知的合成报告/父结果摘要也不能冒充在线自适应请求的预注册。

最终 r3/r4 两份摘要各 23,590 B，逐字节一致，SHA-256 `706ffcff681f4b5bb6e272f369a04a3a18f6479ce8d6b61269dfc955e6103001`。Git 收录小摘要，staging 保留重复对照和早期中间结果。

最终 14 项新测试（适配/解析 8、预算 6）通过，0.008 秒；独立复核另执行同组 14 项通过，0.011 秒，并重新验证三个初审反例均被拒绝。完整相关回归 1,170 项中 1,164 项执行通过、6 项条件跳过，零失败/错误，74.643 秒。完整回归包含旧微型本地子进程测试，不是新的 Tessent/SSH 调用。独立审核逐项核对 6 个来源摘要及离线连接结果，结论为 `PASS_LOCAL_SYNTHETIC_CONNECTION`。

## 下一实质依赖

现在已有请求特征、严格阶段配方/文本观察和任务扣减原型；仍缺真实可执行环境/输入认证、目标原生故障翻译、持久预算准入、真实进程与内存/timeout/输出守卫，以及实际报告方言验证。`-license_wait 5` 不是 whole-attempt timeout，旧训练内存和 E78 的 128 MiB 也不是 Tessent 限额。

下一步应将这些缺项形成一个真实输入/资源白名单与完整有界执行包，而不是再原样训练、扩电路或声称已采到新的 ATPG 数据。

产物：`src/data/prospective_tessent_stage_v1.py`、`src/data/prospective_stage_budget_v1.py`、`scripts/demo_prospective_tessent_stage_e81.py`、`contracts/prospective_tessent_stage_e81_v1.json`，以及 `data/manifests/ranking_v6_e81_*`。
