# E121真实失败与E122证据回读

## 结论

这是执行器接线错误，不是资源不够：语义任务编号 aes_core:HF:h1:H 被直接拼到 Tessent design identifier。工具拒绝冒号，common.tcl 第25行 set_context 就终止，尚未读取 cell library、读取电路或调用 create_patterns。

此前251项本地回归与独立入口复核都不等于真实工具接受；本次真实验证暴露了合成测试没覆盖的厂商标识符约束。不能把进程“启动了”当成 ATPG 已完成。

## 实际发生了什么

1. 环境模块捕获成功，运行值仅在A端内存传递，未输出到Git或日志。
2. 三项真实Linux进程自检完成。success为rc0及精确输出；timeout与setsid_child按预期CASE_TIMEOUT/rc-9，均cleaned=true。setsid readiness记录中的PID、进程组和会话一致。
3. 初始化共享输入及首阶段TSDB克隆已完成，持久intent先于准备，Tessent额度扣1不退还。
4. 首个Tessent进程启动，真实PID56700、worker56312；观察回调身份持久化成功。
5. 工具在set_context返回真实Error。其明确要求：设计标识符首尾必须为字母或数字，中间仅允许字母、数字、下划线，不能出现双下划线。
6. 退出码1，supervisor failure字段null，cleaned=true、cleanup_error=null；wrapper区间8.275002725888044秒，worker+子进程RSS+swap采样峰值251,461,632B，即239.8125MiB，低于512MiB阈值。
7. 按首失败停止，未翻译、未衔接后续电路。计数为Tessent debit1、translation0、committed_tasks0；没有可放行的ATPG runtime/quality标签。

Controller执行区间约13.994秒，不等于ATPG搜索耗时。原package_elapsed约31,728秒包含从E112准备开始的行政/实现等待，只是授权预算窗口，禁止作为模型搜索成本。失败wrapper成本前缀保留，不能补成成功耗时、挑最快成功或抹掉失败。

## 证据封存

- E121本地原始响应1985B，SHA-256：05ec97c35b0c7558267f45cccaca2b0e68664c5fe5b974f1ba284c61d25122cd。
- E122只读回包45,614B，SHA-256：170eaaae6c14c32a0821ce2d3d47e86aad4f343ef4811c49d4bc6e40c6affb31。
- 23/23固定新产物完整size/SHA核对通过。两份真实日志均3008B，SHA相同且与观察stdout_expected及独立ACK对应；准备、spawn身份、controller summary和外层响应逐项联接一致。
- 原始文件保留本地runtime_training_staging_20260928下的v6_e121_generation_20261026_r1及v6_e122_failure_readback_20261026_r1。A端失败目录和sidecar不删除、不覆盖。
- 回读不启动工具，不访问B、BLIND、LSF或额外历史报告。历史报告总额度仍为8/8。

## 下一步与权限

E123仅在Tcl内部为受限制的工具标识符派生可追溯token，保留原任务身份及输出联接。计划在新包中显式冻结新Tcl、工具token映射及相应echo规则，并完整复核全部48项工具名称。

当前“一新版本、首失败停、零自动重试”的真实执行权限已经用完，不能靠还剩47次Tessent额度就继续。新的完整采集包需要新的明确答复；拟保持单worker、512MiB/8GiB采样、3自检、固定18动作/48生成+30翻译，不打开B/LSF/训练/BLIND。新包若获准，独立计时必须被新授权明确允许，旧窗口与证据不重置。
