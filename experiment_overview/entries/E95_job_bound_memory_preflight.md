# E95：把资源限制落实到将要执行的同一个LSF作业

承接E94：A的v1控制器存在，但当前SSH账号对常规根没有写权限hint；不能直接套用B端Docker或v2合成门禁。本轮实现作业内只读memory-v1检查，尚未注册或恢复LSF作业。

## 为什么不能只加一个-M就开跑

IBM官方memory-limit文档说明，实际内存限制行为取决于集群配置；参数存在不等于所有进程受内核硬限制。IBM的全版本cgroup说明给出job.<jobid>.<job_res_pid>.<timestamp>作业层级，并说明memory及memory+swap限制写入作业祖先组。我们只将该方言作为待验证的输入格式；不因为文档存在就认定A的9.1.3集群已启用，也不把并行作业说明直接当作本站单进程作业的事实。

- [IBM：cgroup job memory enforcement](https://www.ibm.com/support/pages/parallel-jobs-memory-enforcement-cgroup)
- [IBM：memory limit参数及配置依赖](https://www.ibm.com/docs/da/spectrum-lsf/10.1.0?topic=syntax-memory-limit)

## 检查器职责与停止条件

检查器应在目标作业内读取真实/proc与cgroup文件：LSB_JOBID必须与登记ID匹配、不得数组；当前worker必须在非根memory-v1组，且能绑定精确job ID祖先；该祖先的RAM及RAM+swap限额均为有限值且不超过用户批准上限，use_hierarchy开启。前后读回身份、membership及限额一致。未知方言、缺失memsw、根组、仅soft limit、无限值、错误Job ID、没有批准上限均失败。

memory.memsw是RAM+swap的合计上限；即使与memory.limit相等，也不能描述成“禁用swap”。本组件不写限额、不创建组、不启动子进程，也不单独证明未来Tessent的继承、pids、超时清理或scratch限额。调用方提供的合成字典与mock测试不能冒充实际内核证据。

## 实现复核记录

初版14项合成测试通过后，独立复核仍找出五项缺口：打开的挂载设备未绑定、ACL权限遗漏、producer-safe声明过宽、读取会多探测一个字节、CPU变化测试误改PPID。已一次聚焦修复：绑定major/minor并拒绝覆盖挂载；采用有效身份锚定检查并对访问ACL失败关闭；只报告root/job具名控制项的当时访问结果；读取前预留物理预算；真正改变utime并拒绝start_ticks改变。有限作业祖先下的无限子组仍能正确继承，不误判为无约束。最终16项合成测试和两个Python3.6 AST检查通过，独立结论PASS_SCOPED_MEMORY_PREFLIGHT_IMPLEMENTATION。

这些仅是本地实现证据，没有调用真实collector、注册/恢复LSF或运行Tessent。最终完整回归1,371项中6项跳过、零失败错误，78.537秒；日志SHA为493a082618ebadbdcfe0dcb50fb5353a062b00cef048df4fd7291e5eb5177186。真正执行仍需整体作业入口接线、部署身份与资源批准，并在同一作业内验证；本组件不认证LSF配置文件，不证明全局不可迁移、未来子进程继承或清理完成。完整job executor尚未实现，不将本组件PASS称作整包可以运行。

## 下一整体包与尚需的一次权限决定

计划只注册一个held、非数组、不可自动重试的作业；独立registration review和新鲜pre-resume review通过才恢复。在同一作业内完成资源前置，合格后才按序运行E94四项无pattern接受测试，首错停止，不自动重试。不是18组合采集，更不是训练或BLIND放行。

具体待批准建议为：RAM与RAM+swap分别不超过512MiB、每次Tessent从准备启动到确认清理结束总墙钟10分钟、整作业45分钟、单worker、最多四次Tessent调用。进程数量64与scratch总量128MiB（含TSDB副本）是采样后的终止阈值，可能有采样间超出，不冒充内核pids上限或文件系统quota；stdout+stderr合计16MiB采用严格捕获字节上限。512MiB只是新请求建议，不是把128/256MiB reader上限提高，也不是已获批准的ATPG上限；历史RSS低于该数值不保证新运行能装下，若OOM则停止，不提高限额重跑。内存硬限制、墙钟超时后的kill/reap/无残留验收、捕获输出上限是必须落实的门禁，不将内存限制降级为RSS轮询；不因为缺少额外pids内核quota而增设未经用户要求的基础设施阻塞。

这些数值、部署/注册/恢复/四项工具调用是一个整体权限包；当前仍未获得本包批准，合同保持null/false，不从旧LSF恢复实验的批准推导新Job授权。先完成本地实现和独立审查，再一次性请求整包，不逐个模式请求。
