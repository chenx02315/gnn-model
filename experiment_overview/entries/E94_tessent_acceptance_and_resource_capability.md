# E94：把实际接受测试与资源缺口收敛为一个整体包

E93已经证明固定真实输入的四条翻译可以计算成功。下一步不是重训，而是确认Tessent是否读得进这些状态，以及真实进程是否能在规定内存和时间范围内安全退出。

## 本轮实现

新增纯配方编译器，固定aes_core/spi的H→M/F四项。复用E85实际库正文SHA及六棵TSDB树SHA，不把已有证据当缺失；编译入口只接受E85/E93原始JSON字节，并在解析前验证精确SHA。初版允许调用方提供dict+旧SHA，主端发现其无法认证字节，已聚焦修正为bytes-only；伪改输出SHA、修改库SHA、传dict均有拒绝测试。

四份固定Tcl只初始化对应设计/scan mode、进入analysis、先读完整common BASIC，再merge翻译状态并重新分类，statistics丢弃到/dev/null，输出固定接受标记后退出。不含create_patterns/write_faults/write_patterns，不生成pattern，不写故障报告。Tessent自身仍可能写隐式scratch，因此真正运行必须在全新专属目录、复制并认证TSDB后进行；原始树不能作为可写输出。当前配方不创建这些目录，也不执行Tessent。

资源读器仅准备一次只读A能力观察：固定读取/proc/self/cgroup、/proc/self/mountinfo、/proc/cgroups、/proc/self/limits；对四个常规cgroup根做元数据和write_access_hint检查。单文件128KiB、总512KiB、输出16KiB，helper地址空间上限128MiB、CPU上限5秒，SSH60秒、零重试。继承限制若更低则实际更低；这不是Tessent预算。无目录扫描、不输出原始proc正文或group路径，不安装限制。

## 资源审查结论

既有证据没有真实Tessent内存上限数值：合同字段仍为null；历史RSS只属于观察。A此前cgroup版本hint为1，合成v2门禁和B的128MiB验证不能直接当A的ATPG守卫。LSF可调度也不证明hard-memory enforcement。此次partial观察仅判断controller是否enabled、mount是否可见及常规根写权限hint；即使通过也不能证明可创建子组或未来LSF作业内限制生效。

后续真实整体四项包必须补：实际内存/超时/清理/进程数/输出上限、引擎版本、隔离scratch与TSDB副本，以及在同一作业内绑定Job ID和资源生效回执。不能把soft limit、MemAvailable、RLIMIT_RSS或reader上限当整棵Tessent进程树硬限制。当前未运行新Tessent、ATPG或训练；BLIND不开放。

## 本地验证及边界

23项组合测试通过。资源测试最初有两个Windows测试夹具问题（O_NOFOLLOW未模拟、stdout.write被误归为文件写），已仅修正夹具并完整复跑；生产读取范围未因此放宽。独立预审又发现两个实质缺口：controller漏验能力主体及额外字段，Tcl初始化漏了真实参考的四条设置。分别聚焦补齐exact nested schema及反例、clock/split/random/F-fill顺序分支后，独立复审两部分均PASS；首审问题另留findings记录。最终回归1,355项中6项跳过、零失败错误，80.172秒。真实接受仍未执行，四项recipe不是接受结果，更不是D95或模型收益。

## 实际能力观察与下一条路径

预审与完整回归通过后，已实际一次只读A观察：四proc文件共11,901B，stdout 5,367B、stderr 0、退出0，无超时/溢出/重试。memory/freezer/pids控制器均enabled，三个常规v1挂载可见且mount不是只读；但uid1047对/sys/fs/cgroup及memory/freezer/pids根的write_access_hint全为false，目录均root所有、0755。本次没有尝试写入，也没有扫描委派子组，因此不能推断全机不存在其他可用子组；只能确认现有证据不足以直接创建本实验专属组。

选择下一路径为受控LSF整体包：在同一作业内先绑定Job ID、检查真实kernel限制和清理能力，再允许四项接受测试；不能只凭bsub的rusage[mem]预留或-M参数存在即宣称硬限制生效。若前置不足，必须在Tessent启动前退出。当前没有注册、恢复LSF作业，没有部署scratch，也没有Tessent调用。实际硬内存/超时仍null，下一步准备整体包而非重读相同proc或原样尝试Tessent。
