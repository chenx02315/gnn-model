# E104：剩余三项低内存验证包

## 新授权与目的

用户答复“授权上述低内存整包，复核通过后自动执行”，question `call_45193f6ef9fb496ab9bfdb3d7638aee4`。这是新的一版、最多3次启动的整体包，不使用上一两版授权的余额。真实授权文件 `contracts/direct_tessent_low_memory_authorization_e104_20261025.json`，SHA `b4251f39a899ead25e39f09c154446bf15530d3dbb38cf05d4e3c786a0c3ea75`。

只运行AES H→F、SPI H→M/H→F。保留E103已通过的AES H→M成功回执（2850B/SHA `a205ee9b0fc095b0268f9808f4aad7263e28f124ed22fd1b22645318e45fcc47`），不重跑该项。新旧配置不同，不将跨配置记录冒充一次同配置四项实验。

## 唯一实验变量

从每个保留项的固定Tcl中，恰好删除一次 `add_processors localhost:1`。纯变换核验原plan自洽hash与完整四项roster，再选择三项并重算Tcl/recipe SHA；其余逐项字段、库、设计、故障映射、翻译状态、TSDB树输入pins均不变。变换不修改原plan。原hash校验只是自洽，不是独立认证；实际运行继续依赖冻结compiler在内部生成plan及完整源码绑定。

这只是取消显式额外处理能力请求，不保证少一个OS进程或一定减少峰值。保持512MiB RSS+swap采样停止阈值、单worker、600秒/项、2700秒/session、16MiB输出、128MiB命名scratch采样、清理和逐项告警规则。采样不是内核硬保证；不使用LSF，不恢复内核硬cap，不做正式ATPG/训练/BLIND，首失败停止、零重试。

## 准备验证

新27项测试加既有125项，共152项本地测试退出0。覆盖只删除精确命令、所有其他row字段/输入pins不变、原plan不变、缺失/重复/别名命令拒绝、recipe重新封存、原生materializer初始化得到三项且尚无IO、3/3聚合、不重跑M、旧授权拒绝、真实bootstrap前缀加载14份模块但不执行工具等。

待审精确包193476B，SHA `8b0164880923d738d3305532ec2d68a2d21c9719521e51c5af40441cf70296e4`。新root `/temp/jiangchuanc/multimode_ate_direct_e104_20261025_r1`，本地phase固定且exclusive，未知结果不重传。

新鲜只读A检查：host/uid匹配、新root不存在、E103 summary及AES M成功回执完整SHA匹配，先前cases均cleaned、Tessent可执行。原始小回执在 `v6_e104_direct_prelaunch_20261025_r1`。这不是另行OS终止认证。

当前待最终独立精确包复核，尚未新增实际Tessent启动。成功也只支持固定状态导入的运行接受，不自动证明D95、故障语义或训练收益。

最终独立复核已返回可执行限定PASS：独立152项相关测试退出0，14份源码、实际新授权、E85/E93、前件summary及缓存M成功回执一致，AST3.6通过。controller SHA `61dda62df23fa5033c9450e64ffd167288e46fafb9d6e5b2f44f01421c39be87`；executor SHA `6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190`。

已调用一次固定controller execute，精确包同上，本地会话36479待观察；不重传，不预填实际启动次数或通过结果。

## 实际结果（覆盖上述等待观察状态）

会话36479已终止，controller与远端均退出0，无超时/溢出/stderr。新包3次启动、零重试，3/3窄范围接受通过：

| 项目 | 返回/失败/清理 | 聚合RSS+swap采样峰值 | 接受执行到回执前的时间 |
|---|---|---:|---:|
| AES H→F | rc0 / None / true | 394252288B，375.99MiB | 13.459秒 |
| SPI H→M | rc0 / None / true | 376700928B，359.25MiB | 8.751秒 |
| SPI H→F | rc0 / None / true | 350707712B，334.46MiB | 8.186秒 |

三项均未触发512MiB采样停止阈值。以上内存不是独占物理内存或硬上限证明；时间包含物化/setup/检查，不是正式ATPG生成wall time，不进入训练runtime标签。不能仅凭一次前后尝试宣称移除命令已因果证明降低内存。

已进行19个固定文件的有界只读回读：summary、synthetic gate、repair binding、物化header、3result、3observation、3Tcl、3log、3物化receipt。响应75680B，SHA `d1fab60b05890aa3e7d4cffb031dd360a2672fc08ec9e2f500138c9ed7310ae4`，原始小证据留在本地 `v6_e104_result_readback_20261025_r1`，未向Git放整套商业工具日志。summary7870B/SHA `842c8688ac493e4d1a9de90de3a0aea63322b9583f61511dedc1d6753bcf6ce3` 原样进入 `data/manifests/ranking_v6_e104_execution_response_20261025_r1.json`；19文件大小/SHA索引另存 `ranking_v6_e104_artifact_index_20261025_r1.json`。

三份实际Tcl和日志均没有显式add_processors；每份日志都有两条精确read_faults、唯一尾标记及exit，监督器无失败且清理成功。summary初步独立复核PASS，完整19文件回读仍在独立核对。D95/fault_semantics_verified依然false，不夸大为质量验证或告警无害。

完整19文件最终独立复核已返回限定结果PASS：大小/SHA全部一致，summary与执行响应逐字段一致；三份Tcl与冻结源码变换逐字节相同，完整日志重评均通过，物化header/binding和receipts对应recipe SHA `68bd3c07d71fad665c44ec8d38ab81fd391a9b903f65106b32f81234a7b8491b`，Linux三项synthetic gate也通过。物化receipt的“未执行”是执行前快照，不与后续通过冲突。可封存为本包三项导入运行接受通过，不升级为其他范围通过。

## 回到论文主线的下一门槛

此前卡住的四条工具导入路径现已有接受结果：旧配置E103 AES H→M，加新配置E104余三项；这是跨配置覆盖，不是同配置四项批次，也不是模型实验已经成功。

已重新读取E84总合同、E80请求接口和E98资格盘点：下一节点是认证运行前请求、同一F完成策略的结果和完整费用。E84阶段2的training_budget仍null、training_ready=false；六家族资格尚未被当前合同认证，不能把入口验证记录当新的训练数据。先冻结请求/结果/成本采集与共同故障分母下D95核验口径，再安排有界真实ATPG采集；当前新授权明确不开放正式ATPG、训练或BLIND，因此不自动启动这些操作。
