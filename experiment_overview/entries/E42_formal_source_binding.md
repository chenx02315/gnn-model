# E42：正式版本的认证链已定位，读取被文件权限阻断

## 现在卡在哪里

不是重新找ATPG日志：E41-r2的16个声明已各找到一条严格匹配记录，本次没有重跑。现在要确认**正式候选集合究竟用了哪个源快照**，否则同一个candidate在v1/v2中都存在时，不能直接选择一版或把两版运行费用混在一起。

已从旧生成代码和小型封存记录定位到这条来源链：

`打包manifest的candidate_receipt哈希 → 候选receipt的source_provenance哈希 → 每份原测量文件的source_sha256`

关键区别：`source_sha256`绑定原文件，`normalized_sha256`绑定补candidate等处理后的副本，不能互换。取得可信的原文件哈希后，才可以与E38已有的版本限定文件哈希比较；现在不再靠配置或路径猜版本。

## 已核实与尚未核实

| 事项 | 真实状态 |
| --- | --- |
| 打包代码保存候选receipt哈希 | 源码已确认 |
| 候选receipt保存逐源文件清单哈希 | 源码已确认 |
| 仓库旧封存记录声明package manifest哈希 | 已找到，属于历史声明，不是本次文件读回 |
| 本地实际package manifest | 一次精确属性读取返回Access denied，内容未打开 |
| 正式候选最终采用的Phase2版本 | 尚未认证 |
| 完整搜索费用、全集及执行前冻结 | 尚未认证，训练不放行 |

操作系统随后还输出“找不到”消息，但前面的访问拒绝意味着不能据此判定文件不存在。未重试该目标、未接管所有权、未改ACL或递归解封目录。E37已记录候选目录原DACL不可读取，安全备份/最小增量修改前提仍未满足；一句新的“允许”并不能直接改变这些OS读取条件。

## 最小需要补什么，不要解封整套数据

基础目录：`C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928`。由有权限的来源端读取器或管理员提供**元数据投影**，不要求用户记住实验目录：

1. `runtime_training_package_v2_r1/runtime_training_package_manifest_v2.json`：只取schema及`source_sha256`中的candidate_receipt、candidate_space、normalized_measurements，附完整文件SHA。已有历史manifest声明SHA为`66c6776c033c87c2b41fa6cdeb05852e650eb1fe5173600fae2f0d2a8907eafc`。
2. `formal_candidate_space_v2_r1/receipt_v2.json`：只取schema及`sha256`中的source_provenance、candidate_space、normalized_measurements，完整文件SHA必须与第1步绑定一致。
3. `formal_candidate_space_v2_r1/source_provenance_v2.tsv`：只导出六TRAIN电路×四stage的24行，保留原逻辑行号和六个来源字段，完整文件SHA必须与第2步绑定一致。导出器本身也需要来源/操作回执，不能只手抄哈希文本后当作独立认证。

注意：package manifest本身包含oracle等结果派生值，**不能因为文件名叫manifest就整份解封**。这次只需要选定哈希字段；不要导出质量表、outcomes、validation/BLIND行、真实wall数值、checkpoint或完整结果目录。字段和路径见[小型读取请求/观察回执](../../data/manifests/ranking_v6_e42_source_binding_20261017_r1.json)。

拿到可验证投影后，下一整步是校验哈希链 → 比较24份原源哈希与已有E38版本 → 保留0/1/多版本匹配 → 独立复核 → 更新费用连接计划。不会因版本相符就自动认证执行前全集、完整搜索调用或启动训练。

## 本轮范围和证据边界

只核对仓库代码、历史小型元数据声明和一次本地精确属性访问。没有读取受拒manifest内容、重读E38–E41实际输入或访问A/B主机；没有执行builder、mapper、ATPG或训练，没有修改历史费用。

最初一次仓库内容搜索范围过宽，输出被工具截断且命中历史结果摘要；未用这些命中作新版本认证或实验结论，后续已改为指定小文件和字段。此轮不产生Notebook或数据分析实验：可复查证据是代码位置、已有封存SHA及本次明确的访问状态，不用额外合成测试数冒充来源进展。

当前高风险缺口是来源认证，不是新增电路数量。需要可读且有来源回执的上述元数据投影，或用户指定一个获准、可读的来源端。不能为继续实验而绕过拒绝或伪造绑定。

静态来源链与发布范围已通过独立复核：三份代码/旧封存文件SHA、字段关系、历史声明哈希和链接一致；独立复核没有重复探测受拒目标，所以不称操作系统状态已由第二人读回。没有新增数据实验或重复累计旧测试数量。

可选恢复方式：若用户明确允许新增一小范围远端读取，可到既有B端`/ssd/cjc`内有界定位上述三类元数据，排除受保护的`/ssd/cjc/multimode_ate_gnn_v1`，只导出白名单字段；不读结果/质量/checkpoint、不写远端、不训练。当前没有执行这条路径，也未证实B端一定保留可用副本；它需要明确的新增远端范围授权，而非把上一轮“不增加远端读取”的修复授权自动延长。
