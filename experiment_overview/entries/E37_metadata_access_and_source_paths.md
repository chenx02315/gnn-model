# E37：权限诊断与真实来源路径恢复

## 结论

本轮不是等待用户再次同意。用户已经明确授权六TRAIN配置、原行序、哈希和来源回执的限定读取，必要时可设置指定元数据只读权限。实际障碍是Windows连目标权限描述也拒绝返回：无法确认文件存在、备份原DACL或制定可恢复的最小修改，因此没有改ACL、接管所有权或递归放权。

随后换用**已授权的计时元数据定位来源，再独立复核只读路径方案**。A端实际执行一次固定32路径的lstat探测，32/32均存在，都是普通单链接、大小不超过8MiB的文件。覆盖六TRAIN、八个版本根，stat大小合计2,450,482字节。仅确认路径元数据，没有打开测量内容、计算源表哈希或导出候选行，更没有训练。

## 做了什么

1. 对两个指定元数据路径尝试获取属性和ACL，对父目录尝试获取ACL，均被拒绝。没有读取质量目录内容；无法读取原DACL时不盲改。
2. 只查看既有SSH配置的主机/用户名信息，不读私钥和凭据。复用已使用的A端主机`vnc.buptic.top`，没有连接B端。
3. 串行核验六份既有TRAIN manifest的固定SHA，共20,761,204字节，只提取电路、stage/mode和source_log_path元数据。不打开记录中的日志路径，不输出状态、费用或质量值。
4. 原路径均为相对路径；与已存在的2,506字节remediation bindings配置声明组合，恢复精确的coverage根。bindings SHA为`3d1b8f6b2a9b1162dcf99c046dbed6573145d404ff5a3258eb1b0a46f3c7e187`。这是提供元数据的组合，不是formal builder输入来源认证。
5. 冻结八根32文件路径及lstat-only代码；11项合成测试和独立复核通过后，执行一次A端探测，child exit=0，零自动重试，无远端任务文件写入。

## 找回的来源版本

| TRAIN | coverage版本 | 文件数 |
| --- | --- | ---: |
| aes_core | Phase4 / 10_coverage95_phase4_v2 | 4 |
| s13207 | Phase3 / 10_coverage95_v3_merge_reclassify | 4 |
| s15850 | Phase3 / 10_coverage95_v3_merge_reclassify | 4 |
| s35932 | Phase2 / 10_coverage95_v1 与 10_coverage95_v2_merge_reclassify | 8 |
| s38417 | Phase2 / 10_coverage95_v1 与 10_coverage95_v2_merge_reclassify | 8 |
| spi | Phase4 / 10_coverage95_phase4_v2 | 4 |

每根四类文件为HF粗网格、HMF粗网格、HF整数细化、HMF整数细化。完整固定绝对路径保存在[小型stat回执](../../data/manifests/ranking_v6_e37_path_stat_20261016_r1.json)，不再要求用户记忆。

s38417的计时路径还记录了失败repeatability和cascade日志scope；本次没有打开这些日志，不能据本次32路径探测宣称已覆盖全部历史生成、失败或搜索记录。

**重要：六个电路不等于六份唯一版本。** 不能挑一个Phase2版本、合并同名source UID，或把32文件硬缩成E36的24文件输入；必须保留coverage版本并另证旧正式清单采用了什么来源。

## 验证与证据边界

实际stdout 11,997字节，SHA `82ef18e36816911a4e60f1f54287804eea8761b80d9a4ac0290e3ef6c0ff0f9a`；stderr为空，无超时或输出截断。[传输回执](../../data/manifests/ranking_v6_e37_transport_20261016_r1.json)确认固定调用通过。

Linux实际设置地址空间上限1GiB、CPU软上限20秒、单worker；没有提高既有内存上限。未测峰值内存，不能拿上限冒充峰值。每路stdout/stderr上限64KiB，传输超时120秒，实际本地elapsed 1.165秒；此数只是路径查询耗时，不是ATPG runtime。

完整相关回归484项，其中479实际执行通过、5条件跳过，0失败/错误，57.818秒。独立重复测试不累计。控制台的模拟失败transport JSON属于测试fixture，不是另一次真实远端调用。

lstat是可信主机上的有界观察，不认证内容、哈希、历史冻结时间、formal builder根或抗并发替换身份；PASS_PATH_STAT_ONLY不能升级为候选全集或训练PASS。

## 连续推进的下一节点

现有授权内继续准备E38：仅投影candidate/H/M、原逻辑行号和SHA，保留八根32文件版本。原表字节必须用于完整SHA与TSV结构扫描，不能声称“没有读文件字节”；非白名单字段不解码、不作为质量值解析、不保留原表、不按PASS/eligible筛选。实现、异常方言测试和新的独立门禁通过后才允许实际读取；E37的stat通过不能替代该门禁。

后续仍须区分历史观察清单、全部生成候选、结果前冻结与真实调用计费。当前无质量连接、BLIND、模型、optimizer、训练或LSF/Tessent。
