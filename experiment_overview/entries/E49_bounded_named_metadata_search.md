# E49：限定定位完成，仍缺候选receipt与逐源清单

## 本轮结果

一次实际调用exit0，严格回执接受；72个冻结项目根均可访问，实际扫描94个白名单目录、883个名称条目，深度上限剪枝0。没有打开数据文件内容、读归档、计算内容SHA、进入非白名单结果/依赖/checkpoint目录、访问受保护目录或写远端。

只命中两份package manifest：

1. `gnn_model_runtime_v2_98efbd4f_20261002T235119/inputs/runtime_training_package_v2/runtime_training_package_manifest_v2.json`
2. `gnn_model_runtime_v2_input_stage_98efbd4f_20261002/runtime_training_package_v2_r1/runtime_training_package_manifest_v2.json`

前缀均为`/ssd/cjc/`。第二份已由E47实际读回，SHA与历史封存一致；第一份仅名字命中，没有重复打开或认证其内容。receipt_v2.json与source_provenance_v2.tsv在**本次限定范围**内命中0，不宣称整个B端不存在。

stdout SHA：`adecd5732b2f44a17348de1fe5b12f9c08fc11f02995c1043262c8500a11736b`。完整小型名称回执见[scoped inventory](../../data/manifests/ranking_v6_e49_inventory_20261017_r1.json)。本地0.471秒是元数据操作耗时，不是ATPG耗时。

## 覆盖范围和测试

72个根来自E44实际盘点，不是推测；只沿data/manifests/inputs/input/package/artifacts或正式候选/package/staging前缀目录名下探，最多三层。上限512个目录、每目录2048项、总20000项、64KiB每流、1GiB/单worker/20秒CPU/120秒超时、零自动重试。逐组件FD相对nofollow；遇到目录更换、重复inode、超界等均关闭失败，不把异常解释成缺失或损坏。

实现代理负责四文件，主代理核对后由独立复核代理阅读全实现、核对72根与E44完全相同、重跑9项合成测试。主代理相关完整回归609项，603执行、6条件跳过、0失败/错误，63.395秒。全部门禁通过才实际执行；测试计数彼此重叠，不叠加成不同测试数量。

## 为什么现在仍不能训练

E47证明正式package绑定candidate receipt的原字节SHA为：

`48c164e99e653c1d00dbf8e7655447e2ffc09c9519c63b7191dff9a151b7456d`

但候选receipt内容没有恢复，因而还不知道它绑定的source_provenance SHA；24份正式源快照也不能认证。配置相同、package一致或日志已匹配，都不能代替这一来源链，也不能解决候选全集/执行前冻结及完整计费问题。

本地原始候选目录此前访问被拒，尚未修改ACL、接管所有权或再次探测。B端本次固定白名单里没有找到另外两份文件；没有依据继续盲目扫整个SSD、读大归档或进入保护目录。当前需要**可读的原始元数据副本、来源端白名单导出，或一个明确的备份位置**，不是再给一次笼统授权。

已列出[精确元数据请求](../../data/manifests/ranking_v6_e49_missing_metadata_request_20261017_r1.json)：包含原始Windows路径、要选的字段、已知receipt SHA、24个TRAIN来源行约束和不可导出的值。无需用户凭记忆找实验目录；管理员/来源端只须按请求提供两份有哈希绑定的投影。不上传质量表、真实runtime、checkpoint或整套实验包。

收到可验证元数据后，在现有恢复范围内继续SHA链→正式版本比较→独立复核→后续费用/全集门禁；不因本阶段封存就自动解封训练。
