# v5 单折调用链与冻结后 TRAIN LOFO 回放

本轮接通了代码调用顺序：审批字节完整性 → 已绑定的 package/fold 输入 → fitting-only 回调 → 模型 SHA 写入确认 → 留出特征预测 → 排序封存确认与完整读回 → 有界加载该 TRAIN 留出电路的 outcomes → 固定 top-10 回放。

实现与独立复核按 AgentFleet 分工。拟合回调只得到 fitting prepared data、头部 recipe 和 seed，不得到 held 标签。模型确认、freeze 确认或读回失败时，held reader 不会被调用。held reader 自身在任何路径操作前再次检查 root、输入身份、UID 成员以及依据 scores 重建的完整排名 payload/SHA；之后按固定 manifest/shard SHA 读取 outcomes，拒绝非 SUCCESS、非整数 D95=1、非法 cycles/runtime。runtime 仍是既有 `policy_charged_runtime_s`，没有用 cycles 或 CPU time 替代。

正例只使用临时生成的人工 v3 分片及模拟拟合回调。其中一项集成测试使用新增 RealArtifactStore 实际写入临时的非 Torch fixture bytes、核对模型 raw SHA、持久化并读回 freeze，随后实际读取临时 held shard，而非 mock held reader。它证明调用顺序与本地存储连接正确，不证明真实模型学好了。人工审批 ID、测试中提供的可信 pin 也不是真实用户授权。

**这还不是可执行的正式单次训练 worker。** 新 composition 没有 CLI、Torch 导入、OS 资源隔离或 18 项 scheduler；物理存储是单独的辅助模块，尚未接入真实 tensor worker。返回的 consent、physical limits verified、formal authority 三项均为 false。历史 synthetic worker 及其封存源码没有改动。本轮真实拟合 0、B 调用 0、生产 package 读取 0；不能宣称 ATPG 时间已改善。

RealArtifactStore 限定新训练前缀的直接子目录和四个固定产物名，独占创建、不覆盖、不自动重试。模型 1MiB、122 条日志及日志总量 3MiB、freeze/receipt 各 20KiB，超过上限即拒绝。普通文件检查后同一次有界 buffer 读回核对 SHA；不把无效模型字节当作 Torch checkpoint 证明。文件 fsync 与正常运行时读回不代表断电后的目录项持久性保证；也不是抵御同用户恶意竞态的系统沙箱。Windows 的 symlink/FIFO 能力测试若跳过，必须明确保留 skip，不能宣传 Linux 特殊文件测试已经实际通过。

JSON 不是先无界 dumps 再检查：编码前限制对象深度 64、节点 4096、单容器 1024 项、字符串 2048 字符、整数 1024 bit，拒绝循环、非有限值和非 JSON 类型；随后按累计字节限额编码。冻结 SHA 在有界 payload 编码后计算。重复键以及不到 20KiB、却嵌套 5000 层的损坏 freeze 均有拒绝回归。上述是序列化 scratch 防护，不是运行中 combined-RSS watchdog 已执行的证据。

资源协议保持单 worker、threads=1、AS=8GiB、sampled combined RSS=1GiB、零自动重试。路径检查后再 open 不是同用户恶意竞态下的系统沙箱，仍须由未来隔离 caller 承担此边界。最新设计为 `contracts/ranking_v5_real_caller_design_v3.json`，不改写历史 v1/v2 合同。

后续先将已实现的有界 create-once 存储、固定 tensor 拟合 loop 与当前调用链接成真实单次 worker，再接串行 18-fit launcher，并独立封存完整源码和新鲜环境门禁。新 v5 正式放行仍未成立；不读取生产数据、不启动训练，不进入 BLIND/LSF/Tessent。

最终 focused/full 回归、独立复核和 SHA 以 `data/manifests/ranking_v5_single_fit_composition_validation_20261007.json` 为准。

最终 r4 完整回归：864 项、32 skip、0 failure/error、exit 0，140.740 秒；raw log SHA `ab9360dafdff7f989b096781172841424cbad4209c7fffad8bf36386532da65f`。独立复核为 IMPLEMENTATION_ONLY PASS，不是 Linux 执行或正式训练门禁。此前中间版本和未完成日志保留在 manifest 中，不替代最终结果。
