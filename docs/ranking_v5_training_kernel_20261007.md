# v5 训练接线：已实现，真实执行仍封闭

## 本节点做了什么

新增独立 `ranking_v5_training_kernel.py`，不修改 r4 的 trainer、release 或历史结果。沿用 7 列特征、拟合侧归一化、CandidateMLP、三个既定 seed、Adam 参数和 120 epochs；优化目标唯一改为 first-hit top-10 head loss。损失定义仍使用已封存的原 v5 objective，没有改动其 SHA。

训练接线只接收专用 synthetic scope，不接受旧 v4 scope/real scope。没有 CLI、远端操作、文件写入、held 推理、freeze 或正式 release 入口。scope 名称不是数据来源证明：后续执行者必须另行证明 synthetic fixture 来源，不能改个 scope 就放入真实数据。

拟合前、每轮更新后和最终各输出日志，总计 122 条。日志仅包含拟合家族汇总：首正例排名、前排负例数、top-10 命中、cycle regret、边界间隔、head loss，以及完整配对的旧 pair loss 诊断参考。旧 pair loss 不参与反向传播。拒绝漏配对/重复配对、额外 held 标签、非法整数 cycles、错误日志阶段和非有限差值。日志不导出动作 UID、分数向量或标签向量。

## 验证边界

本地 mock-loop 验证了 120 次优化步、120 次 head-loss 调用、固定 optimizer 参数、拟合矩阵唯一输入、122 条日志顺序和一致 request digest。纯函数测试验证 fitting join、held 特征不影响拟合归一化/recipe 和日志稳定性。

这不是实际 PyTorch 训练，也不是数值训练确定性证明。上一个 B 合成梯度门禁只验证 objective，不覆盖新 kernel 的优化循环。已有 CUDA OOM warning 仍未消解。本节点不启动新真实 fit，不提高内存限制，不增加 worker 或重试。

## 连续后续节点

1. 对新 kernel、旧 objective 门禁及 CUDA warning 进行独立只读复核；没有回执不能标记 PASS。
2. 源码精确绑定后，建立新的小型 synthetic integration gate：实际 CPU optimizer、122 条日志、重复计算确定性、受限资源、零重试；不复用旧 objective gate 的 PASS。
3. 实现独立 v5 real-release/freeze/receipt 门禁；held 标签仍不得进入 fit/epoch 选择。冻结模型和排名后才可按合同读取 TRAIN LOFO held 结果。
4. 门禁和独立复核全部通过，再取得明确的新 18-fit 放行并检查新隔离目录、锁定依赖、单 worker、现有资源上限和零重试。
5. 先比较困难家族 fitting 是否改善，再比较 TRAIN LOFO held；拟合改善但 held 不改善才继续上下文实验。没有共同命中时不能声称 ATPG 加速，不增加图/成本变量或大批电路来混淆本次对照。

此清单是继续路径，不是上述节点的完成或执行许可。BLIND、LSF/Tessent、受保护目录仍不在本节点范围。
