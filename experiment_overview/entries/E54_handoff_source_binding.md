# E54：用户提供副本后，正式来源哈希链恢复

日期：2026-10-18。

## 结论

两份副本已可读取，且不是仅凭同名接受：receipt 完整字节 SHA 与 E47 正式 package 的 candidate_receipt 绑定一致；provenance 完整字节 SHA 与该 receipt 的 source_provenance 绑定一致。此前“缺少可读元数据”的阻塞已解除，用户不需要再复制文件或重复授权本步骤。

## 实际执行与范围

独立 13 项合成测试通过并放行后，一次固定本地双文件读取 exit0，输出 `PASS_BOUND_TRAIN_PROVENANCE_METADATA`。

- receipt：1368 B，SHA `48c164e99e653c1d00dbf8e7655447e2ffc09c9519c63b7191dff9a151b7456d`。
- provenance：5880 B，SHA `b1bfb85632209948cd23c353cbc93da8d70871478f2f53098a8f9a255fc11ccb`。
- 32 条来源元数据中，选择六个 TRAIN 电路的 24 条，覆盖每电路 HF/HMF coarse/refine 四阶段；其余 8 条只扫描字节结构并计数，没有解码值。
- receipt 中只解码 schema 和三个指定哈希，不解释 counts、质量派生值等其他内容。provenance 只在完整哈希匹配后，先按原始 circuit 字节筛选，再解码选中字段。

保留原始数据行序号（不含表头）和物理行号（含表头），不筛 PASS、不删失败、不重新生成原文件。没有打开源测量表、质量结果、checkpoint 或 A/B 主机，也没有修改 ACL。

小型投影回执：`data/manifests/ranking_v6_e54_train_provenance_projection_20261018_r1.json`，SHA `8aca374b13a89035706a72006258e9373ba67f0f31eda5376215eb51d007ba9e`。

## 这一步证明与不证明什么

证明这些提供的 metadata 字节确实由正式 package 哈希链绑定。尚不证明它们与 E38 记录的每个源快照版本相同，不证明文件历史生成时刻、执行前候选全集冻结或完整搜索计费，更不是模型训练或性能改善。

下一节点 E55 按 `circuit + stage + source_sha256` 对比已有 32 个 E38 快照。`normalized_sha256` 单独保留，绝不代替原始 SHA；有多个相同字节位置时保留所有位置，不默认选择 v2。

具体例子：s35932 的 HF 整数细化源 SHA 以 `5eb754...` 开头，规范化副本 SHA 以 `6768be...` 开头，两者不同。生成器会重写规范化副本（包括必要时补 candidate 列）；版本比较必须使用原源 SHA，不能因两个 SHA 不同就猜测版本或改用副本 SHA。后续 E55 已实际确认全部24项各有一个原SHA匹配。
