# E03：解析正例停止信号

- 问题：能否避免只有偶然抽中近优动作才产生正例梯度？
- 方法：负例-only PL 提议顺序，解析积分正例停止；保留提议分布导数，避免负例梯度偏差。
- 设置：736 动作、单位成本、均匀评分、K10、单正例 UID17，固定四 seed 各32样本；名义工作942,080，一次运行、零自动重试。
- 结果：正例风险梯度四 seed 均为 -0.013485006866910882，解析误差约1.2143e-17。
- 局限：只支持单正例；不证明负例精度、非均匀方差优势或完整模型更新安全。
- 证据：[结果](../../data/manifests/ranking_v6_positive_signal_validation_20261013_r1.json)、[复核](../../data/manifests/ranking_v6_positive_signal_review_20261013_r1.json)、[方法说明](../../docs/ranking_v6_conditional_survival_result_20261013.md)。封存提交 `3f2d150`。
- 放行：合成信号通过；继续 E04，不训练。
