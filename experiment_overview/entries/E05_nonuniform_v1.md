# E05：非均匀评分与不同成本 v1

## 固定设置

- 两个六动作合成样例 mixed/rare，单 ε 近优正例 UID5，K3；真实固定评分/成本见合同对应源码及 raw fixture。
- seed11/29/47/83；各 pilot64/main16384，共名义工作2,368,512；一次执行，零自动重试。
- 风险与标准化成本、每个 UID 梯度、四个冻结方向投影：共144比较。联合 alpha=.01，固定绝对半径阈值 .02。
- 精确原始全 PL 与条件停止双 oracle 在采样前核对；pilot 冻结基线和 L1 方向，main 独立。

## 实际结果

- `PASS_FIXED_SYNTHETIC_PRECISION_ONLY`：144/144 真值在区间内，所有半径≤.02；最大半径 .01746637，最大绝对误差 .00112744。
- `INCONCLUSIVE_DIRECTION`：mixed 四 seed 均认证风险/成本各自下降；rare 四 seed 的成本方向认证，但风险方向 UCB≥0，未认证。
- 精确 oracle 下 rare 的风险方向导数均为负；本轮保守 CI 不能证明其符号。这不是拟合或迁移失败的证据：没有训练模型。
- rare 风险区间半径约 .01112–.01162；其中范围项约 .01106–.01157，方差项仅约 .000048–.000070。主要瓶颈是保守先验范围，不能擅自改旧阈值。

## 证据与限制

- [冻结合同](../../contracts/ranking_v6_nonuniform_precision_gate_v1.json)、[小型摘要](../../data/manifests/ranking_v6_nonuniform_precision_validation_20261013_r1.json)。原始171,755 bytes保留在专属 staging，不复制进本总览。
- 原始路径：`C:\Users\86155\Desktop\new lab\runtime_training_staging_20260928\v6_nonuniform_precision_20261013_r1\result.json`。
- 原始 SHA-256：`306797bd8a993894949544e4506b1f15bca64105f36f04a0bc0231b29035287f`。
- 正式运行前修复“数值失败却可能方向 PASS”的状态问题，加入冻结 payload/观测滚动 hash 和双 oracle；没有消耗额外正式运行。
- 仅验证两个 n6 合成样例，不外推736动作或真实电路。没有 optimizer、Torch、远端、真实标签或训练放行。
- 下一步：独立推导输入条件先验范围并建立新版本验证。v1 的结果与状态保持不变，不自动加样本。
