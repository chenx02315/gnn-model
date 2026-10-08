# v5 当前执行位置与实验终点

核心目标不变：固定 H64/M16/F4、满足D95的组合中，让推荐排序更快找到ε近优组合，减少累计真实ATPG wall time。cycles不是ATPG耗时。当前先修复困难电路的排序目标和拟合问题，不原样重跑旧训练、不大批增加电路。

用户已经授权：所有实现、独立复核及新鲜环境门禁通过后，自动执行固定6个TRAIN家族×3seed共18项。不再逐项申请；单worker、线程1、AS8GiB、采样合计RSS1GiB、零自动重试，失败保留证据并停止该矩阵。BLIND/VALIDATION/PILOT、LSF/Tessent未开放。

## 已完成

- 固定120epoch、7候选特征、top10/ε=101/100的v5排序目标及既有单次fit adapter。
- 原core26字节封存、冻结源码导入、独立模型/冻结ACK顺序实现。
- 本地最终r3：932项测试，32项能力skip，无failure/error，exit0。
- 全新B目录的一次真实Linux源码导入/资源门禁，已独立封存；21模块、合计RSS约37MiB、无实际MLfit/生产数据读取。

以上不是18项正式训练完成，也不是模型收益结论。

## 当前依赖链

| 顺序 | 工作与验收 | 当前状态 |
| --- | --- | --- |
| 1 | 新鲜依赖31版本、搜索路径、来源与传递导入围栏；实际受限ML导入验证 | metadata真实只读审计通过；围栏静态独立通过；新增CPU导入门禁待复核和实际运行 |
| 2 | 受控单次TRAIN入口、真实产物独立读回、完整源码/授权/评审/环境信封绑定 | CLI及产物读回独立IMPLEMENTATION_ONLY通过；正式信封待绑定 |
| 3 | 固定18项串行launcher，首失败停止，零重试/零覆盖；独立复核及新鲜prelaunch | 待1、2完成 |
| 4 | 自动执行已授权18项，在B保留模型、取回小型指标/SHA | 门禁全通过才启动 |
| 5 | 对比训练家族拟合与TRAIN-LOFO：区分目标未学好、输入辨识不足和跨电路迁移失败 | 待真实18项结果 |

第5项才是这轮实验要回答的问题。三seed都汇总，不挑最佳seed/epoch；以既定公平基线比较排序命中、近优regret和累计ATPG wall time，不把合成fixture收敛当真实电路收敛。

## 连续执行规则

一个依赖节点通过后立即进入下一个已授权节点，不因单个测试或复核完成就等待用户说“继续”。只有权限实质扩张、真实失败不能安全修复、证据冲突、内存门禁拒绝或完整阶段结束才需要用户决策。不能跳过缺失实现，也不能用旧环境metadata替代新鲜运行证明。

权威证据：`ranking_v5_import_fence_validation_20261008.json`、`ranking_v5_real_caller_design_v6.json`及执行账本。当前正式release仍为false。

## 最新验证回执

最终受控runtime context修复后，完整本地r1为988tests、33能力skip、0failure/error、exit0，164.851s；日志`../runtime_training_staging_20260928/v5_runtime_entry_full_20261008_r1.log`，SHA256 `64d667972255fac66ebac8e5294e45aaf1afc9ef81a213ecce69189f3d33f7df`。该版本context与CLI独立31项通过，context SHA `a04d5426c7470895bb03fc60a615f6a0d4bc1632a317af96fa0131c46d32f4e9`。上述完整回归不包含随后新增的CPU门禁脚本；不能混作新增脚本完整验收。

新增CPU门禁只做Torch/NumPy受控导入和极小CPU张量运算，生产package读取和fit均为0；4项regular-file小包、压缩64KiB/tar256KiB有界解包、新目录独占创建，父guard使用已封存原core且在child前置资源检查后才导入ML。当前12项本地测试通过；独立review和实际B执行尚pending。不放行TRAIN。

后续实际运行：r1在导入ML前被`sitecustomize`缓存拒绝，退出1，父guard正确STOPPED_NO_RETRY、livegroup=0，峰值combined42024960字节；旧目录原样保留。155字节只读诊断确认stdlib的sitecustomize是指向/etc的系统apport hook，不予新增准入。唯一聚焦修复改为父/子均`-I -S -B`，显式固定已审计的5条sys.path、不运行site hook或pth，不改系统/原core/context代码。修复后18项focused和1006项完整r2通过（33skip/0failure/error/exit0，170.884s，SHA7c94986be019b9f09d3d1039a72d18604694bcc748ebdcbb010aa0c44397b412）。r2独立代码/packet审核及唯一实际执行尚pending；正式fit=0。r1失败回执见ranking_v5_controlled_runtime_failure_20261008_r1.json。

## 当前真实阻塞（覆盖上方pending阶段）

r2独立代码/packet审核通过后，在全新B目录实际调用一次仍退出1：`V5_CONTROLLED_IMPORT_PRELOADED_SPEC:typing.io`。这是Python3.11标准库保留的`_DeprecatedType`伪命名空间，没有ModuleSpec；只读诊断也确认typing.re同类。门禁在显式Torch/NumPy导入前拒绝，不是OOM；combinedRSS41189376、group20529152、采样1、退出清理后成员0、STOPPED_NO_RETRY。r1启动hook历史没有被审计，不泛称整个启动期间零ML。

现已用完一次聚焦修复/复跑额度，停止第三次自动远端门禁尝试，不部署/执行训练。两版目录和原始小型回执都保留，current evidence见ranking_v5_controlled_runtime_failure_20261008_r2.json。18项TRAIN条件授权仍存在，但实现环境门禁条件未满足、fit=0，不能把本地1006tests PASS当实际runtime PASS。后续需窄范围兼容typing.io/re的标准库身份核验，不能对所有缺spec对象放行；新远端门禁需先解决两次失败后的执行边界。
