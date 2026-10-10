# 2026-10-10：Python3.11伪命名空间精确兼容修复

用户在上一轮明确问题“精确修复typing.io/re，复核通过后再运行一次门禁；内存上限不变，不直接重跑训练”之后回复ok和继续。当前只消耗一次新的受限CPU门禁授权，零自动重试，不扩大成正式训练放行。原18项TRAIN条件授权不变，环境门禁/矩阵实现/独立release-review未满足前仍不得启动。

## 原因与修复

只读核实B的Python3.11.2标准库`/usr/lib/python3.11/typing.py`：117090字节，SHA256 `ed0a1062b1d0a0c846c5c794d266470b88cac646d873543e861a3720a3b830e6`。小型源码摘录日志位于`../runtime_training_staging_20260928/v5_typing_source_20261010_r1.json`，SHA256 `9ba195669a58a51ede67b4a2118f62cff1dca3c4f50b77ea401bac91abbf2709`。该源码明确将两个_DeprecatedType类注册进sys.modules，原普通ModuleSpec检查因此拒绝。没有修改标准库/旧证据或执行ML。

只增加两个精确名称的分支：要求Python3.11.2；typing父模块是普通ModuleType，必须exact typing.py、SourceFileLoader、非package，并经过原file/loader/origin检查；namespace必须是父属性同一对象、同一_DeprecatedType元类，严格导出普通字符串列表且每个导出对象与父属性一致，没有spec/file/loader/path。不泛化允许任何缺spec对象，不删除cache，不跳过整个typing子树。

独立review发现两处窄gap（相等比较对象伪造__all__；父源码一致却指向fractions.py）。一次聚焦补齐，新增自定义比较/list subclass/tuple/坏成员，以及wrongorigin/builtin/frozen/package在filesystem检查前拒绝。50focused通过。最终context源码SHA `4cb4b533ed4e87c9144fe99bfb361326b5a745ba71f3e8e47e58aeace1f7fb68`。

## 验证与边界

- full r1在最后修复前启动，期间代码改变，虽输出1007项/33skip/exit0，也明确NONFINAL，不能封存最后字节。
- final full r2修复后串行运行：1007tests、33skip、0failure/error、exit0、177.860s；日志SHA256 `53cd5dc3b2f20ecd7307701c103460518d5ddf961297228299ed7f67e2a804f3`。独立实现及精确包审计通过。
- 候选packet r1同样旧版本，只保留；候选packet r2=11605compressed/51200tar/4regular entries，SHA256 `60c77f70536b590edfa88923ff2e95989860170b8173ffa9fe640c27d9d37443`。只有r2精确byte审计通过才可部署。
- 计划唯一新B目录`/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r1`。保持-I -S -B和5条固定路径、AS8GiB/combined sampledRSS1GiB、worker1/threads1/retry0；只做Torch/NumPy导入和极小CPU张量运算。
- 本日实际门禁1次，exit1，零重试。typing伪命名空间检查已越过，显式`import torch`进入torch/nn后，`torch.utils._python_dispatch`所需`torchgen`被拒绝：`V5_CONTROLLED_IMPORT_UNKNOWN_ROOT:torchgen`。Torch导入未完成，CPU张量验证未通过，不能宣称运行时兼容性PASS。
- guard为STOPPED_NO_RETRY，4个RSS采样，combined峰值381419520字节（约363.8MiB），group峰值360771584字节，低于既定1GiB cap；cleanup后live group=0。不是内存超限，也不提高内存。
- 生产数据读取0，fit0，formal release=false。本次唯一远端门禁额度已消耗，不自动第二次运行。10月8日两个负证据目录保留不变；新失败manifest为`data/manifests/ranking_v5_controlled_runtime_failure_20261010_r1.json`。

## 下一节点

独立原始证据审计为PASS_FAILURE_EVIDENCE_AUDIT_ONLY：三个raw/hash与部署绑定匹配，确认进入部分Torch导入、非内存超限、没有CPU张量PASS。此审计只确认失败记录准确，不代表运行成功。

先只读核实torchgen是否确由锁定的torch发行包提供（准确元数据/文件所有权与固定site路径），再设计最小root-to-distribution映射与拒绝测试，不能直接放宽所有site包。若要修复后再次远端门禁，需新的窄范围执行授权；本次授权不是第二次门禁或正式TRAIN放行。此前18项TRAIN条件授权仍保留，但矩阵入口、完整新鲜release/prelaunch与真实CPU门禁未通过，不可启动。
