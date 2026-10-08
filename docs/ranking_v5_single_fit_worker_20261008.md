# v5 单次拟合 adapter 与子进程资源前置条件

目标仍是减少命中 D95 安全近优组合之前累计 ATPG wall time。此次只把固定拟合 loop、封存和回放接成单次调用，不修改头部目标、7 列特征、120 epochs、Adam、seed、ε/K，也不新增电路或重跑正式训练。

新增 worker 先验证审批字节完整性、root/family/seed/output 词法条件与当前子进程前置条件，再通过 bound reader 读取一次输入快照。固定 `fit_prepared` 回调只收到 fitting data、recipe 和 seed；日志绑定完整请求 SHA 与 recipe SHA。模型字节由有界 buffer 生成并交给已有 create-once 存储，模型 ACK、freeze ACK 和完整读回后，才加载该 TRAIN LOFO 留出标签。失败保留部分文件，不覆盖、不重试。

资源 helper 要求固定 Linux 解释器、AS hard/soft 均为 8GiB、core=0、线程环境变量均为 1、CUDA 隐藏、用户 site 禁用、禁止 PYTHONPATH/VIRTUAL_ENV，并核对已有 guard 的单 worker、RSS=1GiB、零重试等策略没有变动。它不改变限制；父进程的 RSS 采样监控与最终回执仍须由未来 launcher 的 `run_bounded` 实际执行，不能由子进程自证。环境变量也不能单独证明 Torch 实际线程数。

本机没有 Torch，本轮使用人工输入、模拟 tensor/拟合回调、模拟 Linux 前置观察值和临时文件进行实现验证。没有 B 调用、生产 package 读取、真实 Torch 拟合或正式训练收益。输入/授权的测试 patch 不能当成 genuine consent。worker 没有正式 CLI、完整运行时源码文件绑定或锁定环境 preflight；正式 18-fit release 仍为 false。

worker 在实际 tensor 操作前调用线程 set/get 检查，要求 intra-op/interop 均为整数 1，但本轮对应 API 仍为模拟值，不宣称真实 Torch 线程已经验证。有界模型 buffer 拒绝初始数据和状态恢复，并覆盖 write/writelines/seek/truncate；超限在 buffer 扩张前失败。`python -m` 调用该模块必须以 `V5_SINGLE_FIT_CLI_CLOSED`、exit 1 拒绝，不能无操作退出 0 冒充成功。

下一节点是受控物理 launcher：导入 runtime 之前落实 guard、完整源码与依赖绑定、产物及最终 memory receipt 验证，再接串行 18-fit 调度。新放行、环境门禁、独立复核都必须单独成立。不得以本节点 PASS 自动访问生产数据、BLIND/LSF/Tessent。

本节点最终证据以 `data/manifests/ranking_v5_single_fit_worker_validation_20261008.json` 为准。

独立复核 IMPLEMENTATION_ONLY PASS；21 项 focused、0 skip。最终完整回归 885 项、32 skip、0 failure/error、exit 0，158.723 秒；日志 SHA `5e11d548f35b4b72665a9b1bd53af3ddf60b5d3046ec5e198a0d817bd47f29c2`。这不是实际 Torch、Linux 正向运行或正式训练放行证据。
