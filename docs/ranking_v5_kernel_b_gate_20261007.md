# v5 实际 CPU 合成训练接线门禁

独立复核后实际执行一次远端门禁，状态 **PASS_WITH_WARNING**。没有真实训练、BLIND/held 评估或远端文件部署。

生成 72 个虚构动作，其中 60 个进入拟合；同一固定 seed 两次预计划的 120 轮拟合，共 240 次优化步。两次权重 SHA 和各 122 条日志完全一致。合成 head loss 从 0.704895 降至 0.006132，仅说明这个人工 fixture 的接线能优化，不能证明真实困难电路学好了。

峰值 RSS 为 522153984 bytes（约 498 MiB），小于 1 GiB **事后观察阈值**；AS 8 GiB 和 CPU 120 秒是硬限制。墙钟采用固定外层 GNU timeout 180 秒与 SIGALRM。未提高资源、未增加 worker、零失败重试，耗时约 2.39 秒。

CUDA 初始化 Error 2 警告再次出现；空 CUDA_VISIBLE_DEVICES 并未消除它。原始 stderr 完整保留，独立复核接受已完成的 CPU 计算，不宣称 clean CUDA 或 GPU 可用。

审计记录分离：原始日志证明 bootstrap 正常输出；外层 argv/exit 来自本次工具执行回执；program SHA 是发送前逻辑 UTF-8 源码（不包含终端换行），不能冒充独立捕获的远端 stdin 字节 SHA。11 份 payload 源码/lock 的 SHA 在远端解包和独立复核中均精确比对。

原始证据：`../runtime_training_staging_20260928/v5_kernel_b_gate_20261007_r1.log`，SHA `647e83f7381f9a4e3434cda4435426348a1a12975c5ea50ddae89f22c72199cf`。结构化封存见 `data/manifests/ranking_v5_kernel_b_gate_20261007.json`。

最终源码完整回归 773 项、25 skip、零失败/错误、exit 0，69.635 秒；日志 `../runtime_training_staging_20260928/v5_kernel_gate_full_20261007_r2.log`，SHA `0b14520f289faba176705c38e3e33edcfecc097c47a41351ca53251dc253db36`。第一次回归在控制修订前，仅保留证据，不替代修订后完整复跑。

后续是单独的真实训练 release/freeze/receipt 实现与门禁；本次 PASS 不解封正式 18 fit，不允许标签进入 held 排名冻结之前的训练/调参。
