# v5 有界实际读取器（本地实现验证）

输入接线顺序已实现：固定 package-root 词法 allowlist → 六 TRAIN 家族/严格整数 seed → 普通、无 symlink 的 aggregate receipt 有界一次读取 → 同 buffer 的实际总 package SHA → 选定 fold manifest SHA → 既有 v3 adapter → 1706 行检查。返回 v5 fitting-only 请求及 input identity，不生成授权，不启动 worker，不写训练产物。

集成正例使用 1706 个**人工动作**的临时 v3 exporter 分片；测试中只替换 root allowlist 和人工 package SHA，让代码真实读取临时文件。没有读取生产 B package，没有真实电路拟合。selected heldout_outcomes 的 open/stat/lstat/is_symlink/resolve 五种操作计数全部为零。受保护 root、错误 family、float seed 均在路径读取前拒绝；总回执字节、实际 manifest、shard SHA 与行数漂移均有拒绝测试。

安全路径校验后再 open 不等于同用户恶意并发篡改下的 OS sandbox；这是既有安全读取器的限制，不能据此宣称系统级防 race。最终回归和独立结论以本节点 validation manifest 为准。

最终完整回归 843 项、30 skip、0 failure/error、exit 0，144.459 秒；包含该读取器最终 5 项集成测试。raw SHA `41efdd62a2b2edf1e1be193c991eb1f7d2060ed528cf5b572e588a820e0ab3e1`。结果与源码身份记录在 `data/manifests/ranking_v5_bound_input_reader_validation_20261007.json`；初稿 4 项 focused 不是最终版本证据。

剩余正式 caller 义务：先验证真实的新 v5 授权、独立封存的源码身份及 fresh prelaunch，再在获准路径读取真实 package；完成正式模型/排名持久化并 SHA 回读后，才加载 TRAIN LOFO held outcomes。正式 18-fit launcher、真实 held replay 和执行放行尚未完成，不进入 BLIND/LSF/Tessent。资源仍保持 single worker/threads1、AS8GiB、sampled combined RSS1GiB、零自动重试。
