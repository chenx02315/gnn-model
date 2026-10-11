# 冻结持久化 v2：修复范围与执行边界

## 本次解决什么

上一轮首个 TRAIN 任务的部分产物未能验收：冻结记录碰到旧20 KiB门禁，完整排序体积是静态推断的可能来源，现场实际payload长度未保存。0项验收不推断0次实际拟合。本次只修复新版本的保存、读回和验收链，不修改旧core26，不清理失败产物，不消费新的训练权限。

新链仍保存全部候选 scores 与完整 order，保持原payload字段、规范JSON、SHA-256及换行语义；没有截断top10，也没有更改模型、损失、训练轮数或数据划分。

## 容量与内存控制

- freeze专用文件上限16 MiB、held候选数上限1706、UID字符上限2048、图节点上限5150、深度上限4。1706来自当前包总行数；并非声称每个家族实际都有1706候选。
- 拟合前只看fold/UID元数据，计算 `2×UID规范JSON引号编码字节总数 + 68×候选数 + 1024`。估算超过16 MiB就拒绝，不创建输出目录、不调用fit、不读held outcomes。并非保证所有最大长度UID组合都可接受。
- 解码前先扫描字节、节点、深度、字符串及数字长度，再分配JSON对象；之后检查精确schema、完整UID连接、有限分数、排序和SHA。
- 模型1 MiB、日志3 MiB/122条、单条日志与回执20 KiB及其通用JSON限制不变。B端训练的RSS1 GiB、AS8 GiB、单worker/单线程、零重试均不变。

## 新文件链

`freeze_codec_v2 → real_artifact_store_v2 / single_fit_worker_v2 → train_artifact_readback_v2 → independent_fit_context_v2 → parent_artifact_candidate_v2`

`freeze_supplement_v2`只在已有受控core上下文中验证六份新源码的独立SHA，然后注册新模块名并按身份清理；不替换旧模块，不创造CLI别名，不读取正式包、不发放权限。外层仍必须核验core、依赖、授权、资源门禁与新的训练包。

worker相对旧版仅增加两处版本化导入和拟合前preflight。旧数值内核、模型序列化和held读取时序保持。验收只建立字节完整性及独立输入身份连接，不声称已独立验证数值预测或held指标。

## 验证与证据

新增测试覆盖1025/1706完整候选保存、读回、输入连接及guard后验收；旧链仍拒绝旧超限样本。超候选数、转义UID容量、非有限分数、错误SHA/排序、重复键、非规范JSON及guard失败都fail-closed。

本地接近上限的合成编码结果为16412060字节，保守估算16518516字节；Windows进程峰值97886208字节，完整内存编解码一致，仅落盘小型回执。文件保存/读回由独立规模测试覆盖。它没有Torch/NumPy调用，也不是Linux训练RSS或硬内存限制证明。

独立本地装载检查使用未改动的25源码core fence，认证装载六个新模块，确认worker/store/readback/context/collector依赖一致且旧store身份保留；这不是新生产包或真实Linux执行证明。

最终r2完整回归1330项、40平台/依赖能力skip、0失败/错误、exit0，源码前后一致。首轮两项测试夹具因discovery预加载与空命名空间假设冲突失败；只修复测试隔离并补恢复回归，运行时代码不变，首轮原始日志保留。首轮summary解析器对失败计数不完整，错误/skip以原始unittest日志为准；r2已正确提取。完整回归及各证据SHA见同名implementation manifest；能力skip不作为Linux正向验证。本次代码、合成测试和独立复核通过，不等于训练完成或模型效果提升。

## 下一执行节点

旧一次性TRAIN授权已消费，旧CLI/父入口/训练包不重新绑定或重跑。后续需要新的外层CLI/parent/packet版本、独立源码与授权绑定、新鲜B端执行前门禁；在取得新的明确部署/实际TRAIN权限之前保持关闭。BLIND、VALIDATION、PILOT、LSF/Tessent及受保护目录均未解封。
