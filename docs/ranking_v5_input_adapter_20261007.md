# v5 输入适配：代码已实现，不是正式训练

在合成物理门禁封存后继续实现输入层，没有等待新一次“继续”，也没有启动真实训练。

新增两块隔离代码：中间请求封装 loader 负责有界普通文件读取、SHA/schema/roles 和 fitting-only 标签检查；v3 fold adapter 负责将既有四分片格式转换为 v5 request。后者只读取 manifest、fit_features、fit_outcomes 和 heldout_features，不检查、stat、resolve 或读取 heldout_outcomes。适配器没有 CLI、训练调用或权限生成。

独立复核已修正并验证 protected 路径零文件系统触达、非普通文件/FIFO、父目录 symlink、manifest release roles 漂移及 held-label 五种路径操作零触达。独立结论：loader DESIGN_PASS、adapter IMPLEMENTATION_PASS；正向用的是合成 exporter 的临时目录，不是实际 B package。Windows symlink/FIFO 能力 skip 保留，不冒充 Linux实测。

输入完整性不等于授权：自提供 SHA、manifest 内 release 或新中间封装都不能证明 caller 已获真实训练许可。实际 caller 仍须把总 package receipt、每个 fold manifest SHA、完整 source binding、正式新授权及独立回执逐一绑定，并在新鲜 prelaunch 通过后才可执行。物理 synthetic worker 仍只开放 synthetic CLI。

最终修订后完整回归：825 tests、30 skip、0 failure/error、exit 0，93.143 秒；原始日志 SHA `13b78247d8a25d61b6c547e85a412c0fb79c60f7920413175364f49a794a504b`。聚焦 26 项、3 skip、零失败。源码/测试 SHA 与独立回执分项记录在 `data/manifests/ranking_v5_input_adapter_validation_20261007.json`。r1 在测试修订期间启动，仅保留，最终结论使用 r2。

当前下一步见 `contracts/ranking_v5_real_caller_design_v1.json`：完成正式 caller 与 freeze 后的 TRAIN LOFO 回放，再满足新正式放行。受控对照保持 6 家族 × 3 seed、7 列、120 轮和当前资源，唯一变化是 first-hit top-10 目标。先判断困难电路 fitting 排序，再判断跨家族迁移，不原样重跑、不立刻增加图模型或批量电路。
