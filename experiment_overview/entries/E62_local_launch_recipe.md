# E62：找到真正的本地启动脚本，纠正查找方向

日期：2026-10-20。仅静态读取本地代码，没有运行脚本或读取其引用的日志、状态、结果。

## 结论

上次查找的是以 `phase4_closure_batch_v2` 开头的文件；真正的代码文件分别多了 `start_` 和 `run_` 前缀。在本地 `phase4_bootstrap` 的直接子文件中找到：

- `start_phase4_closure_batch_v2_r1.sh`：680 B，SHA `2f864c541e16b9e573e7aff0a98db6dcfeb45cfd016c663dccc287227662e5a3`。
- `run_phase4_closure_batch_v2.sh`：2323 B，SHA `d1d04f1338af9ec76fffe0224a7b1a1f5ca7ea0bb262e5f2db117a070c5b9f50`。

这解释了上次匹配规则为何可能漏掉启动脚本，但不证明 A 端现在或历史上存在、执行过这些代码。两个原始源码小快照已按原字节封存于 E62 JSON，可用 base64 解码并校验 SHA；没有保存任何运行输出。

## 代码能证明与不能证明什么

starter 第 14–15 行用 `nohup bash` 调用固定框架路径下的 wrapper，并把 stdout/stderr 合并到 batch launcher log；第 16–17 行保存的是 watcher 的 `$!`，不能当成 LSF Job ID。

wrapper 第 33–39 行为每个电路生成作业名，用 `bsub -K` 提交，作业 stdout/stderr 分别写入每电路 `.lsf.out/.lsf.err`。但是第 25、29、37、45、49、51 行还把 SKIP/BLOCK/SUBMIT/FAIL/PASS/BATCH 等进展通过 `tee` 写到自身 stdout。因此 launcher log 混有七电路状态，**不能当成纯提交回显来读取**。

代码中没有历史 driver SHA 或运行前冻结 ACK。这份当前本地源码不认证历史实际部署、调用身份或完整计费。独立复核已确认以上边界。

## 实际调整与下一步

原计划的 E62 宽文件名查找不再需要，未执行远端调用。三个未执行草稿已完整移至本地隔离目录 `runtime_training_staging_20260928/v6_e62_deferred_inventory_20261020_r1`，可恢复，未删除；其 12 项合成测试不算真实读取或训练证据。

接续 E63：只核验 starter 明确引用的 A 端 `00_framework/run_phase4_closure_batch_v2.sh` 当前字节 SHA，不猜 starter 的部署位置，不执行代码、不跟随其引用，也不读取 launcher/progress/status 正文。独立复核和回归通过后才运行一次；即使 SHA 相同，也只能证明当前字节相同。
