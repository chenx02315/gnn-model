# 数据边界

Git 仅保存小型、可审计的配置、manifest、schema、SHA-256 和汇总结果。

以下内容不得提交：

- 原始 Tessent driver/tessent logs；
- TSDB、STIL、MTFI 和网表大文件；
- 未压缩的候选全集或中间运行目录；
- 模型 checkpoints 与训练缓存。

数据位置通过合同文件和 manifest 引用；A 端历史证据保持只读，B 端大文件只放 `/ssd/cjc`。

