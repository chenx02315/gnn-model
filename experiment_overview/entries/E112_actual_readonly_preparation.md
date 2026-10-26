# E112：整包授权后的真实 A 端只读核对

## 目的与范围

开始落实用户已批准的固定 AES/SPI TRAIN 采集包。此次只做一次固定准备核对，不运行 Tessent、翻译、LSF、训练或 BLIND，不修改历史输入。此前本地实现不耗远端计时；本次第一次 A 准备调用已经启动不可重置的 14 小时窗口。

## 本次真实结果

- A 主机身份、UID 与固定 SSH host key 匹配；transport rc0，无超时、溢出、写失败或 stderr。
- 17 项冻结输入（1 库、10 个共同故障/映射/manifest 文件、6 棵 TSDB）和启动脚本均匹配已冻结摘要。
- 6 份限定历史 TRAIN 报告全部完整流式 SHA-256：AES/SPI 各 statistics、patterns、tester.stil。不扫描其他电路。
- 整个只读捕获哈希正文 30,242,187 字节；返回 226,428 字节；采样 worker 与子进程 RSS+swap 峰值 23,527,424 字节（约 22.44 MiB）。
- 捕获耗时约 2.16 秒。512 MiB 是采样停止阈值，不是内核硬限；90 秒是协作式检查期限，不是阻塞 IO 的硬保证。
- 新 Tessent 0 次、翻译 0 次、3 项 Linux 自检尚未执行。没有新增训练样本或模型收益结论。

## 发现与处理

1. 真实 statistics 含 #test_patterns。CPU_time 不能作为 wall runtime。
2. 大 STIL 在 // 注释与 Ann 中重复标记同一 TesterCycle；原始 marker 数不是周期数，不能计数相加。AES STIL 为 2,020,035 字节，SPI 为 466,022 字节；只返回有界样例，同时对完整文件哈希。不能把样例当完整解析。
3. AES patterns 为 70,054 字节，超过本次 64 KiB 全文返回门槛，因此只有完整摘要及前缀，不能当全文。SPI patterns 为 20,862 字节，可完整返回。
4. module 子进程正常退出，环境包含 PATH、LD_LIBRARY_PATH 和两项 license 变量，均符合格式；没有 MGC_HOME/ROOT。E112 的额外“根变量必须存在”假设标为不严格兼容，不等于服务器坏了。E109 也未要求其存在。后续应根据固定绝对 launcher 的真实需要复核，不臆造或补入路径。

## 门禁与证据

本地 113 项相关回归通过；E112/controller 26 项专项通过；独立只读复核通过精确 payload 后才执行。Windows fixture 的 named stat/CRT fstat ctime 视图差异已局部修复，不放松 Linux 的生产身份检查。

原始报告与启动脚本文本保留在本地 staging，不纳入 Git。小型总览和逐文件 SHA-256 见 data/manifests/ranking_v6_e112_artifact_index_20261026_r1.json，精确执行前复核见同目录 ranking_v6_e112_pre_review_20261026_r1.json。

## 继续执行

保持现授权不变，继续实现实际进程身份、持久启动意图、显式环境和完整流式结果解析的整合，独立复核后执行已授权的 3 项 Linux 自检；所有门禁通过后自动进入固定 18 动作。不重复准备调用，不自动重试，不重置计时，不把本次只读核对当采集完成。
