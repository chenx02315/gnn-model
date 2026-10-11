# TRAIN v2 实际首任务失败与下一步

2026-10-11，新鲜环境检查及独立启动审查通过后，既有一次固定18项 TRAIN 授权已实际消费。首任务 `iwls_aes_core / 20260824` exit2，父进程 `STOPPED_NO_RETRY`：0项通过验收，其余17项未启动，自动重试0。

## 已证实的失败边界

- stdout 最后拒绝标记为 `V5_REAL_STORE_FREEZE_BOUND`。14次内存采样的 combined RSS 峰值541577216字节，低于1 GiB上限；采样不能证明采样间峰值。CUDA warning 原样保留，不作为失败根因。
- 不可变 store 在 freeze payload 或带 SHA 包装的规范JSON超过20480字节时产生该标记；读回校验也限20 KiB。完整排序同时保存 scores 和 order，UID重复，是静态最可能的体积来源，但实际内存 payload 长度未保存，不能声称已测得。
- 静态执行顺序为拟合、日志与模型保存、预测、冻结保存与读回、held outcomes callback。失败在冻结写入之前。当前收集器不读取模型/checkpoint，因此“0项验收”不能写成“0次实际拟合”。
- 57个固定回执目标中5个存在；首任务只有stdout和memory回执，没有验收sidecar，其他17项回执均缺席。原始内容与SHA已经独立核验。

## 证据与版本

小型事实见 `data/manifests/ranking_v5_train_v2_actual_failure_20261011_r1.json`。原始启动回执SHA为 `fb42ba82a0afe207fc34796eee68827f72185ab3ff3f7ee7fd1b75efbad6257a`，收集回执SHA为 `f1897a07f0e489f696e7df0675ef3edf0b404ad17f9e7c36bbdb99398c35e1e6`。

历史 implementation/deployment manifest 保持当时状态，不回写成训练成功；旧core26、依赖锁、旧运行目录与once文件保留。模型留B，不进入Git。

## 下一步收敛方案（尚未放行新训练）

1. 在新版本中定义完整排序的有界冻结格式，协调 producer、store、readback及验收绑定；不得只提高store常量、截断top10或猴子补丁旧core。
2. 增加20 KiB边界及大候选规模的合成测试；超限时保存小型长度/阶段诊断，验证失败不写freeze、不调用held outcomes。
3. 完成独立设计/实现复核与完整回归，保留当前单worker、RSS1 GiB、AS8 GiB和零自动重试。
4. 当前一次授权已消费；新版本部署与新实际TRAIN需新的明确权限。不能清除once、复用旧目录或把“继续”理解成失败后自动重试。

本次没有模型效果结论，也没有解封BLIND、VALIDATION、PILOT、LSF或Tessent。
