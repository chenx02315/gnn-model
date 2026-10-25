# E102：先保存监督器观察，再做最终文件检查（本地准备）

## 为什么做

E101 已真实读取 AES，但在最终 scratch 检查时抛错；当时尚未写 case receipt，因此无法从现有证据补出真实工具退出码、峰值或完整单项耗时。此次不能补造历史数据，修复只对未来经过复核的新执行版本生效。

## 已实现

`src/data/direct_observation_journal_e102.py` 是无启动能力的回调组合器，尚未接入远端 executor。调用者须使用已有的锚定、不可覆盖发布器：

1. 接收监督器已返回的原始观察，核验固定电路/方向、字段类型、cleaned=true、输出16MiB上限。
2. 先发布小型 observation：返回码、失败原因、采样峰值、日志字节数/SHA-256、截至监督器返回的耗时和告警清单。不写原始日志正文。
3. 再发布日志，随后才做最终 scratch 检查。发布失败或检查失败立即向上传递，无内部重试。

回执明确 `acceptance_evaluated=false`、`final_scratch_sample_evaluated=false`、`independent_os_termination_attested=false`。这不是最终 PASS，也不是完整 case wall time。输入观察不被修改。告警分类超过128条时记录 inventory_failed，不丢弃已返回的进程观察，更不把告警视为已通过。

## 验证及边界

8项新增测试覆盖：最终检查失败时已先落回执、原观察不变、元数据发布失败和日志发布失败均不重试、无效观察在回调前拒绝、范围/NaN/负耗时拒绝、正常封存也不生成PASS、告警解析超限仍保留进程观察、Python3.6语法。连同其他相关测试，当前66项通过。

全部为本地 mocks；不代表锚定发布器或新组合入口已在真实Linux验证。E100/E101源码和历史失败不改写；未新增Tessent启动、LSF、ATPG、训练或BLIND访问。

独立只读复核限定实现PASS，独立8项测试退出0、源码/测试AST3.6通过。source SHA `e53e1d3b32f237519adf52b8d1005f7c592b428150e8b8e91bbe46878437c027`；test SHA `65341af7dd6ae3a780d31de1dae508e001293b94fc718b547c000fd7be2e0392`。复核强调后续接受逻辑不能把inventory_failed视作已审核清单。

## 下一依赖

还需把新监控器和本组件组合到新 executor，并验证精确来源、独占新目录、失败回执顺序与首失败停止；独立复核五类真实告警的接受规则。新增启动仍受尚待答复的整体修复包授权约束，不复用已消费的E101授权。
