# E113—E115：按真实准备证据继续整合

## 本次完成

### E113：实际启动句柄身份观察

新增独立观察器，不改 E109 历史模块。启动前检查当前 worker PID、稳定身份和单线程；不满足时不调用 Popen。启动后从实际 Popen.pid 双读 /proc，核对 boot、worker、父进程、进程组、会话及自有后代归属，再交持久化 callback。身份检查或 callback 失败时清理已知进程，保留已读输出及有界可取的失败前缀，不重试。

独立复核发现“worker 检查最初晚于启动”的问题，已聚焦修正并增加拒绝前不启动的反例。E113 21 项测试及与旧 E109 联合 34 项通过。全部是 Mock，不是实际 Linux 进程验证。观察的是直接 launcher 子进程，不冒充 ATPG 内核进程；callback 返回不等于 fsync 或独立耐久性证明。domain.peak 为该 domain 的累计峰值，不能未经重置宣称单 case 峰值。

### E114：保留根变量缺失事实的兼容适配

E112 真正观察到四个运行变量，未包含 MGC_HOME/ROOT。新纯本地适配支持这一精确四键、固定绝对 launcher 摘要的分支；不补造变量。当前 profile 与已保存 metadata 必须完全相等，且再次经过 E109 实际启动参数的长度/路径校验；环境漂移拒绝。

6 项测试和独立复核通过。返回运行值仅供未来可信 worker 内存使用；小型回执不含值。调用方仍须绑定真实 E112 响应和部署 launcher，不能自行构造 metadata 冒充环境认证。尚不能保证 Tessent 必然成功。

### E115：真实 statistics 格式与完整 STIL 流

新解析支持真实 top-level 故障分类行中的括号名称、百分比和 subclass 区段；验证 FU 与冻结共同故障数及分类整数分区一致。不从 CPU_time 派生 wall runtime。

对本地 E112 保存的两份完整 statistics 先比对字节数/SHA 再解析，AES 794、SPI 235 个历史 H-full patterns；这些不是本次固定动作采集结果，不能当新增样本、组合 D95 或模型收益。

STIL 接口要求消耗完整调用方字节流并匹配完整大小/SHA，有界 chunk/行长度；只输出最大 TesterCycle 注释值与标记数，不把注释/Ann 重复标记相加，不输出已认证 ate_cycles。8 项测试和独立复核通过，但尚未用完整真实 STIL 正文验证；E112 的前缀样例不会被冒充全文。

## 联合验证

E105—E115 选定回归共 148 项，53.175 秒，0 failures、0 errors、0 skips。原始小型日志保存在 data/manifests/ranking_v6_e113_e115_regression_20261026_r1.log；独立复核和源码摘要见 ranking_v6_e113_e115_review_20261026_r1.json。

## 尚未完成，不能越过

- E113 的身份观察与最终封存/持久 intent/真实预算、E111 输入准备尚需由同一个可信 controller 完整连接。
- 固定翻译 helper 及真实结果引用尚未冻结；E113 对翻译入口明确拒绝，不猜测命令。
- 3 项 Linux 进程自检尚未执行，固定 18 动作采集仍未启动。
- 没有 B、BLIND、LSF、训练、额外历史扫描或新增 Tessent 调用。

## 下一整合包

在现有授权内完成一个实际采集 controller，统一绑定 E112 不可重置时钟、部署摘要、单 worker/512MiB/8GiB 采样停止、持久 intent 和零重试预算、翻译及结果回读。先本地测试和独立复核，再用 3 项获准 Linux 自检验证真实进程行为；全部通过才自动进入 18 动作。不得把这些局部实现 PASS 当作该 controller 的执行许可或 Linux PASS。
