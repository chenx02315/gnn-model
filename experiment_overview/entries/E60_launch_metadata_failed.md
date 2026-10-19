# E60：启动元数据定位被门禁拒绝，保留失败

日期：2026-10-18。没有取得成功目录清单或启动连接结果，不把测试通过写成实际执行通过。

## 实际发生了什么

固定范围为 A 端 Phase4 的 `logs` 和 `00_framework` 两个目录，仅选择两个明确 batch stem。内容读取仅允许单后缀 `.sh/.lsf/.bsub/.job` 启动代码；普通日志、status、submit 记录全部只做文件元数据检查，不能打开正文或计算正文哈希。即便在代码里识别到 Job/SHA 字样，也只当作代码字面声明，不认证提交事实。

13 项合成测试、独立源码/隐私门禁以及 799 项相关回归（793 执行通过、6 条件跳过、零失败/错误）后，实际发起一次 SSH。连接与传输没有超时、stderr 或输出越界；但远端 child exit2，只返回固定 `FIXED_SCOPE_REJECTED`。耗时 1.154 秒是这次 SSH 观测开销，不是 ATPG wall time。

原源码、合同、测试、失败 stdout 和传输回执均保留；没有用同一程序自动重试。实际拒绝 guard 和读到哪一步仍 UNKNOWN。不能声称“没有读取任何输入”，也不能因保护性拒绝声称历史没有启动记录。普通日志/status/submit 正文在源码所有路径都不允许打开，这一点由代码审查保证。

## 已做的失败后核查

实现者与独立复核均只用合成数据检查了空目录、两个目录、仅元数据文件、空代码、普通代码和锚点上限等组合，没有复现生产者/响应校验器矛盾。

另复现了一个可移植性缺口：这版新代码使用 `str.isascii()` 和 `os.scandir(directory_fd)`；二者在 Python 3.7 才支持。缺失这两个 API 的合成环境分别产生 AttributeError / TypeError。A 端当时实际版本未知，因此这只是有依据的候选解释，不能反写成已经证实的失败原因。官方依据：[str.isascii](https://docs.python.org/3/library/stdtypes.html#str.isascii)、[os.scandir](https://docs.python.org/3/library/os.html#os.scandir)。

## 后续操作

继续做独立的 E61 最小解释器能力观测：只返回三段数字 Python 版本、两个接口声明能力和资源/非访问标志，不列目录、不打开项目文件，不运行 E60。待观测和独立审查通过后，才决定安全的兼容修复或下一诊断，不降低 nofollow、隐私、字节/数量预算。

本次没有访问 B，没有提交 LSF/Tessent、读取 BLIND 结果或训练。E59 当前源码字节一致的结论仍成立，但 E60 的启动定位未完成。
