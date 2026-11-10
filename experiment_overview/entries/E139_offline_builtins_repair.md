# E139 失败后的本地兼容性修复

## 目的和不变项

修复私有 `FunctionType` 对隐式内建函数查找的依赖，并补齐从真实授权到子脚本构建、命令检查、模拟监督器的测试。此次用户批准仅用于本地实现、测试和独立复核；不恢复已关闭的 E139，不新增 A/B 连接，不启动 Tessent，不改变 AES F4、共同故障集合或 D95 门槛。

## 已证实与尚未证实

E139 实际在 `CHILD_CODE_BUILD` 失败，子进程与工具扣次均为0。冻结 bootstrap 构造的私有函数 globals 没有显式 `__builtins__`；原 E127 函数在该区间使用 `repr`、`min` 等内建名称。本地清空内建表可以复现构建前失败，补齐后可到监督边界，但这并不是目标解释器上的真实异常记录。

CPython 3.6.9 的 [frameobject.c，622–637行](https://github.com/python/cpython/blob/v3.6.9/Objects/frameobject.c#L622-L637) 明确在不同 globals 且缺少内建表时建立仅含 None 的最小表；3.13 的 [funcobject.c](https://github.com/python/cpython/blob/v3.13.0/Objects/funcobject.c#L167) 走不同的内建解析路径。这提供兼容性机制依据，不能证明本次 A 端实际使用了哪个版本。

独立复核已确认：固定 E139 capture（14,200字节、SHA `7cacac58cda8e5067b0c6a03fb02ddf2e83f32b25bccd29c063318452ee55144b`）和 E112 receipt（226,428字节、SHA `fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae`）均不含解释器版本/ABI的测量字段。`/usr/bin/python3` 和应用 schema 版本不能代替该证据。

## 修复候选与验收要求

在新文件中对冻结有效 bootstrap 做有限派生，显式绑定该固定函数实际引用的九个名称：`repr`、`min`、`len`、`type`、`bytes`、`dict`、`set`、`Exception`、`ValueError`。不修改执行过的源码或授权；不将候选接入旧 phase。这不是面向任意代码的沙箱。

测试须同时保留缺失名称的反例和补齐后的完整预工具路径，确认原命令、30秒/64KiB等预算及错误脱敏规则保持不变；监督器使用无副作用替身，真实进程启动次数为0。语义模拟与 Python 3.6 AST 检查不能冒充实际 Python 3.6 运行，匹配版本的实测若未完成必须明确保留该缺口。

本地修复通过也不产生 F 新增检测数。AES 结果表继续为 UNPROVEN；目标仍是一张有逐故障依据的 H/F新增/去重并集/D95结果表。

## 本轮完成情况

有限修复候选和5项测试已完成并独立通过（0.970秒）。实际冻结源码在真实私有loader中加载，使用实际E139授权；宿主/时钟/进程域是明确的测试替身。修复后的路径到达一次模拟监督器调用，并按预设CASE_TIMEOUT在OBSERVATION_CHECK停止；这一次是模拟调用计数，不是真实子进程。原执行文件、授权和失败目录不变。

小型回执：`data/manifests/ranking_v6_bootstrap_builtins_repair_review_r1.json`。候选有效bootstrap SHA为 `ad019f0ef4910d12be465b8caa41ac27f32befefc3ac659ae104c7e07680658a`，尚未接入新的运行入口。后续只在全新包身份/目录中传播有效源码pin并审查完整接线，不能把这个保留E139兼容身份的局部候选直接发往已关闭目录。匹配解释器的真实执行仍未证明；不以语义模拟冒充完成该项。
