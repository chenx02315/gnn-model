# E123：只修复工具内部标识符，不改实验任务身份

## 修复范围

保留语义UID、环境RUN_ID、文件路径、父结果SHA、既有MAPPED/ATPG审计marker与所有实验控制。新增内部tool_id：字母r后跟原UID的ASCII字节十六进制编码。该编码可逆且不会把冒号和下划线等不同UID压成同一个名称。

每份已冻结Tcl仅做：紧跟set run_id插入3行基础Tcl helper（含独立TOOL_DESIGN_ID_TOKEN输出），并精确替换set_context及两分支set_current_mode共3处工具名称后缀。机械逆变换逐字节恢复原E108有效Tcl，证明没有更改路径、请求、随机填充、compaction或故障读写策略。新Tcl拥有新摘要，不能伪装原E108已冻结字节。

## 已验证

- 固定78个UID编码唯一，全部最终名称满足厂商实际错误日志列出的字符规则：字母/数字/下划线、首尾字母或数字、无双下划线。
- 真正48个Tessent阶段的完整context最长73字符、current_mode最长64字符；这只是当前候选名称的长度，不是已核厂商长度上限。
- 本机无窗口Tcl解释器逐一执行完整helper，对全部78 UID与Python编码精确相等，不是skip或Mock；这不等于Tessent接受。
- 10项专项及独立复核通过；与E122/E108联合31项通过、零skip，Python3.6 AST通过。
- common新字节3216B/SHA1865b49c09203e0255ff5c5d019420a5e2b76f20f7ca8de5f5a3bdbd16eadd5c；incremental4254B/SHA50982a3c1b9b93b452313ef503bbfe6d17a44f7f3a018334041244807587dafe。

## 没有做

未修改A端失败包或任何历史输入；未再次启动Tessent；未生成新训练标签；未访问B、BLIND或LSF。新版本完整接线、根目录、echo/source pins与token审计仍需在未来新包显式冻结并独立复核。

当前权限已因E121真实首失败停止而消费。只有用户明确批准 contracts/prospective_identifier_repair_proposal_e123_v1.json 所述新整包后，才可在新目录接线、复核和执行；本地修复通过不是续用旧版本或重置旧时钟的许可。
