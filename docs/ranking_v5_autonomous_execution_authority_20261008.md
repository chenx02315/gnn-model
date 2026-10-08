# v5 自动推进授权与停止边界

用户在本线程对 `request_user_input_async` 的明确答复为：

> 授权，全部门禁通过后自动执行上述固定 18 项 TRAIN

对应问题的范围为：完成全部实现、独立复核和新鲜环境门禁后，在 B 端新目录执行 v5 的 6 个 TRAIN 家族 × 3 个固定 seed，单 worker、现有内存上限、零自动重试，BLIND/LSF/Tessent 不开放。

记录身份为 `USER_ASYNC_V5_18_TRAIN_20261008`，问题回执调用标识为 `call_dbffb0b3a6cc47e685841ad8dc56cf6c`。`contracts/ranking_v5_user_authorization_20261008.json` 是本次真实用户答复的固定格式记录，不是依据自建 JSON 推导授权。可信依据是线程中的实际答复；后续 caller 必须将其独立获得的 SHA 作为 trust anchor，不能接受输入文件自我声明的 pin。

这项授权不表示代码、数据、import fence、依赖锁、实际 Linux 子进程/RSS、fresh prelaunch 或独立审计已经 PASS。门禁失败时停止并保留一次失败证据，不扩内存、不自动换目录重试，不通过修改合同掩盖失败。权限依赖满足后连续推进，不逐折或逐 seed 重复询问。未经新的明确授权，不访问 BLIND/VALIDATION/PILOT，不提交 LSF/Tessent，不执行额外 fit，也不改变训练协议。

既有历史合同与 manifest 保留原样，里面“当时无新授权”的记录仍是历史事实。本记录不覆盖历史失败、不强推、不修改受保护目录。
