# E140：解释器问题确认与完整修复接线

日期：2026-11-10。目的：先让固定 AES F4 的干净回放能正确启动，最终补齐 H64+F4 的逐故障覆盖证据；不是重训模型。

## 最新实际终态（下方准备状态保留为历史）

用户已明确回复“批准 E140 整包”。实际 canonical ASCII 授权为 1,801 字节，SHA `977e5de382e91433cde3e0f9c6dc77b5da3e4d4ee8bdcce63b2c2222ddd84b33`；实际授权预工具 3 项独立测试通过，capture 与 execution 精确包分别独立审核后由同一控制会话按原时钟发送。

capture 成功；execution 返回 782 字节失败帧，SHA `cbb10ac058522f32d6e1eba8aae5e695e6fe07286f6016d1ac089db7c679160b`：尝试阶段 ENGINE_COLLECTION，VALUE_ERROR/REDACTED_UNKNOWN_ERROR，工具启动扣次 0，无 owned_root/cleanup。原 phase 已 VALIDATION_FAILED，两个连接已消耗，未使用第三连接、未重试。本地控制进程已退出。

该 checkpoint 位于 selector.build_plan 之前。只能按程序顺序确认 bootstrap 和 launch builder 已返回，不能宣称 collector 开始读文件、bootstrap 独立完成回执或实际子进程数。故障细节未输出，当前继续本地确定性定位，不改本次冻结源码。F 新增和 H∪F 都未知；D95 未证明，不是已证明未达标。完整独立终态回执：`data/manifests/ranking_v6_e140_actual_terminal_failure_r1.json`。

## 已确认什么

A 端 `/usr/bin/python3` 存在，实际版本为 CPython 3.6.8。因此不是“没有安装 Python”。已获准的一次只读通用探针复现：动态构造的函数未显式配置内置名称时缺少 `repr`；显式配置九项名称后通过。探针没有携带项目源码、没有启动 Tessent，也没有新检测结果。原始记录在 `data/manifests/a_python_builtins_readonly_observation_20261110.json`。

E139 的实际失败发生在 `BOOTSTRAP/CHILD_CODE_BUILD`；工具启动扣次为 0。上述探针验证了兼容问题机制，但未直接测得原失败被隐藏的唯一异常，不能把机制复现说成原异常逐字核实。

## 做了哪些修复

在新 E140 文件中显式绑定冻结构建函数需要的九个内置名称，保留旧 E139 源码、授权和失败证据。新身份贯穿 56 个原生模块、7 个本地控制核心、实际材料适配、固定公开入口和有效源码 SHA；不通过改旧全局变量或关闭检查来放行。保留同一控制器、原始整包时钟和逐角色独立审核。

组件独立复核均通过：材料与私有入口 8 项；会话与原生图 14 项；真实 pinned factory 本地构造 3 项；公开入口 5 项。最终相关回归 **821 项全部通过，60.674 秒，退出码 0**。这些是实现/合成证据，不是 A 端完整函数实跑、SSH 连通性或 F 检测信用。

## 目前还差什么

来源冻结为 `data/manifests/ranking_v6_e140_proposed_source_freeze_r1.json`，摘要 `83cecb8e87eb20043c88cd351500b2b6ddbb4f6f4735cc2c42f1cbfaf9477e98`。独立再生与逐字段核对通过：11+73 项原始来源、56 个有效原生模块、7 个本地核心及两层配置摘要均无不匹配。该文件保留生成时待审状态；最终独立审核另写 `data/manifests/ranking_v6_e140_integrated_review_r1.json`，不改被审字节。

E140 未收到新的整包远端批准，未生成实际授权文件，未创建远端目录或启动 Tessent。E139 的零重试终态不变。

下一次整包范围：全新目录、单 worker、最多三次 A 连接、一次 Tessent、零自动重试、首失败停止，512 MiB 采样停止阈值、8 GiB 目录阈值、整包最长 3600 秒（包含审核/传输），仅固定 AES F4 干净回放。不得新生成 ATPG 向量、导入 H 检测标记、访问 B/BLIND、提交 LSF 或训练。

成功后才按共同 71,216 个故障逐键连接 H/F：H 已有 18,323 个合格检测，F 至少需新增 49,333 个，去重并集达到 67,656 才达 D95。任何回放或映射缺口都继续记为未证明，不填零或借用旧合并状态。正式结果总览在 `../AES_HF_RESULT.md`。
