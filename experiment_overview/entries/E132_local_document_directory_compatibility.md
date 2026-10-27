# E132：文档目录扫描兼容性补救（仅本地）

## 最新授权：新文档核验整包已明确批准

用户实际答复“批准 **E132 新文档核验整包**”单独记录于contracts/coverage_semantics_documentation_authorization_e132_20261027.json，SHA-256 a093e056d09c91796ae4cebd0403288a49618ee6afc6a5eef6de6ad762159f8d。正在新增独立执行入口并接入本地兼容组件；原E131源码/失败/时钟以及原PENDING提案均保留。下文“新远端包尚未授权”是此前时点，不能覆盖实际新答复。

新入口/测试及metadata精确包、固定export协议独立复核后自动推进两次限定只读访问；真实候选选择仍由主代理在新300秒窗口内核对，不提前伪称独立审过尚不存在的候选。本包尚无实际A访问。

## 为什么做

E131已真实连接A，但目录盘点返回TypeError，未取得手册。源码使用的os.scandir整数fd在Unix上从Python3.7才支持；这是与旧Python环境不兼容的强候选原因，而非已经由本次现场堆栈唯一确认的报错行。

## 本地补救边界

保留已执行E131源码、原始失败和原时钟。新组件只准备流式目录名迭代：调用方先验证指定文档目录，组件持有自己的dup句柄，核对目录身份及logical/resolved docs-only路径；只将这个已持有句柄的精确/proc/self/fd/数字别名交给字符串路径scandir，且前后核对身份。不泛查/proc、不listdir一次性装入未知目录、不chdir，不读取文档正文。

最多返回200个条目，到上限即保守标截断，不取第201个。模拟旧版拒绝整数fd的API测试只是本地兼容证据，不是实际Linux/安装目录盘点成功。

## 新远端包尚未授权

提案contracts/coverage_semantics_documentation_repair_proposal_e132_v1.json只申请一个新版本：metadata最多1次、export最多1次，单次60秒/整包300秒、200条目/深度2、最多3文档共32MiB、512MiB采样、零自动重试。新包只能在明确授权、完整新入口冻结及独立复核后启动；不能复用E131未用的export次数或续期旧时钟。

没有新Tessent、ATPG、LSF、B、BLIND、训练或D95合同变更授权。组件未接入真实执行器，本条目不代表可执行放行。

## 已完成的本地实现与测试

新增src/data/documentation_scandir_compat_e132.py及独立测试，10项专项通过，联合E131、E130、故障类别、报告、采集控制等选定回归合计190项通过（0跳过/失败/错误）。Python3.6 AST与inert import通过；这些只证明本地实现，不是A端实际盘点或3.6系统API实测通过。

组件源码SHA-256 fb944116ac17da709bda9f6d4a5aa4b0aa4699f3b48c0829bca9ece362f99d11；测试SHA-256 db3f0e44d0afb7341614b663ffddb51531287ad84d567d59dfca1a47b590967c。已执行E131源码仍为bcbc66b54c171ca1cb3b955b189aa85f91c1e77c4b44e61a5539d976d66a168e。

实际安装根认证和跨多个目录合计200项预算仍由未来调用方承担；组件需要调用方提供已验证快照及剩余预算，不可脱离这些条件直接视为完整执行器。

独立复核10项专项及Python3.6 AST通过，结论仅为PASS_LOCAL_IMPLEMENTATION_ONLY，无新增远端/重试许可；回执见data/manifests/ranking_v6_e132_local_compatibility_review_20261027_r1.json。下一步只需对新E132整包作一次授权，随后才能接线、复核并执行新的一次盘点与一次导出；不把本地组件PASS当成现场成功。
