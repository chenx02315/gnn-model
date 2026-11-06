# E139：新目录的有界恢复提案（未授权、未实现完整入口）

## 已完成的本地修复（2026-11-06）

最新：本地原生图、材料、控制会话与 capture 准备接线已经完成独立复核，最终762项相关回归通过（49.632秒）。这不是新一轮物理实验：没有实际 E139 授权文件、运行目录或 A/B 连接。

具体证据如下：56模块原生图中14份做有限派生，42份helper保持原字节；实际loader加载后，assembler组件共享同一有效contract，capture依赖pin及输入源码交叉连接通过。recipe的主脚本与helper都采用新输出root，并可逆向还原为原科学命令。实际材料保持capture/execution/readback各35/53/36份源码与原顺序，静态缓存不变，五个动态源码输入改为有效字节；公开137行摘要，旧依赖计数与有效字节校验明确分开，没有声称所有依赖语义已验证。

私有本地会话先加载原生图再加载7份控制脚本；空路径scripts父包阻止延迟导入回退到旧模块。每次源码闭包检查同时重验原文、有效字节和配置摘要；异常退出恢复注册表与锁。packet不再拿磁盘旧源码冒认RAM有效源码。入口start不再复制有闭包的run_role，而是核对已加载clock的对象关联和源码标签，保留会话存活保护及原截止计算。

集成测试以实际私有图/材料/打包器生成完整capture包，但授权是明确标注的合成数据。start测试替代了pinned factory和role执行，只证明clock连接与方法保护，不证明真实建phase或capture执行。还需固定薄公开入口、真实facade/provider来源绑定及本地替代运输下的实际pinned构造验收；之后才形成完整冻结和一次新整包批准请求。实际grant缺失时绝不把合成记录当权限。小型回执：data/manifests/ranking_v6_e139_local_preparation_review_r1.json。

有限派生器及合同/bootstrap 两模块候选已独立复核：24 项定向测试、711 项相关回归通过。派生器同时验证原始 SHA、规则及次数和有效源码 SHA，拒绝重叠与级联替换；仅输出私有字节和小型元数据，不加载或运行模块。合同的新身份/目录/预算与提案一致，默认仍禁用，bootstrap 显式拒绝 E137/E138 已消耗授权的哈希。

合成中文/左引号授权以 canonical ASCII JSON 保存原话语义，经过两个真实解码函数及派生 bootstrap 的授权检查后，按测试设计停在 CONTEXT_JSON；host、supervisor、子进程、tick 均未调用。此处不是实际 E139 授权证据，更不是完整入口验证。E138 原授权与原源码不改；兼容模块名、文档和诊断码保留旧标签并明确记录，不能据此声称整个运行图已迁移。

小型复核回执：data/manifests/ranking_v6_e139_identity_subset_review_r1.json。后续继续将时钟/归属收据/取回的生产者与消费者 schema 成对迁移，随后绑定 recipe、完整源码图、worker/controller/运输与实际材料；不跳过完整接线审核，不提前连接服务器。

runtime primitives、root receipt、role2 join、role3 export 的四模块候选也已完成：9处精确schema替换，原文逆向还原与AST恢复一致，原限制、来源pin和默认禁用状态不变。6项结构测试独立通过，最终全部717项相关回归通过（37.512秒）。receipt→join、join→export 的字面量已配对；clock/capture/assembler/cleanup等外部生产者明确标为待接线。本轮没有加载或运行这四份派生模块，不能据此声称ownership/readback已验证。回执：data/manifests/ranking_v6_e139_runtime_identity_subset_review_r1.json。

## 目的与边界

E138 的真实授权含 UTF-8 中文，冻结 bootstrap 使用 ASCII 解码器，在工具启动前失败。原字节、phase 和失败回执保持不变。E139 不是恢复旧任务，也不使用 E138 未用完的第三连接。

新提案只变更包身份、协议标识、新远端根和新本地 phase；其余资源、操作预算与 E138 一致。机器合同在 contracts/physical_f_clean_replay_proposal_e139_v1.json。范围仍仅 AES 当前固定 F4 外部向量的一次干净故障仿真，随后独立核算检测信用；不是新生成 ATPG、模型训练或历史动作归属证明。

新远端根：/temp/jiangchuanc/multimode_ate_physical_f_replay_e139_r1。新本地 phase：v6_e139_clean_F_replay_r1。两者必须新建，发现已存在则停止；不改动或清理任何旧根。最多 3 个 A 连接、1 次 Tessent、3 个 Python 自检、1 个 bootstrap 子进程；全包 3600 秒包含审核和传输，单 worker、512MiB 采样停止阈值、8GiB 新目录采样阈值，零自动重试。B/BLIND/LSF/训练/额外帮助会话均不开放。

## 先做哪些本地工作

1. 固定旧 E138 源码与真实失败证据哈希，列出 E139 合同、根目录、phase、时钟和私有服务的全部绑定点；复用旧算法时记录原始源码、适配源码及有效配置，不把旧代码标签冒认为新状态。未知或遗漏的绑定必须拒绝，不能简单替换目录字符串后执行。
2. 为新身份建立默认禁用的合同/配置迁移。审查范围覆盖 capture、bootstrap、collector、私有 Files/storage、recipe、root receipt、join/export、worker、packet、controller、入口和运输审核记录；只迁移必须变更的绑定，不复制无关算法或改旧文件。
3. 统一新授权的序列化与解码契约。未来真正收到新批准时使用兼容的 canonical ASCII JSON（Unicode escapes 保留原话语义）；编码转换不是新授权。旧编码反事实候选不能当作 E139 grant。
4. 准备阶段必须把将要发送的同一份实际授权、提案、完整输入和源码配置贯穿实际 pretool 校验；同时保留 UTF-8、中文、左引号、重复键、非有限值、错误包身份、错误根和旧授权的反例。不能只验证 JSON 能解析或使用合成授权断言全链通过。涉及环境/进程的部分仅用明确替代后端验证，不伪称真实环境已经执行。
5. 用既有固定本地缓存构建真实材料清单，先核对哈希再解析；不新增远端取件，不输出厂商正文或私有环境。保存小型元数据和 SHA，完整正文只留私有 RAM。
6. 实现并独立复核精确包、模拟运输、本地一进程三角色、原始时钟、原文先存后验和失败终止。验证实际将使用的入口，不以组件单测数量替代真实接线证据。

## 复用实现的具体选择

独立架构复核建议采用“薄入口＋冻结 E138 源码的私有派生模块图”，而不是批量复制所有模块。派生器只接受清单指定模块和指定常量/字符串字面量，要求原始 SHA、原值及出现次数一致；禁止全局 E138→E139 替换。每份材料必须同时记录 origin SHA、规则 SHA、effective-source SHA，运行 pin 绑定实际执行字节。旧模块 globals 和文件均不变，私有图退出后恢复模块注册表。

迁移点至少包括：合同身份和旧授权拒绝；bootstrap 硬编码身份；clock/receipt/join/exporter 的 root、phase、schema；recipe 的 main 和 helper；selector/STIL 输出路径；assembler 内部私有原文与有效 pin；worker/envelope/packet/controller 的身份、来源闭包和新入口授权路径。无需改变的解析器、文件原语、运输算法和科学命令保留原字节。无法精确派生的模块需单独实现小型适配，不能用宽泛运行时改写兜底。

以上是待实施的路线，不表示派生器或完整模块图已存在。源码标签只表示一致性，不自证独立审核或真实许可。

## 何时才运行（授权状态）

目前没有 E139 授权，也没有可执行的完整 E139 入口。提案测试通过仅表示预算未扩张，不能设置 execution_ready。待新身份绑定、本地验证和独立复核就绪后，请求一次 E139 整包批准；收到真实批准、绑定准确字节及完成首个精确包审核后才启动第一连接。后续角色在同一进程和原时钟内逐包审核，不重新开预算。

首个失败停止科学执行。只有已保存的角色2原文、归属及清理证据通过本地 native join，才可在原预算内用第三连接固定取证；无根或未知清理时不探测、不取件、不重试。最终结论必须来自向量应用与逐故障检测依据，不把传输成功、工具退出码或本地 PASS 当作 D95。
