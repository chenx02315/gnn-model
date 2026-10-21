# E69：不停止在模板，继续核实模型真正需要什么

日期：2026-10-21。仅检查六份本地源码/合同，没有读 checkpoint、数据表、预测、BLIND、A/B 或真实日志。

## 已确认与尚不能确认

已知 v2 基础特征路径需要整数 H/M 数量，不接受“25% / 50%”这类符号直接代替。F 的实际完成 pattern 数不是输入，这是正确的部署边界。

但本轮没有加载某个真实模型版本，因而不声称已证明当前某份 checkpoint 的特征版本或兼容性；只确认下面这条已知源码链的事实。

| 来源 | 字段/事实 |
|---|---|
| `contracts/runtime_training_v2.json:50` | 7 个候选特征；没有 D95 分类头；未知安全动作必须在构造特征前拒绝 |
| `src/models/runtime_training_v2.py:201` | 输入 `action_scheme/h_limit/m_limit/common_fault_count`；H/M 的对数与同电路候选集合最大值之比分别入模 |
| `src/models/runtime_training_v2.py:290` | 图输入是 node_type/cell_type/sequential_flag/edge_index；并非结果指标 |
| `src/data/build_runtime_training_package_v2.py:264` | 历史包把 `h_patterns/m_patterns` 填到 h_limit/m_limit |
| `src/data/build_formal_candidate_space_v2.py:108` | 上述 pattern 数复制自历史 measurement，而不是本轮新提出的请求限额 |
| `src/data/build_candidate_space.py:43` | F 是观察结果，不进入可部署 action key |
| `src/models/train_runtime_v2.py:39` | epsilon_hit/cycles/runtime 是训练标签，不应带入候选输入 |

## 必须解决的四个绑定，不假装都只是补一个 SHA

1. **请求与实际产出是否同义。** 不能把未来执行后才得到的 h_patterns/m_patterns 拿来替代运行前请求限额。现有代码链不足以证明二者对所有候选恒等；这是一项待验证绑定，不是已经证明所有历史实验存在泄漏。
2. **比例分母必须固定。** 模型用的是完整候选集合的最大 H/M 限额，不是独立 full-H/full-M 数。不能把 E68 的比例锚点直接当成模型的 fraction，也不能每次只取 top-k 重新计算分母。
3. **安全准入不能倒填。** 历史候选由 PASS/D95 检验选择，新符号网格没有这个先验证明。旧合同又要求未知安全动作在特征前拒绝，因此不能未经版本化设计就把新网格喂给旧入口。F 完成后验验证可以保证最终接受结果安全，但不是原入口“全部动作预先安全”的同一个合同。
4. **真实模型与图必须固定。** 需要 checkpoint/源码特征版本、静态图与 common_fault_count 身份，只看模型名称或填一个路径不够。此处尚未认证任何真实 checkpoint。

## 决策：先取输入证据，不重跑训练

下一阶段优先获取运行前控制绑定证据，弄清旧 action 的限额是否可以在调用前确知，并核对实际模型采用的特征版本。若可证明，再生成整数清单和固定分母/顺序；若不可证明，应另立“运行前可知的请求/结构特征”版本，重新设计公平对照，而不是用未来实测数量偷偷补输入。

这两条路径都不授权本轮重训。尤其不能通过放宽 ε、保留成功样本、免费预计算端点或丢弃失败来让实验看起来有效。

本地代码、测试和独立复核无需逐项询问用户；真实 A/B 资料核实应一次限定为 aes_core/spi 的代码、输入/模型身份和资源元数据，不读 BLIND 或候选结果标签，不运行任何作业。若要采集新数据，必须先形成具体目录、有限 attempt、资源和停止条件的整体执行包，再一次处理整体放行，不沿用旧 Job ID 或 E64 单次日志许可。

已准备一个整体元数据范围请求 `contracts/prospective_metadata_scope_request_v1.json`：总计最多 16 份普通小文件、单份 128 KiB、合计 2 MiB，最多 4 次有界只读连接；不递归扫描、不读 checkpoint 正文/质量/耗时数据、不建容器、不提交作业。当前为请求而非授权回执，`user_authorization_received=false`。若用户一次批准，该范围内的选择器实现、测试、独立复核、核实和封存应连续完成，不再逐文件/逐测试请求批准。
