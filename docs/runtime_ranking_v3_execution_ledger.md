# v3 执行账本：持续推进的边界

核心目标：在未见电路上推荐较优的D95安全H64/M16/F4组合，减少首次命中1%近优组合前的累计ATPG wall time。不能用未命中的低耗时冒充优化成功。

## 已完成

- v2负结果诊断封存。
- v3家族内pairwise排序核心、六折流程、神经/XGBoost适配器与全18家族seed回执宏汇总。
- synthetic物理分折包与冻结后留出标签加载门禁。文件hash、源manifest外部digest、精确fold成员均检查；禁止覆写原包。
- synthetic磁盘端到端18回执通过（mock预测，不是训练结果）。

## 单一环境权限阻塞

本机Python3.13，没有torch或xgboost；项目既有ML锁为Python3.11相关环境。未发现docker，可执行wsl存在但WSL组件未安装。应用bundled-dependency查询工具报告不可用。没有安装系统组件、下载另一版本Python或访问远端。

当前缺少明确获准的依赖齐全隔离执行环境，真实神经forward/gradient/fit与XGBoost兼容性/同seed复跑都不能验证。不得伪造ML PASS，不重复跑mock制造进度。

最小下一权限请求：允许使用B端一个全新`/ssd/cjc/gnn_model_ranking_v3_synthetic_*`隔离目录，仅部署代码和生成合成数据、验证现有锁定版本的模型测试；不读取任何真实电路/BLIND/历史checkpoint，不提交LSF或Tessent，不启动正式六折训练，不访问受保护`/ssd/cjc/multimode_ate_gnn_v1`。先检查可用空间/版本/源码摘要，发现冲突停止，不修改历史环境。

## 得到上述权限后的连续链

隔离环境与版本锁检查 -> 全部真实ML合成测试和三seed确定性测试 -> 修复一次有证据的聚焦失败并完整复跑 -> 物理fold层与执行接口独立复核 -> 源码/合同/审核回执封存同步。

真实TRAIN数据导出/正式训练需要后续独立release，不能用合成环境授权替代。BLIND仍关闭。已有VALIDATION属于已观察开发证据，不称作独立全新验证。

所有已完成节点不因再次收到“继续”而重做；遇到未授权边界只提出一次具体权限请求，不自动访问远端。

## 2026-10-04：环境阻塞解除，合成执行封存

用户批准上述合成环境范围后，已在B的新目录`/ssd/cjc/gnn_model_ranking_v3_synthetic_589b340_20261004_r1`完成测试。没有读取真实电路、BLIND或历史checkpoint，没有提交LSF/Tessent或正式训练。

- 初次源码包17个常规文件，经SHA-256和有界解包后执行30项测试：0跳过、0失败、0错误、退出码0。
- 不改首次封存源码，另建extensions扩展测试：3项测试全部通过。覆盖六留一家族折 × 三固定seed × CandidateMLP/GraphSAGE/XGBoost，共54次生成数据拟合；另外验证同seed预测和模型参数/booster字节复跑一致。
- 六折真实模型集成测试使用内存冻结回执；磁盘冻结/物理分折门禁由初次测试单独覆盖。不能声称54次流程均为磁盘端到端。
- Python3.11.2、numpy2.1.3、torch2.5.1、xgboost2.1.2及完整依赖锁核验通过。新venv只读共享旧锁定site-packages，并非复制了一套独立依赖；设置禁止写pyc，未修改旧环境。
- 本地回传核验通过：原始日志digest、父子回执连接、封存源码清单、扩展测试源码digest均一致，详见`data/manifests/ranking_v3_synthetic_integrity_20261004.json`。此项是执行者完整性核验，不是独立代码复核。

下一节点为物理fold层、模型接口和证据的独立只读复核；之后才能申请真实TRAIN数据release。独立复核及正式release仍未通过，BLIND与正式训练保持关闭。合成PASS不提供近优命中率或累计ATPG耗时改善的科学证据。
