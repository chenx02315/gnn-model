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
