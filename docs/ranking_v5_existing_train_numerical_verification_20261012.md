# v5：18份冻结模型只读复算通过

本次用户授权是在原内存上限内，只读加载已有18份TRAIN权重，复算冻结预测及指标，不重训、不访问BLIND。授权记录为 `contracts/ranking_v5_existing_train_replay_authorization_20261012_r1.json`，基于线程中的真实答复，不把合同自称当作许可。

## 已实际执行

- 六家族×三个seed，18/18复算成功。`weights_only=True`、CPU、单worker/单线程，零optimizer、零训练、零自动重试。
- 每个checkpoint的六个tensor keys、shape、float32、CPU与有限值先验证；完整分数、排序、UID连接和payload SHA与原freeze逐项精确一致。未用容差放行。
- 只有上述精确一致后，才读取原固定TRAIN held outcomes；近优命中、尝试次数、cycle regret及累计 `policy_charged_runtime_s` 与原worker指标逐字段精确一致。
- 每个任务结束重新流式核对model/freeze/fitting/worker receipt四文件SHA；旧产物和旧训练once不写入。新验证目录 `/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1` 只留临时JIT文件、小型日志和回执，模型仍在原B目录。
- 峰值采样combined RSS为528633856字节，约504.1MiB，低于1GiB。AS仍8GiB，每任务1800秒；采样RSS不是硬cgroup上限，不能排除采样间隙的瞬时峰值。

本地完整回归1468项、48项Windows能力skip、零错误/失败；Linux专属无ML测试实际62项、零skip、gate_pass=true。实际模型推理在源码/环境/资源/新授权与独立预启动审计通过后执行，不把mock或skip当作数值验证。

实际父结果回执SHA `583734cd5904ea23329faea854747cf8e28933c593ab63c05fcfcdc769c09d98`；运行后39份原始小型回执/日志读回82849字节，SHA `a824f81c1b5c3ebd163d0c899c2374e4608a3f0f8fd60802e28d472960dacc5c`。最终独立审计通过：39份原文长度/SHA、18份严格child和18份guard、matrix/started/once及18组指标全部一致，详见同名结果manifest。实现和真实测试门禁由原独立复核代理审核；其后额度不足，最终39回执的机械核对改由轻量独立代理完成，没有冒称其重新加载权重或复跑推理。

## 对论文目标意味着什么

五个非保证命中家族的TRAIN留出仍为0/15；s35932的3/3由“负例数少于K”保证，不能作为非平凡泛化效果。这里的留出指标已经通过冻结权重与标签复算，不再只是worker报告提示。

拟合内64/75仍来自已审计训练日志，而本次独立前向复算的是留出冻结预测。不要把两者说成同一种证据，也不要把15个相关观察当作独立统计样本。当前没有证据证明减少了命中D95安全近优组合前的累计ATPG时间。

## 已确定的下一节点

不原样重训、不立即增加电路。先盘点当前七列输入是否表达电路差异，设计TRAIN-only特征/上下文检查：联合分布、候选响应的电路条件化和图摘要可用性。先做本地源码与合同设计，不增加模型加载次数，不读取新的BLIND/VALIDATION/PILOT标签；任何新训练须另行取得对应授权。

依赖metadata及固定源码已核验，但没有宣称把所有原生库内容或整台主机封成安全沙箱。Git只收代码、合同、小型指标和SHA，权重及原始较大回执继续留在B/本地staging。
