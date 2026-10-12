# TRAIN v3 接续点：固定18项完成，独立有界产物审计通过

2026-10-12更新：随后获授权的18模型只读数值复算也已完成，分数/完整排序/原指标精确一致，39份回执独立审计通过。见 `docs/ranking_v5_existing_train_numerical_verification_20261012.md`；原训练额度不重置，新复算额度已消费。当前下一节点是七列输入的TRAIN-only信息支持检查，计划见 `docs/ranking_v5_feature_context_next_plan_20261012.md`，不新增模型加载、标签读取或训练。

用户在修复封存后的下一步提案后回复“授权”，随后再次回复“授权，继续”。范围已记为全新 `/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2` 中、全部实现/测试/独立复核/新鲜门禁通过后的一次固定18项TRAIN。单worker/单线程、RSS1GiB、AS8GiB、1800秒每fit、零自动重试、首失败停止保持；其他角色与额外optimizer smoke不开。

## 最新实际执行状态（2026-10-12）

- 主代理报告本次执行所用同步版本为 `cdbd0cf`。新版本包在固定 `/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2` 实际部署及读回通过：精确45源码、15证据、18envelope，共80项，另有1份0600外部trust；原始部署回执SHA `827d491de6a2e8e3a76bf119817d13c5bd78e7fd9e13e39e2e2e44375c5ddee1`，读回回执SHA `aa121865b037ac44a8bca0898322d56d8e933818ea058051157bdafe0cc50938`。
- 新鲜只读门禁通过，观察时间 `2026-10-11T16:26:40Z`（北京时间2026-10-12 00:26:40），检查75个尚不存在的输出目标、新once尚不存在、现有锁可获取并释放、资源/运行环境与固定来源。回执SHA `96c237c004e224a668b13b0af9107e2f0c1778500a00537cbdb661da20e98d67`。这是启动前观察，不是持续资源保留。
- 独立prelaunch review绑定准确部署/读回原始回执、fresh回执和gate源码及parent/CLI/receiver/新授权/packet/trust；review SHA `4670a8f5ceef5346356f8199f895b9e623550beb5a5f9dd378957117f127dd2d`，新鲜门禁有效期600秒。旧release/旧once不是本次启动权限。
- 本次仅一次授权固定18项TRAIN启动，实际launcher返回 `exit_code=0`、stderr空。父进程stdout状态 `PASS_ACTUAL_SERIAL_TRAIN_ARTIFACT_BINDING`，报告完成18、剩余0、failed_index=null、workers=1、automatic_retries=0；18组family/seed恰好覆盖既定六家族×三seed，各组均报告fit边界admission和四文件产物完整性检查通过。原始回执 `../runtime_training_staging_20260928/v5_serial_launch_result_20261012_r3.json` 为17279字节，SHA `b549685a8d3f2e7533f8b89f0febad109936a128f73fb7aef9abce5dc6b1ba1b`。
- 18组父进程报告中的最大采样combined RSS为555429888字节（约529.7MiB）。策略仍为RSS1GiB、AS8GiB、每fit1800秒、单worker/单线程、零重试；采样RSS不是硬cgroup上限，也不覆盖采样间隙的瞬时峰值。
- 新一次性额度已经由本次父启动消费；旧失败及旧once保留，不能再次启动、清once或用额度重置绕过。任何额外TRAIN或重试需要新的明确授权。
- **独立运行后读回通过**：固定110项为matrix final、新once，以及18组memory/admission/worker receipt原始JSON和model/freeze/fitting仅流式SHA。共56份原始JSON，239009字节，SHA `a81a30341c0f0e6b90435b7b4417c39b6ed23db33dbb9fcf1aad7778e1d6534c`；独立复核18份完整admission、18份完整guard receipt、72个产物摘要与父记录一致。未下载worker stdout、fitting全文、模型或freeze全文。此为完整性审计，不是数值预测或held成绩验证。
- checkpoints与完整产物保留在B固定root及18个输出目录，不把模型下载到本地，也不加载checkpoint。尚未验证数值预测或held指标，不作ATPG加速、优于基线或模型效果主张；BLIND/VALIDATION/PILOT/LSF/Tessent及额外optimizer smoke未因这次成功开放。结果事实manifest见 `data/manifests/ranking_v5_train_v3_actual_result_20261012_r1.json`。

## 历史实现与门禁状态（保留，非最新执行状态）

以下为本次实际启动之前的历史接续记录；其中“尚未部署/运行/消费”等描述均属于当时节点，不覆盖上面的最新状态。

- 本轮恢复时HEAD及origin/main为 `5fe6e0f13cd6f9c5328facd472d496579c09ddba`。新v3实现/门禁正在封存，尚未部署，未消费新TRAIN额度；后续版本以真实git为准。
- 新授权合同已独立只读核对，旧授权/core完整性校验与新一次性运行额度分离。新run_binding_review必须同时绑定新授权和准确源码/证据map，不能把旧release当作已复核v3。
- 2026-10-12 子代理额度已恢复，child/parent/packet/JIT v3 与四组测试均已落盘。主代理四模块 focused 测试实际运行73项、4项Windows能力skip、exit0；不当Linux PASS。
- 完整授权/once/source/sidecar链已独立只读复核 PASS_IMPLEMENTATION_ONLY；新TRAIN尚未运行。父入口0600新once在global lock内、package I/O前消费；child认证全部六份新freeze源码但仅加载三份。
- 准备器8项mock负测试通过：空Linux来源、任意新增fixture、Linux skip、布尔testsRun、改名测试、回归漏builder、输出冲突均拒绝且零写入；合法mock只产生被拦截的prospective request，不签发实际review。
- 完整本地回归 r1 实际1403项、44项Windows skip、1 error、0 failure、exit1，256.950秒；错误为父测试完整旧core加载时 `V5_FENCE_PRELOADED_HEAVY`。focused独立进程通过但full suite缓存有heavy模块，须只修测试隔离、不得弱化生产fence。原始日志SHA `f556254ebdcdcc1093a7989b76f7c6f2c055c6a995225170352f257d8b94d507`，证据 `../runtime_training_staging_20260928/v5_train_v3_full_regression_20261012_r1.*` 保留。
- 第二次独立复核发现packet `build(output)`首次I/O前缺纯词法protected/canonical输出拒绝；实际固定staging未触碰保护目录。最小修复已落盘：共享纯词法校验提前拒绝；父测试临时隔离heavy/local缓存并逐identity完整恢复，生产fence未修改。主代理修复后四模块实际76项/4Windows skip通过，准备器8项mock通过；等待新鲜独立复核、full r2和Linux实际门禁。
- 修复后Linux合成非ML driver/plan r2 已复核并在B普通隔离unitroot实际执行通过：76 tests、0 skip/error/failure、exit0；Python3.11.2、kernel6.1.0-47-amd64、GNU sort9.1。原始回执 `../runtime_training_staging_20260928/v5_train_v3_linux_unit_result_20261012_r2.json` SHA `ee7eba8880823fbf0d7b1f4076e2a1c7d24a283b8c375be92ca7aae65149f74e`；独立证据核验来源57项、76精确test IDs、plan/archive/rawlog SHA一致。此不是实际ML/内存证明，不签发formal runreview。
- full r2 实际1406项、44项Windows能力skip、0 error/failure、exit0；源码开始/结束/当前59项快照一致，独立回执审计通过。原始回执SHA `8936a135c7a517f6d91b67da9f2f23a5e7f4f443f2833474a79072a7677bd53f`，日志SHA `c418009ba2cb0a796512c3a09b3beccd6d5b0c97bf22e7db02148fc132d2a183`。Linux重合51项rawpin一致；不以Windows skip充当Linux通过。
- prospective精确绑定请求已生成 `../runtime_training_staging_20260928/v5_serial_train_review_request_20261011_r3.json` SHA `f2773d5f744f46bd223db9edc05f1705e04bd82bed8461d3810d438c78aefd58`：45源码/14证据，待独立审计8字段subject；不是实际release。
- 本轮B端仅1次非ML合成unit SSH；正式训练包读取、部署、optimizer、TRAIN均为0。历史失败证据、旧once与受保护目录不动。

## 历史接续文件与SHA快照

| 文件 | SHA-256 |
| --- | --- |
| contracts/ranking_v5_freeze_v2_fresh_train_authorization_20261011_r1.json | 78d34a96962c4e0cc87d3ccfb47beae5f699418a9ed34d717d0b19081e1c8d9c |
| contracts/ranking_v5_train_v3_execution_plan_20261011_r1.json | c2416b1b6d2c5e4e01fd36f1801886b681cbc6e9017dbc83e791867c2f4edd76 |
| scripts/run_v5_train_serial_parent_v3.py | 9c354487a957bc32520b4565786db3458b744f3e73b43c2632d8983ca46860b5 |
| scripts/run_v5_train_single_fit_v3.py | 1b22f4f58b645e180ed2f9c5afdffa39a04fe12fa2d93e35b697fdf947d3544a |
| scripts/v5_train_launch_packet_v3.py | 4a08416bf584809c1e1896346e7fc6dcee1ff7e7ed9e7db0300097eefafad9a4 |
| src/models/ranking_v5_train_jit_admission_v3.py | c1104f613a92c6315fe09495d4995c7755827294cf69e92564ce8d51785de30d |
| tests/test_ranking_v5_train_jit_admission_v3.py | ce45c056b1d79e426acf0228488fc456812771df070cacf4c9a54b0408ae755b |
| ../runtime_training_staging_20260928/prepare_v5_train_v3_packet_20261011_r1.py | 1599fcedfca43ba7f1e67824befa438f2f48590575ba983f11e9c8f6c2a5a202 |

这些是当时的接续识别快照，不是正式训练结果，也不替代最新实际部署/启动回执。准备器实现与负测试、后续实际review/Linux门禁和包准备的历史节点以上文及原始证据为准。

## 已决定的接口

1. 新CLI `scripts/run_v5_train_single_fit_v3.py`；新JIT helper v3只改精确r2 task root，不扩大临时导入规则。HELPERS新增冻结loader。
2. child在任何新源码compile前用已封存loader的validate_sources认证全部六份freeze源码，但只在新模块名加载codec/store/worker；不创建旧CLI别名，不修改旧core。
3. parent仍处于原sealed core，维持既定stable CLI alias，仅此处认证加载全部六份新freeze链，并保留旧serial_matrix。不替换旧module identity。
4. v3 envelope/sidecar绑定六源码map、loader SHA、新run AUTH、新review、source/evidence digest。parent/packet从完整map推导digest，child核验独立pin的同一绑定。
5. `validate_run_authorization(raw, *, trusted_run_authorization_sha256, source_root)`严格匹配新合同；`validate_run_binding_review(raw, *, trusted_review_sha256, source_root, source_binding_sha256, legacy_evidence_binding_sha256)`严格8字段。
6. run_binding_review字段：schema=`v5-fresh-train-run-binding-review-v1`、status=`PASS_V5_FRESH_RUN_BINDING_REVIEW`、scope、source_root、run_authorization_sha256、core_manifest_sha256、source_binding_sha256、legacy_evidence_binding_sha256。后者是全部evidence map排除review自身的规范JSON digest；review subject不含最终packet/archive SHA，避免循环。
7. 新once固定 `/ssd/cjc/gnn_model_ranking_v5_train.authorization_78d34a96962c4e0cc87d3ccfb47beae5f699418a9ed34d717d0b19081e1c8d9c.once.json`；parent在global lock下、任何package I/O前独占创建0600，child只验证不消费。
8. once严格字段：schema=`v5-fresh-train-one-use-authorization-v1`、source_root、run_authorization_sha256、run_authorization_id、source_binding_sha256、packet_sha256、planned_fits=18、automatic_retries=0。child读当前root的launch_packet.json并核packet原始SHA/map digest与review一致，不在envelope中加入自指packet SHA。
9. 预计精确运输45源码/15证据/18envelopes+2=80项，必须从最终源集合复核而不是信任估算；原256KiB压缩/1MiB解包/64KiB单源码上限不变。

## 当时约定的连续执行链（执行及产物审计已完成，保留历史）

读取真实git/未提交文件与本快照 → 完成CLI/parent/packet及测试 → 独立交叉只读复核 → focused/full回归 → 新版Linux合成非ML门禁（零skip） → 精确包/新授权绑定独立review → 小包SHA与有界新目录部署/读回 → 新鲜内存/环境/新once检查及独立prelaunch → 一次固定18TRAIN → 有界回执独立审计/版本同步。

这条链的一次固定18项TRAIN及有界产物审计已完成。既有日志只读诊断也完成：非协议保证命中家族拟合命中64/75，但已有TRAIN LOFO回执仍为0/15；均为worker报告值，不是独立数值验证。详见 `docs/ranking_v5_fitting_diagnostic_20261012.md`。接续工作先设计TRAIN-only冻结预测/指标复算门禁，再诊断跨电路特征；不再次TRAIN或扩大角色。模型加载、新标签读取、新训练、重试或新数据角色必须另行取得对应明确授权。
