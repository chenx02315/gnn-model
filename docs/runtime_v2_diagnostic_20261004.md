# runtime v2 诊断回执与后续边界

本轮只读诊断 TRAIN/VALIDATION 的冻结三 seed ensemble；未训练、调参、改动原模型，未访问 BLIND、A、LSF、Tessent 或受保护目录。

## 核心结果

- TRAIN 正例14/1706，VALIDATION正例3/815。正例定义保持同电路已测oracle cycles的1%内，正式预算保持10。
- GraphSAGE 成本排序首次命中：s5378第93、tv80第287；XGBoost：第227、第268。原正式top10全部零命中已复现。
- 去除runtime分母，首次命中仍分别是GraphSAGE第99/289、XGBoost第175/281；因此成本分母不是足以解释零命中的主因。
- XGBoost在TRAIN六电路的概率/成本首次命中均第1，VALIDATION显著失效，提示跨家族泛化不足。GraphSAGE在tv80的cycles Spearman为−0.466。
- 不把训练排序当泛化证据，不把未命中的低累计耗时称为加速。只有两个验证家族、三个正例，不能做强统计结论。

## 交付与验证

- 可复现脚本：`src/audit/diagnose_runtime_v2.py`；输入四个TSV必须匹配内置SHA-256。
- 汇总：`data/manifests/runtime_v2_diagnostic_20261004.json`，包含逐电路正例比例、预测误差和首次正例排名。
- 查询源：`src/audit/query_runtime_v2_diagnostic.py`；SQLite唯一连接2521动作，输入分别验证hash。
- 五项单元测试通过；正式三方法的验证top10成本与已封存manifest逐项一致。
- 中文可视报告位于仓库外本地staging：`runtime_training_staging_20260928/diagnostic_20261004/report.html`。规范校验与结构校验通过；环境没有Chromium，浏览器视觉及交互未验证。不是独立复核回执。

## 下一阶段建议（尚未执行训练）

1. 冻结本负结果、1%近优标准及K=10。
2. 在TRAIN六家族内部留一家族验证，定位尺度、特征和家族不平衡；不能反复用现有VALIDATION调参。
3. 新合同优先比较连续质量监督与pairwise/listwise排序、家族均衡采样；oracle归一化只可用于训练标签，禁止作为推理特征。
4. 先证明非图排序基线能泛化，再检查图结构增益；成本策略和质量排序分开验证。
5. 新合同、泄漏门禁、公平基线独立复核通过后才考虑新正式训练；不自动解封BLIND。

确定机制需消融实验；本轮仅识别关联与排除“只改runtime分母即可解决”的解释。
