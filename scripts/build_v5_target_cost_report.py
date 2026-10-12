"""Pinned aggregate report, no real-label loader or model/training entry."""
import hashlib
import json
from pathlib import Path
import sqlite3

REPO=Path(__file__).resolve().parents[1]
STAGING=REPO.parent/'runtime_training_staging_20260928'
ACTUAL_SHA='eb114f05de91998778c2b97fd6f328d506847e0936dd225f9d5869f41ba55eb2'


def main():
    raw=(STAGING/'v5_target_cost_actual_20261012_r1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ACTUAL_SHA:raise ValueError('RESULT_SHA')
    receipt=json.loads(raw)
    result=receipt['result']
    if receipt['status']!='PASS_GUARDED_TRAIN_TARGET_COST_DIAGNOSTIC' or result['primary_online_cost_replay'] is not False:
        raise ValueError('RESULT_SCOPE')
    rows=[]
    for family,x in result['families'].items():
        rows.append({'circuit':family.split('_',1)[1],'family':family,'actions':x['action_count'],
                     'positives':x['positive_count'],'positive_rate':x['positive_rate'],
                     'hf_positive':x['by_scheme']['HF']['positive_count'],
                     'hmf_positive':x['by_scheme']['HMF']['positive_count'],
                     'rho':x['spearman_cycles_vs_policy_charged_runtime']['rho'],
                     'positive_median_s':x['policy_charged_runtime_s']['positives']['median'],
                     'overall_median_s':x['policy_charged_runtime_s']['overall']['median']})
    family_sql='SELECT * FROM family_metrics ORDER BY actions DESC'
    pair_sql='SELECT * FROM pair_metrics ORDER BY comparisons DESC, first_family, second_family'
    pairs=[]
    for x in result['pairwise_grid_directions']:
        pairs.append({'first_family':x['first_family'],'second_family':x['second_family'],
                      'common_keys':x['common_unique_key_count'],'comparisons':x['unordered_key_pair_count'],
                      'concordant':x['directions']['concordant'],'discordant':x['directions']['discordant'],
                      'coverage_first':x['first_unique_key_coverage'],'coverage_second':x['second_unique_key_coverage']})
    with sqlite3.connect(':memory:') as connection:
        connection.row_factory=sqlite3.Row
        connection.execute('CREATE TABLE family_metrics(circuit TEXT,family TEXT,actions INTEGER,positives INTEGER,positive_rate REAL,hf_positive INTEGER,hmf_positive INTEGER,rho REAL,positive_median_s REAL,overall_median_s REAL)')
        connection.executemany('INSERT INTO family_metrics VALUES(?,?,?,?,?,?,?,?,?,?)',[tuple(x.values()) for x in rows])
        connection.execute('CREATE TABLE pair_metrics(first_family TEXT,second_family TEXT,common_keys INTEGER,comparisons INTEGER,concordant INTEGER,discordant INTEGER,coverage_first REAL,coverage_second REAL)')
        connection.executemany('INSERT INTO pair_metrics VALUES(?,?,?,?,?,?,?,?)',[tuple(x.values()) for x in pairs])
        rows=[dict(x) for x in connection.execute(family_sql)]
        pairs=[dict(x) for x in connection.execute(pair_sql)]
    source={'id':'diagnostic','label':'固定TRAIN目标/费用聚合诊断（2026-10-12）',
            'path':'data/manifests/ranking_v5_target_cost_metrics_20261012_r1.json',
            'query':{'engine':'SQLite','language':'sql','sql':family_sql,'tables_used':['family_metrics'],
                     'description':'先由已认证31个TRAIN文件的Python诊断产生聚合，再在六行内存表投影排序；无新标签读取。实际回执SHA '+ACTUAL_SHA,
                     'metric_definitions':{'positives':'100*cycles<=101*同家族全部正式HF/HMF动作最小cycles；重复投影只计一次',
                         'rho':'家族内cycles和历史策略应计费用的Spearman相关，平均并列秩；不是因果',
                         'positive_median_s':'近优候选的历史策略应计费用中位数；不是在线命中前缀总耗时'}}}
    pair_source={**source,'id':'grid_directions','query':{**source['query'],'sql':pair_sql,'tables_used':['pair_metrics'],
                 'description':'仅相同方案和精确相对H/M限额键的跨家族连接；15对家族的聚合计数投影，禁止插值/最近邻补齐。'}}
    lineage={'id':'cost_lineage','label':'费用口径：完整调用均值与前缀复用限制',
             'path':'contracts/runtime_action_cost_aggregation_v1.json',
             'query':{'description':'build_runtime_training_package_v2.py要求ARITHMETIC_MEAN_ALL_INVOCATIONS并投影wall_time_mean_s。runtime_policy_v1允许会话内H/HM前缀复用；v2不修改该规则。静态标签不是当前在线执行或逐顺序增量成本。'}}
    def md(name,body,source_id=None):
        value={'id':name,'type':'markdown','body':body}
        if source_id:value['sourceId']=source_id
        return value
    title='TRAIN Target and Cost Diagnostic'
    blocks=[md('title','# '+title),
            md('summary','## 先对齐首次命中目标，不原样重训\n\n1706个唯一候选中只有14个cycles近优正例（约0.82%）。正例方案随家族变化：SPI仅HF，s15850/s38417仅HMF。费用与cycles没有跨家族通用的单调对应；不能只学“便宜”或把Top10命中当作累计耗时优化。', 'diagnostic'),
            md('scope','## 命中条件、费用和比较分母分别固定\n\n对象是固定六TRAIN家族，不包含BLIND/VALIDATION/PILOT。ε仍为1%，oracle是同家族全部HF/HMF正式动作的最小cycles，K仍为10。HF/HMF分组也沿用共同oracle，不重新定义更容易的方案oracle。31个认证文件的六折重复投影只用来检查一致性，1706个动作只计一次。', 'diagnostic'),
            md('scarcity','## 少量正例要求保留家族分母\n\n下图显示每个家族的近优正例数量；下表同时显示候选总数与正例率。SPI只有1/736，s13207和s15850各有2个；s35932只有10个候选，整族负例9个，因此全量无放回Top10命中有规模保证，并不是跨电路模型迁移成功的证据。不能把全負例方案也判为保证命中。', 'diagnostic'),
            {'id':'positive_chart','type':'chart','chartId':'positive_counts'},
            {'id':'family_table','type':'table','tableId':'families'},
            md('cost','## 相关符号不同，不能用一个费用排序替代近优识别\n\n家族内cycles/费用Spearman相关从约−0.265到0.758，SPI约0.043。表中正例费用是单个候选历史费用标签的中位数，不是找到首个正例的总成本。相关性不能证明哪一个模型能提速，更不能作为换epsilon/K的依据。', 'diagnostic'),
            md('grid','## 可比网格太稀，反向偏好只能作为局部线索\n\n15对家族中，仅3对有至少两个精确共同键；共19个无序候选对，7个方向一致、12个方向相反。其余12对只有一个共同键，不能比较排序方向。s13207/AES的6个共同键仅覆盖各自295/350候选中的约2%；不能把12/19推成全网格或总体迁移失败率。这些比较也并非独立样本。', 'grid_directions'),
            {'id':'grid_table','type':'table','tableId':'grid_pairs'},
            md('meaning','## 静态费用标签不能证明在线前缀耗时\n\n费用来自每次调用全部已映射attempt墙钟费用之和，再对同一动作完整调用取算术平均；不取fastest-success，不丢失败/重试，也不把ATE cycles或CPU time代替墙钟费用。现有合同允许会话内前缀复用，本次outcome没有逐顺序restore/materialization成本，所以未做在线累计费用重放，也没有新跑Tessent。', 'cost_lineage'),
            md('method','## 只做描述性诊断，不改模型与阈值\n\n连接为精确UID和SHA，六折元数据、七维输入及标签一致；Spearman采用平均并列秩，常量或不足样本返回带原因的null；共享网格键为方案、相对H限额和相对M限额的精确值，歧义键单独统计，不插值。未修改旧trainer/loss或训练参数；没有模型加载、训练、调参或新ATPG作业。'),
            md('limits','## 本次没有测得提速，也没有证明表示不可迁移\n\n结果为冻结历史TRAIN数据的诊断，不是未来新电路泛化或因果实验。独立审计核对聚合及回执一致性，并未从原始标签重算全部统计，也未重新审计原始attempt日志。正式候选集合最终状态均为SUCCESS+D95可行，不能估计失败候选率；费用可能含失败/重试attempt成本，是另一粒度。\n\n规模/结构代理尚未做新消融；相对网格位置相同不代表绝对规模相同，七维实际输入也不完全相同。不能用局部反向cycles排序宣称现有表示必然无解。报告结构验证不等于浏览器交互验证。'),
            md('next','## 下一步先冻结最小目标对照，再分离上下文升级\n\n优先用相同七列和scorer定义“更早命中”的目标对照；费用仅作为显式标注的静态历史代理。将电路上下文作为另一条消融轴，不同时换目标、图网络和成本策略。14个正例不足以预先宣称概率已校准，p/费用排序只在相应假设成立后作为待验证基线。任何新训练、图原文读取和在线费用重放仍不在当前权限内。'),
            md('questions','## 仍需独立验证的关键问题\n\n首次命中目标能否改善非保证命中家族，而非只在拟合样本得分？加入规模或结构上下文能否产生增量效果？若要证明在线耗时下降，如何获得可审计的会话顺序、前缀命中与restore成本？这些问题不能靠原样重跑或当前静态标签补算解决。')]
    artifact={'surface':'report','manifest':{'version':1,'surface':'report','title':title,'sources':[source,pair_source,lineage],
              'blocks':blocks,'charts':[{'id':'positive_counts','type':'bar','title':'各家族 cycles 近优正例数',
                'dataset':'families','source':source,'sourceId':'diagnostic',
                'encodings':{'x':{'field':'circuit'},'y':{'field':'positives'}},'options':{'orientation':'horizontal'}}],
              'tables':[{'id':'families','title':'家族内近优结构与历史费用','dataset':'families','source':source,
                'columns':[{'field':f,'label':l} for f,l in [('circuit','电路'),('actions','候选'),('positives','近优'),
                    ('positive_rate','近优比例(0–1)'),('hf_positive','HF近优'),('hmf_positive','HMF近优'),
                    ('rho','cycles/费用ρ'),('positive_median_s','近优费用中位秒'),('overall_median_s','全部费用中位秒')]],
                'defaultSort':{'field':'actions','direction':'desc'}},
                {'id':'grid_pairs','title':'精确共同网格的覆盖及方向','dataset':'grid_pairs','source':pair_source,
                 'columns':[{'field':f,'label':l} for f,l in [('first_family','家族A'),('second_family','家族B'),
                     ('common_keys','共同键'),('comparisons','可比候选对'),('concordant','同向'),('discordant','反向'),
                     ('coverage_first','A覆盖(0–1)'),('coverage_second','B覆盖(0–1)')]],
                 'defaultSort':{'field':'comparisons','direction':'desc'}}]},
              'snapshot':{'version':1,'status':'ready','datasets':{'families':rows,'grid_pairs':pairs}},
              'sources':[source,pair_source,lineage]}
    output=STAGING/'target_cost_20261012';output.mkdir(exist_ok=True)
    with (output/'artifact.json').open('w',encoding='utf-8') as f:json.dump(artifact,f,ensure_ascii=False,indent=2,allow_nan=False)
    metrics=REPO/'data/manifests/ranking_v5_target_cost_metrics_20261012_r1.json'
    if metrics.exists():
        if json.loads(metrics.read_bytes())!=result:raise ValueError('EXISTING_METRICS_CHANGED')
    else:
        with metrics.open('x',encoding='utf-8') as f:json.dump(result,f,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)
    print(str(output/'artifact.json'))


if __name__=='__main__':main()
