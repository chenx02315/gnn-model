"""Build an aggregate-only canonical portable report from the pinned receipt."""
import hashlib
import json
from pathlib import Path
import sqlite3

REPO=Path(__file__).resolve().parents[1]
STAGING=REPO.parent/'runtime_training_staging_20260928'
ACTUAL_SHA='03e678928924343622760939fe1252ab06bb787d199adb8a9511ee5813b074fd'


def main():
    raw=(STAGING/'v5_feature_support_actual_20261012_r1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ACTUAL_SHA:
        raise ValueError('RESULT_SHA')
    data=json.loads(raw)
    result=data['result']
    if data['status']!='PASS_GUARDED_FEATURE_ONLY_RUN' or result['labels_read'] is not False:
        raise ValueError('RESULT_SCOPE')
    rows=[]
    for family,fold in result['folds'].items():
        rows.append({'circuit':family.split('_',1)[1], 'family':family,
                     'action_count':fold['heldout_count'],'fit_count':fold['fit_count'],
                     'hf_count':fold['nearest_fit_distance']['HF']['heldout_count'],
                     'hmf_count':fold['nearest_fit_distance']['HMF']['heldout_count'],
                     'hf_median':fold['nearest_fit_distance']['HF']['median'],
                     'hmf_median':fold['nearest_fit_distance']['HMF']['median']})
    sql='SELECT circuit, family, action_count, fit_count, hf_count, hmf_count, hf_median, hmf_median FROM feature_support ORDER BY action_count DESC'
    with sqlite3.connect(':memory:') as connection:
        connection.row_factory=sqlite3.Row
        connection.execute('CREATE TABLE feature_support(circuit TEXT,family TEXT,action_count INTEGER,fit_count INTEGER,hf_count INTEGER,hmf_count INTEGER,hf_median REAL,hmf_median REAL)')
        connection.executemany('INSERT INTO feature_support VALUES(?,?,?,?,?,?,?,?)',[tuple(row.values()) for row in rows])
        rows=[dict(row) for row in connection.execute(sql)]
    source={'id':'feature_support','label':'固定 TRAIN 六折特征支持诊断（2026-10-12）',
            'path':'data/manifests/ranking_v5_feature_support_metrics_20261012_r1.json',
            'query':{'language':'sql','engine':'SQLite','tables_used':['feature_support'],'sql':sql,
                     'description':'仅七列特征；按原拟合归一化计算同方案最近支持距离。原始聚合回执 SHA-256 '+ACTUAL_SHA+'；feature_support是从聚合回执派生的六行内存表，SQL仅做字段投影和排序，不替代原Python特征诊断。',
                     'metric_definitions':{'action_count':'该家族唯一 TRAIN 候选数；六家族总计1706，不按seed重复计数',
                         'nearest_distance':'每个留出候选到同HF/HMF方案拟合候选的最小七维欧氏距离；各折使用各自拟合总体标准差，下限1e-12。'}}}
    def md(name,body,sourced=False):
        value={'id':name,'type':'markdown','body':body}
        if sourced:value['sourceId']='feature_support'
        return value
    title='TRAIN Feature Support Check'
    blocks=[md('title','# '+title),
            md('summary','## 先改诊断方向，不原样重跑\n\n真实六折特征检查已完成。AES 的共同故障规模和部分 H 限额超出拟合范围；SPI 也存在规模外推。但 s13207/s15850 没有逐列超范围，不能把所有排序失败归结为范围偏移。跨家族完全相同七维向量碰撞为零。',True),
            md('definitions','## 本次只测输入支持，不测排序或 ATPG 加速\n\n对象是六个 TRAIN 家族的1706个唯一候选，每折拟合其余五家族、留出一个家族；不因三个 seed 重复计数。只读取 receipt、manifest 和两份 features。最近距离以该折拟合归一化后的七维欧氏距离计算，并限定相同 HF/HMF；没有事后选择 OOD 阈值。不同折使用不同尺度，距离不是统一风险评分。',True),
            md('weights','## 候选数不均衡会影响归一化统计权重\n\nSPI 有736个候选，s35932只有10个。在非 SPI 留出折中，SPI 占归一化候选统计权重约43%–54%。这不是损失权重；现有 head loss 按家族均值聚合。该不均衡也不是失效原因的证明。下图用于对比家族候选量，不是近优命中或运行时间。',True),
            {'id':'counts_block','type':'chart','chartId':'counts'},
            md('range','## AES 与 SPI 有外推，但另外两族不能用同一解释\n\nAES 的350/350共同故障规模代理超出拟合范围，最大绝对标准化值约5.83；106/350个H绝对限额、12/350个H相对限额也超范围。SPI 的736/736规模代理超范围，36/736个M限额超范围。s13207、s15850、s38417、s35932 的全局逐列超范围数均为零。HF/HMF均有拟合支持，没有方案完全缺席。',True),
            md('distance','## 联合支持距离提供线索，不提供因果结论\n\n下表保留各折HF/HMF中位最近距离和候选分母，便于查验。s13207/s15850 的描述性距离较小，但这不等于排序目标可迁移；特征接近的电路仍可能有不同响应。没有读取标签，所以本检查不能判断哪条排序方向正确。',True),
            {'id':'support_table','type':'table','tableId':'support'},
            md('methods','## 方法和门禁保持不变\n\n七列顺序与原模型一致；按UID排序，仅用拟合侧总体均值和标准差，下限1e-12，不clipping。六折数据逐UID/元数据/特征一致，SHA和唯一连接通过。Linux合成21项测试零跳过，真实执行单worker、零重试，采样RSS峰值约41.94 MiB，上限仍为1 GiB（AS 8 GiB）；RSS是采样监控而非cgroup硬限制。',True),
            md('limitations','## 未证明 GraphSAGE 有效，也未证明 ATPG 已提速\n\n没有读取任何标签、模型或图原文，没有训练、调参、LSF或Tessent作业。零完全碰撞只能排除“所有失败都来自精确输入别名”的解释，不能证明现有七列信息充分。未做时间序列分析：这是冻结数据的单次描述性检查，不是随时间变化的漂移评估。'),
            md('next','## 目标源码审计已接续完成，下一步核对真实目标关系\n\n源码和合成反例检查已完成：现有head只要求Top10中存在cycles近优候选，不直接优化首次命中位置或累计ATPG费用。它不是已测得的真实失效因果。\n\n1. 下一节点限定为TRAIN真实标签与费用关系诊断，需新标签读取授权，仍不开放训练。\n2. 保持家族全方案共同cycles oracle；若费用依赖cache/prefix reuse或动作顺序，不简单相加静态费用。\n3. 再设计候选特征/规模代理/结构摘要的最小消融，分别控制normalizer候选权重和macro-family损失权重；保留固定split、seed和内存限额。\n4. 只有对应合同与独立复核通过，才提出新训练；不直接扩充大批电路。'),
            md('questions','## 仍需回答的问题\n\n对接近输入的家族，近优组合的排序方向是否一致？容量/规模代理是否足以区分响应，还是需要逻辑结构摘要？加入上下文后的收益是否能转化为减少达到近优安全组合前的累计Tessent wall time，而非只改善cycles预测？')]
    artifact={'surface':'report','manifest':{'version':1,'title':title,'surface':'report','blocks':blocks,
              'sources':[source],'charts':[{'id':'counts','title':'各家族 TRAIN 候选数','type':'bar',
              'dataset':'support','sourceId':'feature_support','source':source,'encodings':{'x':{'field':'circuit'},'y':{'field':'action_count'}},
              'options':{'orientation':'horizontal'}}],
              'tables':[{'id':'support','title':'各折同方案最近距离（中位数）','dataset':'support','sourceId':'feature_support','source':source,
                         'columns':[{'field':f,'label':label} for f,label in [('circuit','电路'),('action_count','留出候选'),
                           ('fit_count','拟合候选'),('hf_count','HF候选'),('hmf_count','HMF候选'),
                           ('hf_median','HF中位距离'),('hmf_median','HMF中位距离')]],
                         'defaultSort':{'field':'action_count','direction':'desc'}}]},
              'snapshot':{'version':1,'status':'ready','datasets':{'support':rows}},'sources':[source]}
    output=STAGING/'feature_support_20261012'
    output.mkdir(exist_ok=True)
    with (output/'artifact.json').open('w',encoding='utf-8') as f:json.dump(artifact,f,ensure_ascii=False,indent=2,allow_nan=False)
    metrics=REPO/'data/manifests/ranking_v5_feature_support_metrics_20261012_r1.json'
    if metrics.exists():
        if json.loads(metrics.read_bytes())!=result:raise ValueError('EXISTING_METRICS_CHANGED')
    else:
        with metrics.open('x',encoding='utf-8') as f:json.dump(result,f,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)
    print(str(output/'artifact.json'))


if __name__=='__main__':main()
