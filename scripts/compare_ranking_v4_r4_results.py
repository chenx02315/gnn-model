"""Create-once, local-only comparison of the sealed complete r4 TRAIN run."""
import hashlib
from contextlib import closing
import json
import sqlite3
from pathlib import Path

from scripts.compare_ranking_v4_r3_results import (
    BASELINES, NONEXHAUSTIVE_EXCLUDED_FAMILY, _v3_rows, _v4_rows,
    compare, verify_v3_manifest_agreement,
)

INPUTS = {
    'v4': ('data/manifests/ranking_v4_r4_train_results_20261005.json',
           '55253ab1685b683dc93469407ac4422d57cc142f07e836497a943e02ad74e353'),
    'v3': ('data/manifests/ranking_v3_train_results_r2_20261005.json',
           '01468f838e4ef923b72028f8a59c2a5430d8e2b2faf13745fe87dc43806bcad8'),
    'v3_legacy': ('data/manifests/ranking_v3_train_results_20261005.json',
                  '6f3336eb3acbbf87609ceff6e26141258956e0606f861f0673721ac2d1d91660'),
}
OUTPUT = Path('data/manifests/ranking_v4_r4_fixed_comparison_20261006.json')
ARTIFACT = Path('data/manifests/ranking_v4_r4_fixed_comparison_report_20261006.json')
REPORT_SQL = '''SELECT model, SUM(seed_count) AS count, SUM(hits) AS hit_count,
SUM(hits)*1.0/SUM(seed_count) AS hit_rate,
SUM(mean_top10_regret*seed_count)/SUM(seed_count) AS mean_best_cycle_regret_at_10,
SUM(mean_charged_runtime_s*seed_count)/SUM(seed_count) AS mean_charged_runtime_s
FROM family_stats WHERE nonexhaustive=1
GROUP BY model ORDER BY hit_rate DESC, model ASC'''


def report_rows(result):
    """Execute the report's real SQL against the reviewed family summary."""
    with closing(sqlite3.connect(':memory:')) as db:
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE family_stats (family TEXT, model TEXT, seed_count INTEGER, '
                   'hits INTEGER, nonexhaustive INTEGER, mean_top10_regret REAL, mean_charged_runtime_s REAL)')
        db.executemany('INSERT INTO family_stats VALUES (?,?,?,?,?,?,?)',
            [(r['family'], r['model'], r['seed_count'], r['hits'], int(r['nonexhaustive']),
              r['mean_top10_regret'], r['mean_charged_runtime_s']) for r in result['family_rows']])
        return [dict(row) for row in db.execute(REPORT_SQL)]


def load_pinned(root, inputs=INPUTS):
    loaded = {}
    for name, (relative, expected) in inputs.items():
        path = root / relative
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('COMPARISON_INPUT_BOUNDARY')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('COMPARISON_INPUT_SHA:' + name)
        loaded[name] = json.loads(raw)
    return loaded


def build_comparison(v4, v3, legacy):
    verify_v3_manifest_agreement(v3, legacy)
    result = compare(v4, v3)
    result['schema_version'] = 'ranking-v4-r4-v3-fixed-descriptive-comparison-v1'
    result['epsilon'] = .01
    result['top_k'] = 10
    result['regret_semantics'] = 'Best cycles among all top-10, not necessarily among attempts before stop.'
    result['runtime_semantics'] = 'Frozen TRAIN replay of policy_charged_runtime_s until first hit or K; not model wall time or a new ATPG run.'
    result['generalization_boundary'] = 'TRAIN leave-one-family-out only; no VALIDATION or BLIND claim.'
    left, right = _v4_rows(v4), _v3_rows(v3)
    family_rows = []
    for family in sorted({key[0] for key in left}):
        seeds = sorted(key[1] for key in left if key[0] == family)
        models = [('v4_r4_candidate_mlp', [left[family, s, 'candidate_mlp'] for s in seeds])]
        models += [('v3_' + model, [right[family, s, model] for s in seeds]) for model in BASELINES]
        for model, rows in models:
            family_rows.append({'family': family, 'model': model, 'seed_count': len(rows),
                'nonexhaustive': family != NONEXHAUSTIVE_EXCLUDED_FAMILY,
                'hits': sum(row['metrics']['hit_at_10'] for row in rows),
                'mean_top10_regret': sum(row['metrics']['best_cycle_regret_at_10'] for row in rows) / len(rows),
                'mean_charged_runtime_s': sum(row['metrics']['charged_runtime_s'] for row in rows) / len(rows)})
    result['family_rows'] = family_rows
    return result


def report_artifact(result):
    title = 'ATPG Ranking: r4 Fixed Comparison'
    source = {'id': 'comparison', 'label': 'Sealed TRAIN comparison', 'path': str(OUTPUT).replace('\\', '/'),
              'query': {'engine': 'SQLite (Python standard library)', 'language': 'sql',
                        'sql': REPORT_SQL,
                        'description': 'Exact family-seed pairing; primary/legacy v3 metrics agree.',
                        'tables_used': ['family_stats'],
                        'filters': ['TRAIN only', 'Primary: exclude iscas89_s35932; 5 families x 3 seeds'],
                        'metric_definitions': ['Hit = cycles <= 1.01 * within-family oracle within K=10.',
                            'Charged runtime sums recorded ATPG policy cost until hit or K.',
                            'Regret is minimum cycles/oracle - 1 across the full top-10.']}}
    rows = report_rows(result)
    def md(identifier, body, sourced=False):
        return {'id': identifier, 'type': 'markdown', 'body': body,
                **({'sourceId': 'comparison'} if sourced else {})}
    values = '; '.join(f"{row['model']} {row['hit_count']}/{row['count']}" for row in rows)
    blocks = [md('title', '# ' + title),
        md('summary', '## 技术结论：完整运行不等于推荐有效\n\n'
           + values + '。v4 尚未证明能更快找到近优组合，不能进入加速或泛化结论。', True),
        md('definitions', '## 先看命中，再看耗时\n\n固定 H64/M16/F4，动作已满足 D95。'
           '近优指 cycles 不超过该家族候选最小 cycles 的 1.01 倍；最多尝试 10 个动作。'
           '耗时来自已记录的 ATPG 策略计费 wall time 回放，不是本次模型训练耗时。'
           '未命中时，即使累计耗时更小，也不能称为更快找到近优组合。', True),
        {'id': 'hit-chart', 'type': 'chart', 'chartId': 'hits'},
        md('interpretation', '## 排序质量仍然是当前瓶颈\n\n'
           '上图比较排除小型可穷举家族后的 15 项命中率。'
           '三个 seed 是同一家族的重复观测，不是三个独立电路。'
           'v4 没有非穷举命中，因此与任一基线都没有共同命中耗时配对，不能计算可信加速比。', True),
        md('methods', '## 比较方法与不确定性\n\n使用完整 r4 的 18 项结果，不拼接旧失败运行；'
           '逐 family/seed 配对固定 v3 基线，两个留存 v3 汇总必须一致。'
           '全 18 项另作描述性敏感性分析。这里是 TRAIN 内留一家族评估，未访问 VALIDATION/BLIND。'
           '不做显著性检验，不把少量家族重复 seed 当独立样本；不能据此推广到新电路。', True),
        md('next', '## 下一步：先定位失效，再决定是否补电路\n\n'
           '1. 封存本次负结果，停止无证据重复拟合。\n'
           '2. 本地检查已有特征、近优正负对构造、评分方向与归一化，区分数据不足与训练目标失配。\n'
           '3. 新模型或扩大预算前写单变量实验合同，并独立复核资源与泄漏门禁。\n'
           '4. 不凭本比较解封盲测，也不宣布 XGBoost 为最终模型。'),
        md('questions', '## 尚未回答的问题\n\n'
           '正例是否在各 TRAIN 家族中有足够特征区分度？近优对损失是否实际学到了可迁移方向？'
           '如现有家族确实缺少覆盖，再补独立电路；目前证据既不证明必须补，也不证明无需补。')]
    chart = {'id': 'hits', 'title': '非穷举 TRAIN 近优命中率',
             'subtitle': '5 个家族 × 3 个固定 seed；K=10，ε=1%', 'showDescription': True,
             'type': 'bar', 'intent': 'comparison', 'question': '各固定方案在相同家族和 seed 下命中了多少次？',
             'rationale': 'Four same-denominator categories; bar chart compares rates without implying time trends.',
             'dataset': 'primary', 'sourceId': 'comparison', 'source': source,
             'encodings': {'x': {'field': 'model', 'type': 'nominal'},
                           'y': {'field': 'hit_rate', 'type': 'quantitative', 'format': 'percent'}},
             'valueFormat': 'percent', 'layout': 'full'}
    return {'surface': 'report', 'manifest': {'version': 1, 'surface': 'report', 'title': title,
            'generatedAt': '2026-10-06', 'blocks': blocks, 'charts': [chart], 'sources': [source]},
            'snapshot': {'version': 1, 'status': 'ready', 'datasets': {'primary': rows}},
            'sources': [source], 'package_info': {'report_specification': 'technical-report',
                'structure_note': 'Technical summary, definitions, results, methods/limitations, next steps, open questions.',
                'chart_contract': 'Comparison/bar; 4 categories; single blue root; no redundant color legend; zero baseline.',
                'input_sha256': {name: value[1] for name, value in INPUTS.items()}}}


def write_once(outputs):
    if any(path.exists() or path.is_symlink() for path in outputs):
        raise FileExistsError('R4_COMPARISON_CREATE_ONCE')
    for path, payload in outputs.items():
        with path.open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2) + '\n')


def main():
    root = Path(__file__).resolve().parents[1]
    loaded = load_pinned(root)
    result = build_comparison(loaded['v4'], loaded['v3'], loaded['v3_legacy'])
    result['input_sha256'] = {name: value[1] for name, value in INPUTS.items()}
    write_once({root / OUTPUT: result, root / ARTIFACT: report_artifact(result)})
    print(json.dumps({'status': 'PASS_FIXED_LOCAL_COMPARISON', 'outputs': [str(OUTPUT), str(ARTIFACT)]}))


if __name__ == '__main__':
    main()
