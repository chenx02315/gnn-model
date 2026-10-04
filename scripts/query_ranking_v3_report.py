"""Reproduce report chart rows through explicit local SQLite aggregation."""
import json
from pathlib import Path
import sqlite3
from scripts.collect_ranking_v3_results import validate

def main():
    payload=json.loads(Path('data/manifests/ranking_v3_train_results_20261005.json').read_bytes())
    validate(payload)
    con=sqlite3.connect(':memory:')
    con.execute('CREATE TABLE frozen_evaluations(model TEXT, hit INTEGER, charged_runtime_s REAL, regret REAL)')
    rows=[r['data'] for k,r in payload['records'].items() if k.endswith('/evaluation.json')]
    con.executemany('INSERT INTO frozen_evaluations VALUES (?,?,?,?)',[(r['model'],r['metrics']['hit_at_10'],r['metrics']['charged_runtime_s'],r['metrics']['best_cycle_regret_at_10']) for r in rows])
    con.row_factory=sqlite3.Row
    query=Path('docs/ranking_v3_report_query.sql').read_text(encoding='utf-8')
    print(json.dumps([dict(r) for r in con.execute(query)]))

if __name__=='__main__':
    main()
