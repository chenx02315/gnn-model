"""Materialize reviewed report source rows from hash-verified TSVs in SQLite."""
import json
import sqlite3
import sys
from pathlib import Path
from src.audit.diagnose_runtime_v2 import EXPECTED, read_verified

SQL = '''SELECT r.role, r.circuit, r.action_uid, r.action_scheme,
       CAST(o.epsilon_hit AS INTEGER) AS epsilon_hit,
       CAST(o.total_cycles AS REAL) AS total_cycles,
       CAST(o.policy_charged_runtime_s AS REAL) AS runtime_s,
       CAST(r.predicted_epsilon_hit_probability AS REAL) AS predicted_probability,
       CAST(r.predicted_cycles AS REAL) AS predicted_cycles,
       CAST(r.predicted_runtime_s AS REAL) AS predicted_runtime_s,
       CAST(r.cost_aware_score AS REAL) AS cost_aware_score
FROM ranking r JOIN outcomes o ON r.action_uid = o.action_uid
WHERE r.role IN ('TRAIN', 'VALIDATION')
ORDER BY r.role, r.circuit, r.action_uid'''

def query(root, ranking_name='ensemble_ranking.tsv'):
    con = sqlite3.connect(':memory:')
    con.row_factory = sqlite3.Row
    outcomes = sum((read_verified(root/n, EXPECTED[n]) for n in ('train_outcomes.tsv','validation_outcomes.tsv')), [])
    ranking = read_verified(root/ranking_name,EXPECTED[ranking_name])
    for name, rows in [('outcomes',outcomes),('ranking',ranking)]:
        fields=list(rows[0])
        con.execute('CREATE TABLE '+name+' ('+', '.join(fields)+')')
        con.executemany('INSERT INTO '+name+' VALUES ('+','.join('?' for _ in fields)+')',
                        [[r[f] for f in fields] for r in rows])
    rows=[dict(r) for r in con.execute(SQL)]
    assert len(rows)==2521
    con.close()
    return {'query':SQL,'ranking_file':ranking_name,'row_count':len(rows),'preview':rows[:10]}

if __name__ == '__main__':
    print(json.dumps(query(Path(sys.argv[1]),sys.argv[2] if len(sys.argv)>2 else 'ensemble_ranking.tsv'),indent=2))
