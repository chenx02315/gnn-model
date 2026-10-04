"""Synthetic-only physical fold shards and freeze-gated held-label reader.

No production export/release exists here. Expected manifest digests must be
supplied by the caller from a separately retained receipt.
"""
import hashlib
import json
from pathlib import Path
from src.models.runtime_ranking_v3 import (
    FEATURES,digest,plan_folds,prepare_fold,freeze_ranking)
from src.models.ranking_v3_freeze_io import read_freeze

SCOPE='GENERATED_SYNTHETIC_NO_EXTERNAL_DATA'
METADATA=('action_uid','circuit','family','role')
OPTIONAL=('graph_key','action_scheme','h_limit','m_limit')

def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_once(path,value):
    with path.open('xb') as stream:
        stream.write((json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode())

def export_fixture_fold(root,rows,outcomes,fold,*,scope=None):
    # Refuse before mkdir, labels or any other file access.
    if scope!=SCOPE: raise ValueError('REAL_FOLD_EXPORT_CLOSED')
    if fold not in plan_folds(rows) or set(outcomes)!={r['action_uid'] for r in rows}:
        raise ValueError('FOLD_SOURCE_JOIN')
    fit={u:outcomes[u] for u in fold.fitting}
    prepare_fold(rows,fit,fold,20260824)
    root=Path(root)
    if any(p.is_symlink() for p in (root,*root.parents)):
        raise ValueError('FOLD_SYMLINK')
    root.mkdir(exist_ok=False)
    projected=[{f:r[f] for f in (*METADATA,*FEATURES,*OPTIONAL) if f in r}
               for r in sorted(rows,key=lambda r:r['action_uid'])]
    values={
        'fit_features.json':[r for r in projected if r['action_uid'] in fold.fitting],
        'fit_outcomes.json':fit,
        'heldout_features.json':[r for r in projected if r['action_uid'] in fold.heldout],
        'heldout_outcomes.json':{u:outcomes[u] for u in fold.heldout},
    }
    for name,value in values.items(): write_once(root/name,value)
    manifest={'schema_version':'ranking-v3-synthetic-fold','scope':SCOPE,
              'family':fold.family,'fitting':list(fold.fitting),'heldout':list(fold.heldout),
              'sha256':{name:file_sha(root/name) for name in values}}
    write_once(root/'manifest.json',manifest)
    return file_sha(root/'manifest.json')

class FoldReader:
    def __init__(self,root,expected_manifest_sha,fold):
        self.root=Path(root); self.fold=fold
        if any(p.is_symlink() for p in (self.root,*self.root.parents)):
            raise ValueError('FOLD_SYMLINK')
        path=self.root/'manifest.json'
        if path.is_symlink() or file_sha(path)!=expected_manifest_sha:
            raise ValueError('FOLD_MANIFEST_SHA')
        self.manifest=json.loads(path.read_text())
        m=self.manifest
        if (m.get('scope')!=SCOPE or m.get('schema_version')!='ranking-v3-synthetic-fold'
            or m.get('family')!=fold.family or m.get('fitting')!=list(fold.fitting)
            or m.get('heldout')!=list(fold.heldout)
            or set(m.get('sha256',{}))!={'fit_features.json','fit_outcomes.json','heldout_features.json','heldout_outcomes.json'}):
            raise ValueError('FOLD_MANIFEST_MEMBERSHIP')

    def _read(self,name):
        path=self.root/name
        if path.is_symlink() or file_sha(path)!=self.manifest['sha256'][name]:
            raise ValueError('FOLD_FILE_SHA:'+name)
        return json.loads(path.read_text())

    def fitting(self,uids):
        if tuple(uids)!=self.fold.fitting: raise ValueError('FIT_UIDS')
        value=self._read('fit_outcomes.json')
        if set(value)!=set(uids): raise ValueError('FIT_OUTCOME_SET')
        return value

    def feature_rows(self):
        fit=self._read('fit_features.json'); held=self._read('heldout_features.json')
        if {r['action_uid'] for r in fit}!=set(self.fold.fitting) or {r['action_uid'] for r in held}!=set(self.fold.heldout):
            raise ValueError('FEATURE_UIDS')
        rows=fit+held
        if self.fold not in plan_folds(rows): raise ValueError('FEATURE_FOLD')
        return rows

    def heldout(self,uids,freeze_path,freeze_sha):
        if tuple(uids)!=self.fold.heldout: raise ValueError('HELD_UIDS')
        payload=read_freeze(freeze_path,freeze_sha)
        expected,sha=freeze_ranking(payload['scores'],self.fold)
        if payload!=expected or sha!=freeze_sha:
            raise ValueError('FREEZE_FOLD_BINDING')
        # First access to heldout_outcomes occurs only below these freeze checks.
        value=self._read('heldout_outcomes.json')
        if set(value)!=set(uids): raise ValueError('HELD_OUTCOME_SET')
        return value
