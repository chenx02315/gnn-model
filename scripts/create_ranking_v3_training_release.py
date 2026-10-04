"""Create-once training release from separately retained gate artifacts."""
import hashlib,json
from pathlib import Path
from scripts.run_ranking_v3_real_experiment import REVIEWED_FILES

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    root=Path('data/manifests')
    code_path=root/'ranking_v3_real_entrypoint_gate_r5_20261004.json'
    data_path=root/'ranking_v3_train_data_review_20261004.json'
    code=json.loads(code_path.read_bytes()); data=json.loads(data_path.read_bytes())
    if code['status']!='PASS_CODE_AND_ML_SYNTHETIC_GATE' or code['testsRun']!=19 or any(code[k]!=0 for k in ('skipped','failures','errors')):
        raise ValueError('CODE_ML_GATE')
    if data['status']!='PASS_DATA_GATE_PACKAGE_ONLY' or not all(data['gates'].values()):raise ValueError('DATA_GATE')
    sources={name:code['source_sha256'][name] for name in REVIEWED_FILES}
    if any(sha(name)!=value for name,value in sources.items()):raise ValueError('SOURCE_DRIFT')
    value={'status':'PASS_TRAIN_ONLY_EXECUTION_RELEASE','independent_review_pass':True,'data_gate_pass':True,
           'roles':['TRAIN'],'source_sha256':data['source_sha256'],'reviewed_sources':sources,
           'code_ml_gate_receipt_sha256':sha(code_path),'data_review_receipt_sha256':sha(data_path),
           'package_receipt_sha256':data['package_receipt_sha256'],
           'user_authorization':'continue automatically after independent review and data gates',
           'methods':['candidate_mlp','graphsage','xgboost','fixed_heuristic'],
           'seeds':[20260824,20260825,20260826],'training_release':True,
           'blind_allowed':False,'validation_allowed':False,'lsf_tessent_allowed':False}
    path=root/'ranking_v3_train_execution_release_20261004.json'
    with path.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
    print(json.dumps({'release_sha256':sha(path),'source_sha256':value['source_sha256'],'package_sha256':value['package_receipt_sha256']}))

if __name__=='__main__':main()
