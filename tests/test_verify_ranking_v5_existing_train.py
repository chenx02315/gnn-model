"""Synthetic/mock inference only; no Torch, model deserialization, data or ML."""
import base64
from collections import OrderedDict
from contextlib import nullcontext
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from scripts import verify_ranking_v5_existing_train as v
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_freeze_codec_v2 as codec
from src.models import runtime_ranking_v3 as ranking
from src.models.ranking_v5_physical_worker import synthetic_request

class Tensor:
    def __init__(self,shape=(),values=None,finite=True,device='cpu',dtype='float32'):
        self.shape=shape;self.values=values;self.finite=finite
        self.device=SimpleNamespace(type=device);self.dtype=dtype
    def all(self):return self
    def item(self):return self.finite
    def detach(self):return self
    def cpu(self):return self
    def tolist(self):return self.values

class Model:
    def __init__(self,values):self.values=values;self.strict=None;self.evaluated=False
    def load_state_dict(self,state,strict=False):
        self.strict=strict;return SimpleNamespace(missing_keys=[],unexpected_keys=[])
    def eval(self):self.evaluated=True
    def __call__(self,matrix):return Tensor(values=list(self.values))

def fixture():
    request=synthetic_request();family=request['family'];seed=request['seed']
    fold,prepared,held,recipe=boundary.prepare_request(request)
    scores={uid:float(i) for i,uid in enumerate(fold.heldout)}
    payload,freeze_sha=ranking.freeze_ranking(scores,fold)
    outcomes={uid:dict(execution_status='SUCCESS',is_d95_feasible=1,total_cycles=100+i,
                      policy_charged_runtime_s=1.25+i) for i,uid in enumerate(fold.heldout)}
    metrics=ranking.replay_frozen(payload,freeze_sha,fold,outcomes)
    identity=dict(package_receipt_sha256=boundary.PACKAGE_SHA256,source_sha256=boundary.SOURCE_SHA256,
                  fold_manifest_sha256='c'*64,family=family,seed=seed)
    model_raw=b'UNIT_FIXTURE_NOT_A_TORCH_CHECKPOINT';log_raw=b'UNIT_LOG\n'
    freeze_raw=codec.encode(payload,freeze_sha)
    worker=dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',input_identity=identity,
        fitting_log_sha256=v.sha(log_raw),boundary_receipt=dict(family=family,seed=seed,
            model_ack_sha256=v.sha(model_raw),expected_model_sha256=v.sha(model_raw),
            freeze_sha256=freeze_sha,canonical_request_sha256=ranking.digest(request),
            head_recipe_sha256=ranking.digest(recipe),held_labels_replayed=True,metrics=metrics))
    worker['worker_receipt_sha256']=v.sha(v.canonical(worker))
    worker_raw=v.canonical(worker)
    raws={'model.pt':model_raw,'freeze.json':freeze_raw,'worker_receipt.json':worker_raw,'fitting.jsonl':log_raw}
    pins={p:v.sha(raw) for p,raw in raws.items()}
    plan=dict(output=v.task_gate(family,seed),file_sha256=pins,worker_receipt_raw=worker_raw)
    model=Model(list(scores.values()))
    state=OrderedDict((key,Tensor(shape)) for key,shape in v.STATE_SHAPES.items())
    torch=SimpleNamespace(Tensor=Tensor,float32='float32',no_grad=nullcontext,
        tensor=lambda matrix,**kw:matrix,isfinite=lambda t:t,
        set_num_threads=Mock(),get_num_threads=lambda:1,get_num_interop_threads=lambda:1,
        set_num_interop_threads=Mock(),load=Mock(return_value=state))
    held_reader=Mock(return_value=outcomes)
    modules=dict(resource=SimpleNamespace(check_current_process=Mock()),
        codec=codec,boundary=boundary,ranking=ranking,
        inputs=SimpleNamespace(load_bound_fold_request=Mock(return_value=dict(request=request,input_identity=identity))),
        held=SimpleNamespace(load_frozen_held_outcomes=held_reader))
    def read(root,name,cap,pin=None,stream_only=False):
        raw=raws[name]
        if pin is not None and v.sha(raw)!=pin:raise ValueError('unit bad SHA')
        return (len(raw),v.sha(raw)) if stream_only else raw
    return SimpleNamespace(request=request,family=family,seed=seed,fold=fold,payload=payload,
        freeze_sha=freeze_sha,model=model,torch=torch,modules=modules,plan=plan,raws=raws,
        state=state,read=read,worker=worker)

class PureVerificationTests(unittest.TestCase):
    def run_one(self,x):
        with patch.object(ranking,'make_candidate_ranker',return_value=x.model),\
             patch.dict(v.os.environ,{'CUDA_VISIBLE_DEVICES':''}):
            return v.verify_one(x.torch,x.modules,x.plan,x.family,x.seed,read_artifact=x.read)
    def test_exact_predictions_order_digest_and_charged_runtime(self):
        x=fixture();r=self.run_one(x)
        self.assertEqual(r['status'],'PASS_EXISTING_TRAIN_PREDICTIONS_AND_METRICS_EXACT')
        self.assertTrue(r['predictions_exact']);self.assertTrue(r['original_metrics_exact'])
        self.assertTrue(r['old_artifact_hashes_unchanged']);self.assertEqual(r['postchecked_count'],4)
        self.assertEqual(r['metrics'],x.worker['boundary_receipt']['metrics'])
        self.assertGreater(r['metrics']['charged_runtime_s'],0)
        x.torch.load.assert_called_once()
        self.assertEqual(x.torch.load.call_args.kwargs,dict(map_location='cpu',weights_only=True))
        self.assertTrue(x.model.strict);self.assertTrue(x.model.evaluated)
        x.modules['held'].load_frozen_held_outcomes.assert_called_once()
        self.assertNotIn('scores',r);self.assertNotIn('order',r)
    def test_prediction_drift_blocks_all_held_labels(self):
        x=fixture();x.model.values[0]+=.000001
        with self.assertRaisesRegex(ValueError,'PREDICTIONS_EXACT'):self.run_one(x)
        x.modules['held'].load_frozen_held_outcomes.assert_not_called()
    def test_nonfinite_or_wrong_shape_blocks_labels(self):
        for values in ([float('nan')],[0.0],[]):
            x=fixture();x.model.values=values
            with self.assertRaisesRegex(ValueError,'PREDICTION_SHAPE'):self.run_one(x)
            x.modules['held'].load_frozen_held_outcomes.assert_not_called()
    def test_request_or_identity_drift_blocks_checkpoint_load(self):
        for target in ('request','identity'):
            x=fixture()
            snapshot=x.modules['inputs'].load_bound_fold_request.return_value
            if target=='request':snapshot['request']=dict(snapshot['request'],seed=20260825)
            else:snapshot['input_identity']=dict(snapshot['input_identity'],fold_manifest_sha256='d'*64)
            with self.assertRaisesRegex(ValueError,'FOLD_JOIN'):self.run_one(x)
            x.torch.load.assert_not_called();x.modules['held'].load_frozen_held_outcomes.assert_not_called()
    def test_artifact_pin_drift_blocks_load(self):
        for name in v.ARTIFACT_CAPS:
            x=fixture();x.plan['file_sha256'][name]='0'*64
            with self.assertRaises(ValueError):self.run_one(x)
            x.torch.load.assert_not_called()
    def test_wrong_state_keys_shape_dtype_device_finite(self):
        for change in ('keys','shape','dtype','device','finite'):
            x=fixture()
            if change=='keys':x.state['unexpected']=Tensor()
            elif change=='shape':x.state['layers.0.weight'].shape=(33,7)
            elif change=='dtype':x.state['layers.0.weight'].dtype='float64'
            elif change=='device':x.state['layers.0.weight'].device.type='cuda'
            else:x.state['layers.0.weight'].finite=False
            with self.assertRaisesRegex(ValueError,'STATE_'):self.run_one(x)
            x.modules['held'].load_frozen_held_outcomes.assert_not_called()
    def test_metrics_charged_time_mismatch_is_not_pass(self):
        x=fixture();x.modules['held'].load_frozen_held_outcomes.return_value=copy.deepcopy(
            x.modules['held'].load_frozen_held_outcomes.return_value)
        for outcome in x.modules['held'].load_frozen_held_outcomes.return_value.values():
            outcome['policy_charged_runtime_s']+=.5
        with self.assertRaisesRegex(ValueError,'METRICS_EXACT'):self.run_one(x)
    def test_strict_missing_keys_refused(self):
        x=fixture();x.model.load_state_dict=lambda *a,**k:SimpleNamespace(missing_keys=['x'],unexpected_keys=[])
        with self.assertRaisesRegex(ValueError,'STATE_STRICT'):self.run_one(x)
        x.modules['held'].load_frozen_held_outcomes.assert_not_called()
    def test_post_replay_artifact_byte_changes_refused(self):
        for name in v.ARTIFACT_CAPS:
            x=fixture();outcomes=x.modules['held'].load_frozen_held_outcomes.return_value
            def mutate(*args,**kwargs):
                x.raws[name]+=b'changed after replay'
                return outcomes
            x.modules['held'].load_frozen_held_outcomes.side_effect=mutate
            with self.assertRaises(ValueError):self.run_one(x)
    def test_invalid_task_and_protected_root_zero_io(self):
        with patch.object(v,'read_fixed') as reader:
            for f,s,root in [('unknown',20260824,v.VERIFY_ROOT),(v.FAMILIES[0],True,v.VERIFY_ROOT),
                (v.FAMILIES[0],20260824,'/ssd/cjc/multimode_ate_gnn_v1')]:
                with self.assertRaises(ValueError):v.execute(f,s,root,'a'*64,v.AUTHORIZATION_SHA)
            reader.assert_not_called()
        with patch.object(v.Path,'lstat') as stat:
            with self.assertRaises(ValueError):v.read_fixed('/ssd/cjc/multimode_ate_gnn_v1','model.pt',100)
            stat.assert_not_called()
    def test_fixed_source_protocol45_and_no_training_calls(self):
        self.assertEqual(len(v.CORE_FILES),26);self.assertEqual(len(v.CORE_FILES|v.AUXILIARY),45)
        source=Path(v.__file__).read_text(encoding='utf8')
        self.assertNotIn('execute_single_fit(',source);self.assertNotIn('torch.optim',source)
        self.assertNotIn('torch.save(',source);self.assertNotIn('weights_only=False',source)
        self.assertNotIn('torch.cuda.is_available(',source)
    def test_missing_or_nonempty_cuda_visibility_rejected_before_checkpoint(self):
        for value in (None,'0','1',' '):
            x=fixture()
            with patch.dict(v.os.environ,clear=False):
                if value is None:v.os.environ.pop('CUDA_VISIBLE_DEVICES',None)
                else:v.os.environ['CUDA_VISIBLE_DEVICES']=value
                with self.assertRaisesRegex(ValueError,'CPU_ENVIRONMENT'):
                    v.verify_one(x.torch,x.modules,x.plan,x.family,x.seed,read_artifact=x.read)
                x.torch.load.assert_not_called()
                x.modules['inputs'].load_bound_fold_request.assert_not_called()

class AuthorizationPlanTests(unittest.TestCase):
    def test_real_authorization_exact_pin_and_scope(self):
        raw=(Path(__file__).resolve().parents[1]/'contracts/ranking_v5_existing_train_replay_authorization_20261012_r1.json').read_bytes()
        self.assertEqual(v.validate_authorization(raw,v.AUTHORIZATION_SHA),v.AUTHORIZATION_EXPECTED)
        with self.assertRaises(ValueError):v.validate_authorization(raw,'0'*64)
        with self.assertRaises(ValueError):v.validate_authorization(raw+b' ',v.AUTHORIZATION_SHA)
    def plan(self):
        return dict(schema='v5-existing-train-verify-plan-v1',verification_root=v.VERIFY_ROOT,
            artifact_root=v.TRAIN_ROOT,package_root=v.PACKAGE_ROOT,authorization_sha256=v.AUTHORIZATION_SHA,
            artifact_receipt_sha256=v.ARTIFACT_RECEIPT_SHA,legacy_trust_sha256=v.LEGACY_TRUST_SHA,
            families=list(v.FAMILIES),seeds=list(v.SEEDS),
            source_sha256={v.SELF_PATH:'a'*64,v.PARENT_PATH:'b'*64,v.VERIFY_JIT:v.VERIFY_JIT_SHA})
    def test_exact_plan(self):
        value=self.plan();raw=v.canonical(value)
        self.assertEqual(v.validate_plan(raw,v.sha(raw)),value)
    def test_plan_resealed_wrong_root_family_extra_or_helper_fail(self):
        for change in ('root','family','extra','helper','path'):
            value=self.plan()
            if change=='root':value['artifact_root']='/ssd/cjc/multimode_ate_gnn_v1'
            elif change=='family':value['families'].reverse()
            elif change=='extra':value['training_allowed']=True
            elif change=='helper':value['source_sha256'][v.VERIFY_JIT]='0'*64
            else:value['source_sha256']['unexpected.py']='0'*64
            raw=v.canonical(value)
            with self.assertRaises(ValueError):v.validate_plan(raw,v.sha(raw))
    def test_duplicate_nonfinite_and_bound(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b' '*20481):
            with self.assertRaises(ValueError):v.decode(raw)
    def test_source_missing_auth_before_any_compilation(self):
        with patch.object(v.sys,'platform','linux'),patch.object(v.sys,'executable',v.INTERPRETER),\
             patch.object(v.sys,'version_info',(3,11,2)),patch.object(v.sys,'flags',SimpleNamespace(isolated=1,no_site=1)),\
             patch.object(v.sys,'path',list(v.SEARCH_PATHS)),patch.object(v.os,'getcwd',return_value='/ssd/cjc'),\
             patch.object(v,'read_fixed',side_effect=FileNotFoundError('unit missing auth')),patch.object(v,'external') as compile_helper:
            with self.assertRaises(FileNotFoundError):
                v.execute(v.FAMILIES[0],v.SEEDS[0],v.VERIFY_ROOT,'a'*64,v.AUTHORIZATION_SHA)
            compile_helper.assert_not_called()

class BoundsRestorationTests(unittest.TestCase):
    def test_all_eighteen_task_paths_and_pin_before_parse(self):
        for f in v.FAMILIES:
            for s in v.SEEDS:
                self.assertEqual(v.task_gate(f,s),v.TRAIN_ROOT+'_'+f+'_'+str(s))
                with patch.object(v,'decode') as decoder:
                    with self.assertRaisesRegex(ValueError,'ARTIFACT_RECEIPT_PIN'):
                        v.select_plan(b'not pinned',f,s)
                    decoder.assert_not_called()
    def test_codec_restores_on_exception_and_preserves_replacement(self):
        from types import ModuleType
        import sys
        package=ModuleType('src.models');package.__path__=[]
        package.__spec__=SimpleNamespace(origin='sealed://namespace/src.models')
        name='src.models.ranking_v5_freeze_codec_v2'
        sentinel=ModuleType(name)
        with patch.object(v.importlib,'import_module',return_value=package),patch.dict(sys.modules):
            sys.modules.pop(name,None)
            with self.assertRaisesRegex(RuntimeError,'unit failure'):
                with v.codec_context(b'value = 1\n') as codec:
                    self.assertEqual(codec.value,1)
                    raise RuntimeError('unit failure')
            self.assertNotIn(name,sys.modules)
            self.assertNotIn('ranking_v5_freeze_codec_v2',package.__dict__)
            with self.assertRaisesRegex(ValueError,'CODEC_DRIFT'):
                with v.codec_context(b'value = 1\n'):
                    sys.modules[name]=sentinel
            self.assertIs(sys.modules[name],sentinel)
    def test_codec_preload_rejects_before_compile(self):
        from types import ModuleType
        import sys
        package=ModuleType('src.models');package.__path__=[]
        package.__spec__=SimpleNamespace(origin='sealed://namespace/src.models')
        name='src.models.ranking_v5_freeze_codec_v2'
        with patch.object(v.importlib,'import_module',return_value=package),\
             patch.dict(sys.modules,{name:ModuleType(name)}),patch('builtins.compile') as compiler:
            with self.assertRaisesRegex(ValueError,'CODEC_CONTEXT'):
                with v.codec_context(b'value = 1\n'):self.fail('entered')
            compiler.assert_not_called()
    def test_read_fixed_bound_or_hardlink_or_link_before_open(self):
        import stat
        for changes in ({'st_size':1048577},{'st_nlink':2},{'st_mode':stat.S_IFLNK|0o600}):
            fields=dict(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=1,st_file_attributes=0)
            fields.update(changes)
            fake=SimpleNamespace(parents=(),lstat=lambda:SimpleNamespace(**fields))
            class Root:
                def __truediv__(self,name):return fake
            with patch.object(v,'Path',return_value=Root()),patch.object(v.os,'open') as opened:
                with self.assertRaises(ValueError):
                    v.read_fixed(v.task_gate(v.FAMILIES[0],v.SEEDS[0]),'model.pt',1048576,'a'*64)
                opened.assert_not_called()

if __name__=='__main__':unittest.main()
