import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'scripts/run_v5_target_cost.py'
spec=importlib.util.spec_from_file_location('target_cost_parent_test',PATH)
parent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


class ParentTests(unittest.TestCase):
    def test_base_import_uses_captured_bytes_not_package_files(self):
        sources={parent.BASE:b'TAG="captured"\n',parent.MODULE:b'from src.models import ranking_v5_feature_support as base\n'}
        with patch.dict(parent.sys.modules), patch.object(parent,'read',side_effect=AssertionError('IO')):
            module=parent.load_target(sources,Path('synthetic-no-files'))
            self.assertEqual(module.base.TAG,'captured')
            self.assertEqual(parent.sys.modules['src'].__path__,[])
            self.assertEqual(parent.sys.modules['src.models'].__path__,[])

    def test_allowlist_no_model_or_label_sources(self):
        self.assertEqual(len(parent.ALLOWED),6)
        self.assertEqual(hashlib.sha256((PATH.parents[1]/parent.BASE).read_bytes()).hexdigest(),parent.BASE_SHA)
        self.assertEqual(hashlib.sha256((PATH.parents[1]/parent.GUARD).read_bytes()).hexdigest(),parent.GUARD_SHA)

    def test_output_once_and_cap(self):
        # readback is independently tested on Linux; Windows lacks O_NOFOLLOW.
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'result.json'
            value={'status':'synthetic'}
            raw=(json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode()
            with patch.object(parent,'read',return_value=raw):
                self.assertEqual(parent.write_once(target,value),hashlib.sha256(raw).hexdigest())
                with self.assertRaises(FileExistsError):
                    parent.write_once(target,value)
            with self.assertRaisesRegex(ValueError,'OUTPUT_CAP'):
                parent.write_once(Path(directory)/'large.json',{'x':'x'*65536})
            self.assertFalse((Path(directory)/'large.json').exists())

    def test_wrong_platform_zero_io(self):
        with patch.object(parent.sys,'argv',['runner','--manifest-sha','a'*64]), \
             patch.object(parent.sys,'platform','win32'), \
             patch.object(parent,'read',side_effect=AssertionError('IO')):
            with self.assertRaisesRegex(ValueError,'FIXED_LINUX_ENVIRONMENT'):
                parent.main()

    def test_audit_exact_features_no_labels_write_or_process(self):
        allowed={parent.PACKAGE+'/receipt.json'}
        audit=parent.feature_audit(allowed)
        audit('open',(next(iter(allowed)),'r',os.O_RDONLY))
        audit('open',(3,'r',os.O_RDONLY))
        for path in (parent.PACKAGE+'/fold_other_family/fit_outcomes.json',
                     '/ssd/cjc/multimode_ate_gnn_v1/data', '/tmp/x', 'model.pt'):
            with self.assertRaisesRegex(PermissionError,'FEATURE_ONLY_OPEN_DENIED'):
                audit('open',(path,'r',os.O_RDONLY))
        for target in (3,next(iter(allowed))):
            with self.assertRaisesRegex(PermissionError,'FEATURE_WRITE_DENIED'):
                audit('open',(target,'w',os.O_WRONLY))
        for event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty',
                      'socket.connect','ctypes.dlopen'):
            with self.assertRaisesRegex(PermissionError,'FEATURE_EXECUTION_DENIED'):
                audit(event,())
        for name in ('torch','torch.nn','numpy','sklearn','xgboost'):
            with self.assertRaisesRegex(PermissionError,'FEATURE_ML_IMPORT_DENIED'):
                audit('import',(name,))

    @unittest.skipUnless(hasattr(os,'O_NOFOLLOW'),'POSIX NOFOLLOW required')
    def test_read_regular_bound_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'ordinary'
            target.write_bytes(b'abc')
            self.assertEqual(parent.read(target,3),b'abc')
            with self.assertRaisesRegex(ValueError,'FILE_BOUNDARY'):
                parent.read(target,2)
            link=Path(directory)/'link'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError,'SYMLINK'):
                parent.read(link)
            hard=Path(directory)/'hard'
            os.link(target,hard)
            with self.assertRaisesRegex(ValueError,'FILE_BOUNDARY'):
                parent.read(target)


if __name__=='__main__':
    unittest.main()
