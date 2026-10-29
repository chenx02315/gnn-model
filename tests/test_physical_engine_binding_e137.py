import ast
import base64
import copy
import json
from pathlib import Path
import stat
import unittest
from unittest import mock
from src.data import physical_engine_binding_e137 as m
from src.data import prospective_runtime_profile_e112 as profile


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo=Path(__file__).resolve().parents[1];stage=repo.parent/'runtime_training_staging_20260928'
        files=stage/'v6_e137_engine_source_supplement_r1/files'
        cls.functions=(files/m.selector.FUNCTIONS_SHA).read_bytes();cls.shell=(files/m.selector.SHELL_SHA).read_bytes()
        old=json.loads((stage/'v6_e112_preparation_20261026_r1/stdout.json').read_bytes())
        cls.launcher=base64.b64decode(old['launcher']['body_base64'])

    def setUp(self):
        self.env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/secret/SENTINEL_LD',LM_LICENSE_FILE='1234@SENTINEL_LICENSE',
            MGLS_LICENSE_FILE='1234@SENTINEL_LICENSE')
        self.profile=profile.snapshot(self.env,False)
        self.argv=[m.selector.LAUNCHER,'-shell','-license_wait','5','-log',m.selector.RUN_ROOT+'/tool.log',
            '-dofile',m.selector.RUN_ROOT+'/code/replay.tcl']
        self.clock=dict(authorization_sha256=m.AUTH_SHA256,original_clock_sha256='a'*64,boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
            nonce='b'*64,package_start=1000.,package_end=4600.,connection_start=2000.,utc_end=8000.)
        def record(size=1,directory=False,digest='f'*64):
            return dict(identity=dict(st_dev=1,st_ino=2,st_mode=(stat.S_IFDIR|0o755 if directory else stat.S_IFREG|0o755),
                st_nlink=2 if directory else 1,st_uid=0,st_size=size,st_mtime_ns=1,st_ctime_ns=1),sha256=None if directory else digest)
        self.metadata={p:dict(state='MISSING') for p in m.selector.CANDIDATES}
        self.metadata[m.selector.MGLS['32']]=dict(state='PRESENT',record=record())
        self.metadata[m.selector.TCL['32']]=dict(state='PRESENT',record=record(directory=True))
        self.metadata[m.selector.ENGINE['64']]=dict(state='PRESENT',record=record())
        self.chain={p:record(size=size,digest=digest) for p,size,digest in zip(m.CHAIN_PATHS,(3658,12306,49725),
            (m.LAUNCHER_SHA256,m.selector.FUNCTIONS_SHA,m.selector.SHELL_SHA))}

    def candidate(self,**changes):
        values=dict(functions_bytes=self.functions,shell_bytes=self.shell,launcher_bytes=self.launcher,raw_environment=self.env,
            profile_metadata=self.profile,argv=self.argv,metadata=self.metadata,chain=self.chain,clock=self.clock,now=2100.,utc_now=5000.)
        values.update(changes)
        with mock.patch.object(m,'PROFILE_NORMALIZED_SHA256',self.profile['normalized_sha256']):
            return m.build_candidate(**values)

    def test_private_plan_environment_not_serializable_or_publicly_leaked(self):
        value=self.candidate();raw=value.public_bytes()
        self.assertNotIn(b'SENTINEL',raw);self.assertNotIn('SENTINEL',repr(value))
        with self.assertRaises(TypeError):json.dumps(value)
        environment,privateplan=value.private_runtime()
        self.assertIn('SENTINEL',environment['LD_LIBRARY_PATH'])
        self.assertFalse(value.public['engine_authenticated']);self.assertFalse(value.public['execution_ready'])
        self.assertEqual(value.public['classification']['selected']['tcl_search_width'],'32')
        self.assertEqual(value.public['classification']['selected']['engine']['width'],'64')

    def test_hash_unknown_path_link_and_fallback_not_silently_guessed(self):
        with self.assertRaisesRegex(ValueError,'EXACT_HELPER_SOURCE_BYTES'):self.candidate(shell_bytes=self.shell+b' ')
        for change in ('unknown','unobserved','unsafe','chainhash'):
            metadata=copy.deepcopy(self.metadata);chain=copy.deepcopy(self.chain)
            if change=='unknown':metadata['/unapproved']=dict(state='MISSING')
            elif change=='unobserved':metadata[m.selector.ENGINE['64']]=dict(state='UNOBSERVED')
            elif change=='unsafe':metadata[m.selector.ENGINE['64']]['record']['identity']['st_nlink']=2
            else:chain[m.CHAIN_PATHS[0]]['sha256']='0'*64
            with self.assertRaises(ValueError):self.candidate(metadata=metadata,chain=chain)
        metadata=copy.deepcopy(self.metadata)
        metadata[m.selector.ENGINE['32']]=metadata[m.selector.ENGINE['64']]
        metadata[m.selector.ENGINE['64']]=dict(state='MISSING')
        self.assertEqual(self.candidate(metadata=metadata).public['classification']['selected']['engine']['width'],'32')

    def test_clock_auth_deadline_and_environment_pin_mismatch(self):
        for key,bad in [('authorization_sha256','old'),('package_end',4700.),('boot_id','wrong')]:
            with self.assertRaises(ValueError):self.candidate(clock=dict(self.clock,**{key:bad}))
        with self.assertRaisesRegex(ValueError,'ENGINE_ORIGINAL_DEADLINE'):self.candidate(now=4600.)
        with self.assertRaisesRegex(ValueError,'RUNTIME_PROFILE_DRIFT'):self.candidate(raw_environment=dict(self.env,PATH='/elsewhere'))
        with self.assertRaisesRegex(ValueError,'ENGINE_FIXED_RUNTIME_PROFILE'):
            m.build_candidate(self.functions,self.shell,self.launcher,self.env,self.profile,self.argv,self.metadata,self.chain,self.clock,2100.,5000.)

    def test_missing_physical_and_ldd_capabilities_never_release(self):
        self.assertIsNone(m.EVIDENCE_VERIFIER);self.assertIsNone(m.LDD_VERIFIER)
        with self.assertRaisesRegex(ValueError,'ENGINE_EVIDENCE_VERIFIER_MISSING'):m.bind()
        verified=mock.Mock();verified.__source_sha256__='a'*64
        with mock.patch.object(m,'EVIDENCE_VERIFIER',verified),mock.patch.object(m,'EVIDENCE_VERIFIER_SHA256','a'*64):
            with self.assertRaisesRegex(ValueError,'ENGINE_LDD_VERIFIER_MISSING'):m.bind()
        verified.assert_not_called()

    def test_sources_ast36_and_inert(self):
        repo=Path(__file__).resolve().parents[1]
        for name,digest in m.SOURCE_PINS.items():self.assertEqual(m.sha((repo/'src/data'/(name+'.py')).read_bytes()),digest)
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            scope=dict(__package__='src.data');exec(compile(raw,'<inert-binding>','exec'),scope)
        opened.assert_not_called();self.assertIsNone(scope['LDD_VERIFIER'])
