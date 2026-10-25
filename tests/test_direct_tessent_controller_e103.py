import ast
import json
from pathlib import Path
import sys
import tempfile
import os
import platform
import unittest
from unittest.mock import Mock,patch
from scripts import run_direct_tessent_e103 as m


class Tests(unittest.TestCase):
    def test_missing_reply_never_connects_creates_or_prepares(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'ROOT',Path(directory)), \
             patch.object(sys,'argv',['entry','execute','a'*64]),patch.object(m.control,'load_transport') as connect:
            with self.assertRaises(PermissionError):m.main()
            connect.assert_not_called();self.assertEqual(list(Path(directory).iterdir()),[])

    def test_prepare_missing_reply_is_explicit_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'ROOT',Path(directory)), \
             patch.object(sys,'argv',['entry','prepare']),patch('builtins.print') as out, \
             patch.object(m.control,'load_transport') as connect:
            m.main();value=json.loads(out.call_args[0][0])
            self.assertFalse(value['execution_ready']);self.assertFalse(value['payload_prepared'])
            connect.assert_not_called()

    def test_offline_synthetic_authority_binds_every_source_and_sets_loader_pins(self):
        raw=(m.ROOT/m.AUTH).read_bytes()
        with patch('subprocess.Popen') as spawn:
            plan=m.prepare(raw)
        spawn.assert_not_called()
        self.assertEqual(len(plan['source_sha256']),13)
        self.assertIn(b'm.__source_sha256__=row["sha256"]',plan['payload'])
        self.assertTrue(b'src.data.direct_tessent_acceptance_e103' in plan['payload'],
                        'new controller must select E103, not its predecessor')
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))

    def test_proposal_is_not_authority(self):
        raw=(m.ROOT/'contracts/direct_tessent_runtime_repair_e102_proposal_v1.json').read_bytes()
        with self.assertRaisesRegex(PermissionError,'PACKAGE_REPLY_RECORD_CHANGED'):m.prepare(raw)

    def test_wrong_review_pin_no_network(self):
        with patch.object(sys,'argv',['entry','execute','a'*64]), \
             patch.object(m,'prepare',return_value=dict(payload_sha256='b'*64)), \
             patch.object(m.control,'load_transport') as connect:
            with self.assertRaisesRegex(ValueError,'PAYLOAD_CHANGED'):m.main()
            connect.assert_not_called()

    def test_cli_no_arbitrary_target_or_command(self):
        for args in (['execute','bad'],['execute','a'*64,'other-root'],['resume'],[]):
            with patch.object(sys,'argv',['entry']+args),patch.object(m,'prepare') as prepare:
                with self.assertRaises(ValueError):m.main()
                prepare.assert_not_called()

    def test_exclusive_phase_even_on_unknown_result_never_retransmits(self):
        pin=m.control.sha(b'UNIT_TEST_NOT_EXECUTED')
        for failed in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                transport=Mock();transport.verify_cached_host.return_value='UNIT_TEST_PIN'
                transport.command.return_value=['UNIT_TEST_NO_COMMAND']
                transport.transport.return_value=dict(exit_code=1 if failed else 0,timeout=False,
                    overflow=False,write_failed=False,threads_incomplete=False,
                    stdout=json.dumps(dict(schema='direct-tessent-acceptance-e103-v1',root=m.repair.ROOT,passed=True)).encode('ascii'),
                    stderr=b'',remote_termination_verified=False)
                plan=dict(payload=b'UNIT_TEST_NOT_EXECUTED',payload_sha256=pin)
                with patch.object(sys,'argv',['entry','execute',pin]),patch.object(m,'prepare',return_value=plan), \
                     patch.object(m.control,'STAGING',Path(directory)), \
                     patch.object(m.control,'load_transport',return_value=transport),patch('builtins.print'):
                    if failed:
                        with self.assertRaisesRegex(ValueError,'NO_RETRY'):m.main()
                    else:m.main()
                    with self.assertRaises(FileExistsError):m.main()
                transport.transport.assert_called_once()

    def test_component_drift_is_rejected_offline(self):
        raw=(m.ROOT/m.AUTH).read_bytes()
        with patch.object(m,'PINS',((m.PINS[0][0],'0'*64),)),patch('subprocess.Popen') as spawn:
            with self.assertRaisesRegex(ValueError,'COMPONENT_CHANGED'):m.prepare(raw)
        spawn.assert_not_called()

    def test_exact_bootstrap_loads_all_modules_without_calling_executor(self):
        plan=m.prepare()
        prefix=plan['payload'].split(b'result=m.execute(',1)[0]
        namespace={}
        with patch.dict(sys.modules),patch.object(sys,'platform','linux'), \
             patch.object(platform,'node',return_value='bupt-vncs2'), \
             patch.object(os,'getuid',return_value=1047,create=True),patch('subprocess.Popen') as spawn:
            exec(compile(prefix,'<synthetic-bootstrap-only>','exec'),namespace)
            selected=namespace['m']
            self.assertEqual(selected.__name__,'src.data.direct_tessent_acceptance_e103')
            self.assertEqual(selected.ROOT,m.repair.ROOT)
            selected.validate_authority((m.ROOT/m.AUTH).read_bytes())
            self.assertTrue(all(getattr(mod,'__source_sha256__')==pin
                                for mod,pin in selected.SOURCE_PINS))
            spawn.assert_not_called()

    def test_python36(self):ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
