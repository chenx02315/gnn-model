import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts import run_prospective_metadata_v1 as runner


class MetadataTransportTests(unittest.TestCase):
    def test_strict_ssh_identity_and_no_wrong_host_fallback(self):
        b=runner.command('B')
        self.assertIn('cjc@gpuserver.buptic.top',b)
        self.assertIn('HostKeyAlgorithms=ssh-ed25519',b)
        self.assertIn('StrictHostKeyChecking=yes',b)
        self.assertIn('UpdateHostKeys=no',b)
        self.assertNotIn('work.buptic.top',repr(b))
        self.assertEqual(runner.TIMEOUT,60)

    def test_cached_key_requires_exact_unique_pin(self):
        key=b'fake-public-key-only'
        pin='SHA256:'+base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
        row=b'host ssh-ed25519 '+base64.b64encode(key)+b'\n'
        reply=subprocess.CompletedProcess([],0,row,b'')
        with patch.dict(runner.HOSTS,{'B':('endpoint','host',pin)}),patch.object(runner.subprocess,'run',return_value=reply):
            self.assertEqual(runner.verify_cached_host('B'),pin)
        with patch.object(runner.subprocess,'run',return_value=reply):
            with self.assertRaisesRegex(ValueError,'PIN_MISMATCH'):runner.verify_cached_host('B')

    def test_json_duplicates_and_nan_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):runner.decode(raw)

    def test_unknown_session_reserves_worst_case_and_paths(self):
        event=dict(event='START',session='01_A',paths=runner.BUNDLES['A']['paths'],
            inventory_dirs=[],output_cap=32768)
        used,paths=runner.phase_usage([event])
        self.assertEqual(used['files'],8)
        self.assertEqual(used['body_bytes'],1048576)
        self.assertEqual(used['returned_bytes'],32768)
        self.assertEqual(len(paths),8)
        with self.assertRaises(ValueError):runner.phase_usage([event,event])

    def test_valid_result_counts_actual_reads_not_missing_paths(self):
        start=dict(event='START',session='01_A',paths=['a','b'],inventory_dirs=[],output_cap=32768)
        end=dict(event='END',session='01_A',accepted=True,
            budget=dict(files_read=1,body_bytes=27,inventory_entries=0),returned_bytes=100)
        used,paths=runner.phase_usage([start,end])
        self.assertEqual((used['files'],used['body_bytes'],used['returned_bytes']),(1,27,100))

    def test_corrected_flow_bundle_fits_remaining_global_budget(self):
        from scripts import read_prospective_metadata_v1 as payload
        request=runner.BUNDLES['A_FLOW']
        payload.validate_request(request['role'],request['paths'],request['inventory_dirs'])
        events=[]
        for number,role,files,size,out in ((1,'A',6,59340,3949),(2,'B',8,100516,4487)):
            sid='%02d_%s'%(number,role)
            events.extend([dict(event='START',session=sid,paths=runner.BUNDLES[role]['paths'],
                inventory_dirs=[],output_cap=32768),dict(event='END',session=sid,accepted=True,
                budget=dict(files_read=files,body_bytes=size,inventory_entries=0),returned_bytes=out)])
        used,requested=runner.phase_usage(events)
        self.assertEqual(used['files']+len(request['paths']),16)
        self.assertLessEqual(used['body_bytes']+131072*len(request['paths']),2097152)
        self.assertFalse(set(request['paths'])&requested)

    def test_transport_is_mocked_bounded_no_real_ssh(self):
        class Sink(io.BytesIO):
            def close(self):pass
        class Fake:
            returncode=0
            def __init__(self):self.stdin=Sink();self.stdout=io.BytesIO(b'abcdef');self.stderr=io.BytesIO()
            def wait(self,timeout):return 0
            def kill(self):self.returncode=-9
        proc=Fake()
        with patch.object(runner.subprocess,'Popen',return_value=proc) as spawn:
            receipt=runner.transport(['fake-never-ssh'],b'fixed-test',3)
        self.assertEqual(spawn.call_count,1)
        self.assertTrue(receipt['overflow'])
        self.assertLessEqual(len(receipt['stdout'])+len(receipt['stderr']),3)
        self.assertFalse(receipt['remote_termination_verified'])

    def test_wrong_source_pin_stops_before_auth_or_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source.py';source.write_bytes(b'# synthetic only\n')
            with patch.object(runner,'SOURCE',source),patch.object(runner,'verify_cached_host') as host:
                with self.assertRaisesRegex(ValueError,'SOURCE_PIN_MISMATCH'):
                    runner.run('A','0'*64,Path(directory)/'not-used')
                host.assert_not_called()

    def test_mocked_phase_durable_request_and_no_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'repo';root.mkdir()
            (root.parent/'runtime_training_staging_20260928').mkdir()
            phase=root.parent/'runtime_training_staging_20260928'/runner.PHASE_NAME
            source=root/'payload.py'
            raw=(b'def validate_request(role, paths, inventory_dirs):\n    return None\n'
                b'def validate_response(result, request):\n    return result.get("schema")=="synthetic-only"\n')
            source.write_bytes(raw)
            scope=root/'scope.json';scope.write_bytes(b'{}')
            auth=root/'auth.json';auth.write_text(json.dumps(dict(user_authorization_received=True,
                scope_contract_sha256=runner.sha(scope.read_bytes()))),encoding='ascii')
            response=dict(schema='synthetic-only',budget=dict(files_read=0,body_bytes=0,inventory_entries=0))
            observed=dict(exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False,
                stdout=json.dumps(response).encode(),stderr=b'',remote_termination_verified=False)
            with patch.object(runner,'ROOT',root),patch.object(runner,'SOURCE',source),\
                    patch.object(runner,'SCOPE',scope),patch.object(runner,'AUTH',auth),\
                    patch.object(runner,'verify_cached_host',return_value='fixed-test-pin') as host,\
                    patch.object(runner,'transport',return_value=observed) as transport:
                self.assertEqual(runner.run('A',runner.sha(raw),phase),0)
                with self.assertRaisesRegex(ValueError,'FIXED_AUTHORIZATION_PHASE_PATH'):
                    runner.run('A',runner.sha(raw),phase.with_name('v6_e70_metadata_reset_forbidden'))
                with self.assertRaisesRegex(ValueError,'PATH_ALREADY_ATTEMPTED'):
                    runner.run('A',runner.sha(raw),phase)
                self.assertEqual((host.call_count,transport.call_count),(1,1))
            events=[runner.decode(row) for row in (phase/'sessions.jsonl').read_bytes().splitlines()]
            self.assertEqual([e['event'] for e in events],['START','END'])
            self.assertFalse((phase/'active.lock').exists())


if __name__=='__main__':
    unittest.main()
