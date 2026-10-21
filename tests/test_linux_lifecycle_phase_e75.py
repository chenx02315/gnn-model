"""Pure local recovery tests. No Docker/SSH or actual Linux validation."""
import json
import unittest
from unittest import mock
from scripts import run_linux_lifecycle_phase_e75 as phase
from scripts import probe_linux_lifecycle_image_e75 as image


class RecoveryTests(unittest.TestCase):
    def test_utf8_approval_reaches_payload_without_remote_io(self):
        with mock.patch.object(phase,'payload',side_effect=ValueError('PAYLOAD_REACHED')), \
             mock.patch.object(phase.io,'transport',side_effect=AssertionError('SSH')):
            with self.assertRaisesRegex(ValueError,'PAYLOAD_REACHED'):phase.run('recover_image')

    def test_historical_raw_identity_and_python(self):
        self.assertEqual(phase.history()['image_id'],phase.IMAGE)

    def test_historical_forged_file_rejected(self):
        with mock.patch.object(phase,'read',return_value=b'{}'):
            with self.assertRaisesRegex(ValueError,'HISTORY_PIN'):phase.history()

    def test_image_source_fixed_single_id(self):
        self.assertEqual(image.IDS,(phase.IMAGE,))
        raw='\n'.join(json.dumps(v)for v in(phase.IMAGE,'linux','amd64',['bash'],None,None)).encode()
        with mock.patch.object(image.sys,'platform','linux'), \
             mock.patch.object(image.socket,'gethostname',return_value='bupt-gpus1'), \
             mock.patch.object(image,'capture',side_effect=[b'"2"\n"linux"\ntrue\n',raw])as capture:
            result=image.probe()
        self.assertEqual(capture.call_args.args[0][-1],phase.IMAGE)
        self.assertFalse(result['records'][0]['declared_python_command'])
        self.assertFalse(result['records'][0]['python_execution_verified'])

    def test_duplicate_or_unresolved_journal_rejected(self):
        for rows in ([dict(event='START',mode='probe',stdin_bytes=1)],
                     [dict(event='START',mode='probe'),dict(event='START',mode='probe')]):
            with self.assertRaises(ValueError):phase.usage(rows)

    def test_existing_quota_continues(self):
        rows=[phase.io.decode(x)for x in phase.read('data/manifests/ranking_v6_e74_sessions_20261021_r1.jsonl').splitlines()]
        starts,ends,usedin,usedout=phase.usage(rows)
        self.assertEqual((len(starts),usedin,usedout),(2,10384,5452))

    def test_transport_failure_not_admitted(self):
        result=dict(exit_code=1,stderr=b'',stdout=b'{}',timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        with self.assertRaisesRegex(ValueError,'TRANSPORT_FAILURE'):phase.admitted('recover_image',result)

    def test_metadata_not_python_execution_proof(self):
        obj=dict(host='bupt-gpus1',schema='e75-fixed-historical-image-v1',status='PASS_FIXED_IMAGE_METADATA',
            metadata_bytes=100,new_inventory_scan=False,actual_containers_created=0,
            records=[dict(image_id=phase.IMAGE,volumes_empty=True,python_execution_verified=False)])
        result=dict(exit_code=0,stderr=b'',stdout=json.dumps(obj).encode(),timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        self.assertEqual(phase.admitted('recover_image',result),obj)
        obj['records'][0]['volumes_empty']=False
        result['stdout']=json.dumps(obj).encode()
        with self.assertRaisesRegex(ValueError,'IMAGE_ADMISSION'):phase.admitted('recover_image',result)

    def test_fixed_payload_and_no_extra_mode(self):
        source,wire=phase.payload('recover_image')
        self.assertLess(len(wire),4096)
        self.assertIn(b'40960',wire)
        with self.assertRaisesRegex(ValueError,'FIXED_MODE'):phase.payload('other')

    def test_frozen_execute_wire_within_original_phase_budget(self):
        source,wire=phase.payload('execute')
        self.assertEqual(phase.sha(source),phase.EXEC_SHA)
        self.assertLessEqual(13060+len(wire),32768)
        self.assertLessEqual(20925+512+11000,32768)

    def test_execute_response_requires_real_gate_result(self):
        fake=dict(host='bupt-gpus1',status='PASS_LINUX_SYNTHETIC_GATE',gate_pass=True)
        result=dict(exit_code=0,stderr=b'',stdout=json.dumps(fake).encode(),timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        with self.assertRaises(ValueError):phase.admitted('execute',result)


if __name__=='__main__':unittest.main()
