"""Pure local E78 protocol tests. No SSH, Docker, or actual child process."""
import base64
import builtins
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import execute_linux_journal_e78 as helper
from scripts import run_linux_journal_phase_e78 as controller
from src.data import prospective_lifecycle_journal_v2 as base
from src.data import prospective_linux_journal_v3 as v3


def healthy_journal():
    state=v3.State()
    rows=[v3.header()]
    for index,profile in enumerate(v3.FIXED_PROFILES,1):
        aid='e78-%d'%index
        identity={'host':'a123456789012345678901234567890123456789012345678901234567890',
                  'boot_id':'12345678-1234-1234-1234-123456789abc',
                  'pid':100000+index,'pgrp':100000+index,
                  'start_ticks':123456789012345+index}
        start=123456789000000000+index*100000000
        for kind,payload in (
            ('INTENT',dict(profile=profile,clock_session='e78-fixed-clock',prelaunch_ns=start)),
            ('LAUNCHED',dict(identity=identity)),
            ('REAPED',dict(identity=identity,clock_session='e78-fixed-clock',
                           end_ns=start+10000000,interval_ns=10000000,
                           status=base.EXPECTED[profile][0],returncode=base.EXPECTED[profile][1],
                           timed_out=base.EXPECTED[profile][2],leader_reaped=True,
                           observed_group_empty=True))):
            body=state.event(kind,aid,payload)
            row=dict(body,sha256=base.sha(base.canonical(body)))
            state.apply(row)
            rows.append(row)
    raw=b''.join(base.canonical(row)+b'\n' for row in rows)
    live=state.summary(acknowledged=True)
    live['launch_attempt_count']=3
    return raw,live


def healthy_receipt(raw,live):
    return dict(schema='e78-host-execution-v1',host='bupt-gpus1',image_id=helper.IMAGE,
                status='PASS_FIXED_LINUX_JOURNAL_ONLY',gate_pass=True,phase='COMPLETE',
                execution_ready=False,training_release=False,retry_allowed=False,
                auth_sha256=helper.AUTH_SHA,proposal_sha256=helper.PROPOSAL_SHA,
                source_sha256=helper.SOURCES,container_id='a'*64,cleanup_verified=True,
                running=False,oom_killed=False,container_exit=0,attach_exit=0,
                output_bytes=1600,output_sha256='b'*64,read_bytes=18000,
                live_summary=live,journal_bytes=len(raw),journal_sha256=helper.sha(raw),
                journal_b64=base64.b64encode(raw).decode('ascii'))


class E78Tests(unittest.TestCase):
    def test_build_only_pins_and_quotas(self):
        wire,meta=controller.build_packet()
        self.assertLessEqual(len(wire),65536)
        self.assertLessEqual(meta['source_bytes'],65536)
        self.assertEqual(meta['authorization_sha256'],helper.AUTH_SHA)
        self.assertEqual(meta['proposal_sha256'],helper.PROPOSAL_SHA)
        self.assertEqual(meta['source_sha256'],helper.SOURCES)
        self.assertEqual(meta['payload_sha256'],helper.sha(wire))

    def test_bootstrap_imports_exact_modules_without_running(self):
        code=helper.BOOTSTRAP.split('with m.Journal.create',1)[0]
        real_open=builtins.open
        mapping={'/v2.py':controller.ROOT/controller.SOURCE_PATHS['v2.py'],
                 '/gate.py':controller.ROOT/controller.SOURCE_PATHS['gate.py'],
                 '/v3.py':controller.ROOT/controller.SOURCE_PATHS['v3.py']}
        def mapped_open(path,*args,**kwargs):
            return real_open(mapping.get(path,path),*args,**kwargs)
        with mock.patch.dict(sys.modules,{}),mock.patch('builtins.open',side_effect=mapped_open):
            scope={}
            exec(compile(code,'<bootstrap-prefix>','exec'),scope)
            self.assertEqual(scope['m'].gate.__file__,'/gate.py')
            self.assertEqual(scope['m'].FIXED_PROFILES,('success','failure','timeout_group'))

    def test_realistic_full_receipt_fits_and_replays(self):
        raw,live=healthy_journal()
        receipt=healthy_receipt(raw,live)
        self.assertLessEqual(len(raw),8192)
        self.assertLessEqual(len(helper.encode(receipt)),helper.RECEIPT_CAP)
        self.assertLessEqual(len(helper.encode(receipt)),16384)
        with tempfile.TemporaryDirectory() as tmp:
            result=dict(exit_code=0,stdout=helper.encode(receipt),stderr=b'',timeout=False,
                        overflow=False,write_failed=False,threads_incomplete=False)
            admitted,replay=controller.admitted(result,Path(tmp))
            self.assertTrue(admitted['gate_pass'])
            self.assertEqual(replay['head_sha256'],live['head_sha256'])
            self.assertFalse(replay['fsync_acknowledgments_verified'])

    def test_malformed_response_and_tampered_journal_fail_closed(self):
        raw,live=healthy_journal()
        receipt=healthy_receipt(raw,live)
        receipt['journal_sha256']='0'*64
        result=dict(exit_code=0,stdout=helper.encode(receipt),stderr=b'',timeout=False,
                    overflow=False,write_failed=False,threads_incomplete=False)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'JOURNAL_HASH'):
                controller.admitted(result,Path(tmp))
        with self.assertRaises(ValueError):
            helper.parse('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            helper.parse('{"a":NaN}')

    def test_budget_reserves_cleanup_bytes_and_time(self):
        with mock.patch.object(helper.time,'monotonic',return_value=100):
            budget=helper.Budget()
        budget.read_bytes=helper.NORMAL_CAP
        with self.assertRaisesRegex(ValueError,'CUMULATIVE_READ_CAP'):
            budget.allowance()
        self.assertEqual(budget.allowance(cleanup=True),1024)
        with mock.patch.object(helper.time,'monotonic',return_value=141):
            with self.assertRaisesRegex(ValueError,'SESSION_DEADLINE'):
                budget.timeout(5)
            self.assertEqual(budget.timeout(5,cleanup=True),5)

    def test_config_rejects_gpu_extra_mount_and_wrong_rootfs(self):
        mounts=[dict(Type='bind',Source=helper.ROOT+'/'+name,Destination='/'+name,RW=False)
                for name in helper.SOURCES]
        mounts.append(dict(Type='bind',Source=helper.ROOT+'/journal',Destination='/journal',RW=True))
        user='1000:1000'
        config={'Image':helper.IMAGE,'AttemptLabel':helper.MARK,'HostConfig.Memory':134217728,
                'HostConfig.MemorySwap':134217728,'HostConfig.PidsLimit':16,
                'HostConfig.ReadonlyRootfs':True,'HostConfig.Privileged':False,
                'HostConfig.NetworkMode':'none','HostConfig.CgroupnsMode':'private',
                'HostConfig.CapDrop':['ALL'],'HostConfig.SecurityOpt':['no-new-privileges'],
                'HostConfig.DeviceRequests':None,'HostConfig.Devices':[],
                'HostConfig.Init':False,'HostConfig.Runtime':'runc',
                'HostConfig.IpcMode':'none','HostConfig.PidMode':'',
                'HostConfig.CgroupParent':'','HostConfig.Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=1048576,mode=1777'},
                'Config.User':user,'Config.Entrypoint':['python3'],
                'Config.Cmd':['-I','-S','-B','-c',helper.BOOTSTRAP],
                'Config.WorkingDir':'/tmp','Config.Healthcheck':{'Test':['NONE']},
                'Mounts':mounts}
        helper.verify(config,user)
        for field,bad in [('HostConfig.ReadonlyRootfs',False),('HostConfig.DeviceRequests',[{}]),
                          ('Mounts',mounts+[dict(Type='bind',Source='/x',Destination='/x',RW=True)])]:
            modified=dict(config,**{field:bad})
            with self.assertRaises(ValueError):
                helper.verify(modified,user)

    def test_image_volume_preflight_blocks_before_any_root_write(self):
        values=[b'"2"\n"linux"\ntrue\n',
                ('"%s"\n{"/implicit":{}}\n"linux"\n'%helper.IMAGE).encode()]
        with mock.patch.object(helper,'validate',return_value={}),\
             mock.patch.object(helper.sys,'platform','linux'),\
             mock.patch.object(helper.os,'uname',create=True,return_value=mock.Mock(nodename='bupt-gpus1')),\
             mock.patch.object(helper.os,'getuid',create=True,return_value=1000),\
             mock.patch.object(helper,'checked',side_effect=values),\
             mock.patch.object(helper,'new_root') as root:
            with self.assertRaisesRegex(ValueError,'IMAGE_ID_VOLUMES_OS'):
                helper.execute({})
            root.assert_not_called()

    def test_controller_create_once_and_start_ack_before_transport(self):
        raw,live=healthy_journal()
        receipt=healthy_receipt(raw,live)
        result=dict(exit_code=0,stdout=helper.encode(receipt),stderr=b'',timeout=False,
                    overflow=False,write_failed=False,threads_incomplete=False,
                    remote_termination_verified=False)
        with tempfile.TemporaryDirectory() as tmp:
            phase=Path(tmp)/'phase'
            def fake_transport(_cmd,_wire,_cap):
                rows=(phase/'sessions.jsonl').read_bytes().splitlines()
                self.assertEqual([json.loads(row)['event'] for row in rows],['START'])
                return result
            with mock.patch.object(controller,'PHASE',phase),\
                 mock.patch.object(controller,'build_packet',return_value=(b'wire',{'payload_sha256':'b'*64})),\
                 mock.patch.object(controller,'review',return_value='a'*64),\
                 mock.patch.object(controller.io,'verify_cached_host',return_value=controller.HOST_PIN),\
                 mock.patch.object(controller.io,'command',return_value=['FAKE']),\
                 mock.patch.object(controller.io,'transport',side_effect=fake_transport) as transport:
                self.assertEqual(controller.run(),0)
                with self.assertRaisesRegex(ValueError,'NO_REPEAT_PHASE_ROOT'):
                    controller.run()
                transport.assert_called_once()
            self.assertTrue((phase/'01_execute/events.jsonl').is_file())
            self.assertEqual([json.loads(x)['event'] for x in
                              (phase/'sessions.jsonl').read_bytes().splitlines()],['START','END'])

    def test_controller_failure_consumes_only_attempt(self):
        result=dict(exit_code=2,stdout=b'{"status":"FAILED"}',stderr=b'',timeout=False,
                    overflow=False,write_failed=False,threads_incomplete=False,
                    remote_termination_verified=False)
        with tempfile.TemporaryDirectory() as tmp:
            phase=Path(tmp)/'phase'
            with mock.patch.object(controller,'PHASE',phase),\
                 mock.patch.object(controller,'build_packet',return_value=(b'wire',{'payload_sha256':'b'*64})),\
                 mock.patch.object(controller,'review',return_value='a'*64),\
                 mock.patch.object(controller.io,'verify_cached_host',return_value=controller.HOST_PIN),\
                 mock.patch.object(controller.io,'command',return_value=['FAKE']),\
                 mock.patch.object(controller.io,'transport',return_value=result) as transport:
                self.assertEqual(controller.run(),2)
                with self.assertRaisesRegex(ValueError,'NO_REPEAT_PHASE_ROOT'):
                    controller.run()
                transport.assert_called_once()
            self.assertFalse((phase/'01_execute/events.jsonl').exists())

    def _fake_execute(self, create_error=False, foreign=False):
        raw,live=healthy_journal()
        cid='a'*64
        image=('"%s"\nnull\n"linux"\n'%helper.IMAGE).encode()
        outputs=[b'"2"\n"linux"\ntrue\n',image]
        def checked(argv,*_args,**_kwargs):
            if argv[:2]==['docker','create']:
                if create_error:
                    raise helper.CommandError('LOST_CREATE_RESPONSE',b'')
                return (cid+'\n').encode()
            return outputs.pop(0)
        states=[{'State.Running':False,'State.Status':'created'},
                {'State.Running':False,'State.Status':'exited',
                 'State.ExitCode':0,'State.OOMKilled':False}]
        def inspect(_cid,_budget,cleanup=False):
            if cleanup:
                return dict(Image=helper.IMAGE,AttemptLabel=('foreign' if foreign else helper.MARK),
                            running=True,exit_code=137)
            return states.pop(0)
        live_output=helper.encode(dict(schema='e78-container-live-v1',
              status='PASS_FIXED_LINUX_JOURNAL_ONLY',live_summary=live,
              execution_ready=False,training_release=False))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(helper,'validate',return_value={}))
            stack.enter_context(mock.patch.object(helper.sys,'platform','linux'))
            stack.enter_context(mock.patch.object(helper.os,'uname',create=True,
                                                  return_value=mock.Mock(nodename='bupt-gpus1')))
            stack.enter_context(mock.patch.object(helper.os,'getuid',create=True,return_value=1000))
            stack.enter_context(mock.patch.object(helper.os,'getgid',create=True,return_value=1000))
            stack.enter_context(mock.patch.object(helper,'checked',side_effect=checked))
            stack.enter_context(mock.patch.object(helper,'new_root',return_value=17))
            stack.enter_context(mock.patch.object(helper,'write_at',return_value=(1,2)))
            stack.enter_context(mock.patch.object(helper.os,'mkdir',return_value=None))
            stack.enter_context(mock.patch.object(helper.os,'fsync',return_value=None))
            stack.enter_context(mock.patch.object(helper.os,'close',return_value=None))
            stack.enter_context(mock.patch.object(helper.os,'listdir',return_value=['v2.py','gate.py',
                  'v3.py','journal','execution_manifest.json','container.id']))
            stack.enter_context(mock.patch.object(helper,'cid_file',return_value=cid))
            stack.enter_context(mock.patch.object(helper,'inspect',side_effect=inspect))
            stack.enter_context(mock.patch.object(helper,'verify'))
            stack.enter_context(mock.patch.object(helper,'read_journal',return_value=raw))
            runner=stack.enter_context(mock.patch.object(helper,'run',return_value=(0,live_output)))
            receipt=helper.execute({})
        return receipt,runner

    def test_helper_complete_mocked_one_container_three_profiles(self):
        receipt,runner=self._fake_execute()
        self.assertTrue(receipt['gate_pass'])
        self.assertEqual(receipt['status'],'PASS_FIXED_LINUX_JOURNAL_ONLY')
        self.assertEqual(receipt['container_id'],'a'*64)
        self.assertEqual(receipt['live_summary']['attempt_count'],3)
        self.assertEqual(runner.call_count,1)
        self.assertEqual(runner.call_args.args[0][:3],['docker','start','--attach'])
        self.assertLessEqual(len(helper.encode(receipt)),helper.RECEIPT_CAP)

    def test_lost_create_response_recovers_cid_and_kills_only_owned(self):
        receipt,runner=self._fake_execute(create_error=True)
        self.assertFalse(receipt['gate_pass'])
        self.assertEqual(receipt['container_id'],'a'*64)
        self.assertEqual(runner.call_args.args[0][:2],['docker','kill'])

    def test_foreign_label_never_killed(self):
        receipt,runner=self._fake_execute(create_error=True,foreign=True)
        self.assertFalse(receipt['gate_pass'])
        self.assertFalse(receipt['cleanup_verified'])
        runner.assert_not_called()

    def test_journal_exact_prebudget_read_and_same_size_tamper(self):
        def row(mode,size,ctime=1):
            return SimpleNamespace(st_mode=mode,st_nlink=1,st_size=size,st_dev=1,
                                   st_ino=17 if mode==0o40700 else 18,
                                   st_mtime_ns=1,st_ctime_ns=ctime)
        directory=row(0o40700,0)
        file=row(0o100600,3)
        changed=row(0o100600,3,2)
        def attempt(after):
            budget=helper.Budget();budget.read_bytes=helper.NORMAL_CAP-3
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(helper.os,'O_DIRECTORY',1,create=True))
                stack.enter_context(mock.patch.object(helper.os,'O_NOFOLLOW',2,create=True))
                stack.enter_context(mock.patch.object(helper.os,'open',side_effect=[17,18]))
                stack.enter_context(mock.patch.object(helper.os,'fstat',side_effect=[directory,file,after,directory]))
                stack.enter_context(mock.patch.object(helper.os,'stat',side_effect=[directory,file,file,directory]))
                read=stack.enter_context(mock.patch.object(helper.os,'read',return_value=b'abc'))
                stack.enter_context(mock.patch.object(helper.os,'close',return_value=None))
                if after is changed:
                    with self.assertRaisesRegex(ValueError,'JOURNAL_CHANGED'):
                        helper.read_journal(16,budget)
                else:
                    self.assertEqual(helper.read_journal(16,budget),b'abc')
                read.assert_called_once_with(18,3)
                self.assertEqual(budget.read_bytes,helper.NORMAL_CAP)
        attempt(file)
        attempt(changed)


if __name__=='__main__':
    unittest.main()
