"""E77 local mock receipts. All kernel/process/scratch operations are intercepted."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest import mock
from src.data import prospective_linux_journal_v3 as linux


def require(ok,reason):
    if not ok:raise ValueError(reason)


def run(output):
    repo=Path(__file__).resolve().parents[1]
    staging=(repo.parent/'runtime_training_staging_20260928').resolve()
    output=Path(output).resolve()
    require(output.parent==staging and output.name.startswith('v6_e77_mock_demo_'), 'FIXED_OUTPUT')
    helper=repo/'tests/test_prospective_linux_journal_v3.py'
    require(helper.is_file()and not helper.is_symlink()and helper.stat().st_size<=32768,'FIXED_TEST_HELPER')
    spec=importlib.util.spec_from_file_location('_e77_fixed_mock_helper',helper)
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    output.mkdir(exist_ok=False)
    rows=[]
    cases=('healthy','intent_ack','unknown_spawn','none_handle','identity_read',
           'launched_ack','cleanup_failure','terminal_ack')
    for case in cases:
        path=output/(case+'.jsonl');fake=fixture.FakeLinux();caught=None
        if case=='unknown_spawn':fake.spawn_error=OSError('fixture unknown spawn')
        if case=='identity_read':fake.metadata_error=RuntimeError('fixture identity read')
        if case=='cleanup_failure':fake.cleanup_error=RuntimeError('fixture cleanup')
        with fake.patched(),linux.Journal.create(str(path))as journal:
            backend=linux.FixedLinuxBackend();clock=fixture.Clock()
            popen=linux.subprocess.Popen
            if case=='none_handle':popen.side_effect=lambda *args,**kwargs:None
            try:
                if case=='intent_ack':
                    with mock.patch.object(journal,'append',side_effect=OSError('fixture intent ACK')):
                        journal.run('first','success',backend,clock)
                elif case=='launched_ack':
                    original=journal.append
                    def fail_identity(kind,aid,payload):
                        if kind=='LAUNCHED':raise OSError('fixture identity ACK')
                        return original(kind,aid,payload)
                    with mock.patch.object(journal,'append',side_effect=fail_identity):
                        journal.run('first','success',backend,clock)
                elif case=='terminal_ack':
                    journal.run('before-terminal-0','success',backend,clock)
                    journal.run('before-terminal-1','failure',backend,clock)
                    fsync=linux.os.fsync;calls=[0]
                    def fail_terminal(fd):
                        calls[0]+=1
                        if calls[0]==3:raise OSError('fixture terminal ACK')
                        return fsync(fd)
                    with mock.patch.object(linux.os,'fsync',side_effect=fail_terminal):
                        journal.run('terminal-third','timeout_group',backend,clock)
                else:
                    for index,profile in enumerate(linux.FIXED_PROFILES if case=='healthy'else('success',)):
                        journal.run('attempt-%d'%index,profile,backend,clock)
            except BaseException as exc:caught=type(exc).__name__
            live=journal.snapshot();spawn_calls=popen.call_count
            if case=='healthy':
                require(caught is None and live['complete_live_acknowledged']and
                    live['observed_identity_records']==3,'HEALTHY_COMPLETE')
            else:
                require(caught is not None and not live['complete_live_acknowledged']and
                    live['observed_interval_ns_sum_or_None']is None,'FAILURE_INCOMPLETE')
                try:journal.run('blocked-next','failure',backend,clock)
                except (ValueError,RuntimeError):pass
                else:raise ValueError('LATER_ATTEMPT_NOT_BLOCKED')
                require(popen.call_count==spawn_calls,'LATER_SPAWN_OCCURRED')
            require(spawn_calls==(3 if case in('healthy','terminal_ack')else 0 if case=='intent_ack'else 1),'FIXED_SPAWN_CALLS')
            require(fake.calls.count('cleanup')==(3 if case in('healthy','terminal_ack')else
                0 if case in('intent_ack','unknown_spawn','none_handle')else 1),'CLEANUP_CALLS')
            require(live['os_authenticated']is False,'MOCK_IS_NOT_OS_PROOF')
        replay=linux.load(str(path))
        require(replay['fsync_acknowledgments_verified']is False and
            replay['observed_interval_ns_sum_or_None']is None,'REPLAY_ACK_NOT_PROVED')
        if case=='healthy':
            require(replay['head_sha256']==live['head_sha256']and replay['attempts']==live['attempts'],
                'LIVE_REPLAY_STRUCTURE')
        if case=='terminal_ack':require(replay['structural_complete']is True,'BYTE_COMPLETE_ACK_FAILURE')
        rows.append(dict(case=case,exception=caught,intercepted_popen_calls=spawn_calls,
            intercepted_cleanup_calls=fake.calls.count('cleanup'),live=live,replay=replay,
            journal_bytes=path.stat().st_size,journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    result=dict(status='PASS_LOCAL_MOCKED_LINUX_JOURNAL_CONNECTION_ONLY',case_count=len(rows),cases=rows,
        fixture_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
        module_sha256=hashlib.sha256((repo/'src/data/prospective_linux_journal_v3.py').read_bytes()).hexdigest(),
        actual_v3_children=0,new_remote_sessions=0,new_containers=0,integrated_live_linux_validation=False,
        os_authenticated=False,fixture_clock_not_measured_wall_time=True,
        execution_ready=False,training_release=False)
    with(output/'summary.json').open('x',encoding='utf-8',newline='\n')as stream:
        json.dump(result,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps(dict(status=result['status'],case_count=len(rows),actual_v3_children=0,
        integrated_live_linux_validation=False,execution_ready=False,training_release=False)))
    return 0


if __name__=='__main__':
    require(len(sys.argv)==2,'ONE_FIXED_LOCAL_OUTPUT')
    raise SystemExit(run(sys.argv[1]))
