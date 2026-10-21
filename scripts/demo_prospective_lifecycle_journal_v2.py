"""Deterministic in-process E76 fault fixtures: no children, Docker or network."""
import hashlib
import json
from pathlib import Path
import sys
from unittest import mock
from src.data import prospective_lifecycle_journal_v2 as lifecycle


class FixtureClock:
    def __init__(self):self.ns=0
    def capture(self):
        self.ns+=100
        return ('fixture-clock',self.ns)


class FixtureCancel(BaseException):pass


class FixtureBackend:
    synthetic_only=True
    os_authenticated=False
    actual_processes=0

    def __init__(self,fault=None):
        self.fault=fault;self.launches=0;self.cleanups=0

    def launch(self,profile):
        self.launches+=1
        if self.fault=='unknown_spawn':raise RuntimeError('synthetic unknown spawn')
        return (None if self.fault=='none_handle'else object()),dict(host='synthetic-fixture',boot_id='fixture-boot',
            pid=self.launches+10,start_ticks=self.launches+100)

    def finish(self,handle,profile):
        if self.fault=='finish_error':raise RuntimeError('synthetic finish failure')
        if self.fault=='cancellation':raise FixtureCancel('synthetic cancellation')
        status,rc,timeout=lifecycle.EXPECTED[profile]
        return dict(status=status,returncode=rc,timed_out=timeout)

    def cleanup(self,handle):
        self.cleanups+=1
        return dict(leader_reaped=True,observed_group_empty=self.fault!='residual_group')


def require(ok,code):
    if not ok:raise ValueError(code)


def run(output):
    staging=(Path(__file__).resolve().parents[2]/'runtime_training_staging_20260928').resolve()
    output=Path(output).resolve()
    require(output.parent==staging and output.name.startswith('v6_e76_local_journal_demo_'),
        'FIXED_LOCAL_OUTPUT_ROOT')
    output.mkdir(exist_ok=False)
    rows=[]
    cases=('healthy','intent_ack_error','unknown_spawn','none_handle','finish_error',
           'residual_group','cancellation','terminal_ack_error')
    for case in cases:
        path=output/(case+'.jsonl')
        backend=FixtureBackend(case);clock=FixtureClock();caught=None
        with lifecycle.Journal.create(str(path))as journal:
            try:
                if case=='intent_ack_error':
                    with mock.patch.object(lifecycle.os,'fsync',side_effect=OSError('fixture intent ACK')):
                        journal.run('fixture-first','success',backend,clock)
                elif case=='terminal_ack_error':
                    actual_fsync=lifecycle.os.fsync
                    counter=[0]
                    def terminal_failure(fd):
                        counter[0]+=1
                        if counter[0]==3:raise OSError('fixture terminal ACK')
                        return actual_fsync(fd)
                    with mock.patch.object(lifecycle.os,'fsync',side_effect=terminal_failure):
                        journal.run('fixture-first','success',backend,clock)
                else:
                    for index,profile in enumerate(lifecycle.PROFILES if case=='healthy'else ('success',)):
                        journal.run('fixture-%d'%index,profile,backend,clock)
            except BaseException as exc:
                caught=type(exc).__name__
            live=journal.snapshot()
            if case=='healthy':
                require(caught is None and live['complete_live_acknowledged']and live['attempt_count']==3,
                    'HEALTHY_PHASE_REQUIRED')
                require(live['observed_interval_ns_sum_or_None']==300,'FIXTURE_INTERVAL_SUM')
            else:
                require(caught is not None and not live['complete_live_acknowledged']and
                    live['observed_interval_ns_sum_or_None']is None,'INCOMPLETE_MUST_NOT_RELEASE_SUM')
                count=backend.launches
                try:journal.run('forbidden-next','success',backend,clock)
                except (ValueError,RuntimeError):pass
                else:raise ValueError('LATER_PROFILE_NOT_BLOCKED')
                require(backend.launches==count,'LATER_BACKEND_LAUNCHED')
            require(backend.launches==(3 if case=='healthy'else 0 if case=='intent_ack_error'else 1),
                'LAUNCH_BOUND')
            require(backend.cleanups==(3 if case=='healthy'else 0 if case in('intent_ack_error','unknown_spawn','none_handle')else 1),
                'KNOWN_HANDLE_CLEANUP_REQUIRED')
        replay=lifecycle.load(str(path))
        require(replay['fsync_acknowledgments_verified']is False and
            replay['observed_interval_ns_sum_or_None']is None,'REPLAY_BYTES_NOT_ACK_PROOF')
        if case=='healthy':
            require(replay['head_sha256']==live['head_sha256']and replay['attempts']==live['attempts'],
                'STRUCTURAL_REPLAY_MATCH')
        if case=='terminal_ack_error':
            require(replay['structural_complete']is True,'BYTE_COMPLETE_TERMINAL_FIXTURE')
        rows.append(dict(case=case,exception=caught,backend_launch_calls=backend.launches,
            cleanup_calls=backend.cleanups,live=live,replay=replay,
            journal_bytes=path.stat().st_size,journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    result=dict(status='PASS_LOCAL_SYNTHETIC_JOURNAL_INTEGRATION_ONLY',cases=rows,
        case_count=len(rows),real_processes=0,remote_sessions=0,new_containers=0,
        synthetic_only=True,os_authenticated=False,real_atpg_jobs=0,training_runs=0,
        fixture_clock_not_measured_wall_runtime=True,integrated_live_linux_validation=False,
        execution_ready=False,training_release=False)
    with(output/'summary.json').open('x',encoding='utf-8',newline='\n')as stream:
        json.dump(result,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps(dict(status=result['status'],case_count=len(rows),real_processes=0,
        remote_sessions=0,execution_ready=False,training_release=False)))
    return 0


if __name__=='__main__':
    require(len(sys.argv)==2,'ONE_LOCAL_RECEIPT_DIRECTORY')
    raise SystemExit(run(sys.argv[1]))
