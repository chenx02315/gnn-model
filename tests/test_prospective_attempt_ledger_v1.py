"""Toy circuits, synthetic clocks and temporary journals only; no execution."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from src.data import prospective_attempt_ledger_v1 as m

PLAN_SHA = 'a'*64
UTC = '2030-01-01T00:00:00Z'


def provenance(**changes):
    value = dict(driver_sha256='b'*64, config_sha256='c'*64,
        plan_sha256=PLAN_SHA, input_sha256='d'*64, environment_cohort='toy-env',
        clock_identity='toy-clock', command_sha256='e'*64,
        output_root='/toy/output', job_identity='toy-job')
    value.update(changes)
    return value


def plan(aid='p1', action='toy-action', parents=None, retry=None, **changes):
    value = dict(attempt_id=aid, circuit='toy-circuit', action=action, call_key='toy-operation',
        parents=parents or [], retry_of=retry, provenance=provenance(), cost_node=m.COST_NODE)
    value.update(changes)
    return value


def start(aid='p1', ns=10, **changes):
    value = dict(attempt_id=aid, clock_session='toy-clock', monotonic_ns=ns, utc=UTC,
                 execution_identity=dict(host='toy-host', job_id=None, pid=None))
    value.update(changes)
    return value


def end(aid='p1', ns=20, state='SUCCESS', **changes):
    value = dict(attempt_id=aid, state=state, clock_session='toy-clock', monotonic_ns=ns,
        utc=UTC, termination_verified=True, d95=True, ate_cycles=123,
        output_artifact_sha256='f'*64)
    value.update(changes)
    return value


def success(ledger, aid='p1', action='toy-action', parents=None):
    ledger.record('PLAN', plan(aid, action, parents))
    ledger.record('START', start(aid))
    ledger.record('END', end(aid))


def cache(action='cached', aid='p1', **changes):
    value = dict(action=action, attempt_id=aid, circuit='toy-circuit',
        call_key='toy-operation', provenance=provenance(), output_artifact_sha256='f'*64)
    value.update(changes)
    return value


class LedgerTests(unittest.TestCase):
    def test_nominal_states_and_independent_quality(self):
        ledger=m.Ledger(PLAN_SHA)
        ledger.record('PLAN',plan());ledger.record('START',start())
        ledger.record('END',end(d95=False,ate_cycles=999999))
        result=ledger.aggregate(['toy-action'])
        self.assertEqual(result['physical_atpg_wall_ns_sum'],10)
        self.assertTrue(result['complete'])
        for flag in ('online_cost_complete','execution_ready','quality_used_to_filter_cost','wall_clock_makespan_computed'):
            self.assertFalse(result[flag])
        self.assertTrue(result['cache_lookup_overhead_unmeasured'])

    def test_failed_retry_includes_all_predecessors_not_fastest(self):
        ledger=m.Ledger(PLAN_SHA)
        ledger.record('PLAN',plan());ledger.record('START',start(ns=10))
        ledger.record('END',end(ns=110,state='FAILED',d95=None,ate_cycles=None,output_artifact_sha256=None))
        ledger.record('PLAN',plan('p2','retry-action',retry='p1',
            provenance=provenance(output_root='/different',job_identity='new-job')))
        ledger.record('START',start('p2',200));ledger.record('END',end('p2',210))
        result=ledger.aggregate(['retry-action'])
        self.assertEqual(result['attempt_ids'],['p1','p2'])
        self.assertEqual(result['physical_atpg_wall_ns_sum'],110)

    def test_shared_parent_action_links_cache_once(self):
        ledger=m.Ledger(PLAN_SHA);success(ledger)
        success(ledger,'p2','second',['p1'])
        ledger.record('LINK',dict(action='shared',attempt_id='p1'))
        ledger.record('CACHE',cache(provenance=provenance(output_root='/consumer',job_identity='consumer')))
        result=ledger.aggregate(['second','shared','cached','second'])
        self.assertEqual(result['attempt_ids'],['p1','p2'])
        self.assertEqual(result['physical_atpg_wall_ns_sum'],20)

    def test_cache_wrong_identity_artifact_or_external_rejected(self):
        ledger=m.Ledger(PLAN_SHA);success(ledger)
        for changes in ({'attempt_id':'external'},{'circuit':'other'}, {'call_key':'other'},
                {'provenance':provenance(environment_cohort='other')},
                {'provenance':provenance(input_sha256='1'*64)}, {'output_artifact_sha256':'1'*64}):
            with self.assertRaises(ValueError):ledger.record('CACHE',cache(**changes))
        self.assertEqual(len(ledger.snapshot()['attempts']),1)
        with self.assertRaises(ValueError):ledger.aggregate(['external'])

    def test_cache_requires_verified_success_artifact(self):
        for state in ('PLANNED','FAILED','SUCCESS'):
            ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan())
            if state!='PLANNED':
                ledger.record('START',start())
                ledger.record('END',end(state=state,output_artifact_sha256=None))
            with self.assertRaises(ValueError):ledger.record('CACHE',cache())

    def test_duplicate_dag_retry_and_atomic_cost_node(self):
        ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan())
        for payload in (plan(),plan('p2',parents=['future']),plan('p2',parents=['p2']),
                plan('p2',parents=['p1','p1']),plan('p2',retry='p1'),
                plan('p2',cost_node='WRAPPER_INCLUDING_CHILDREN')):
            with self.assertRaises(ValueError):ledger.record('PLAN',payload)
        ledger.record('START',start());ledger.record('END',end(state='FAILED'))
        for payload in (plan('p2',retry='p1',call_key='other'),
                plan('p2',retry='p1',provenance=provenance(config_sha256='1'*64))):
            with self.assertRaises(ValueError):ledger.record('PLAN',payload)

    def test_same_candidate_different_call_keys_not_cache_equivalent(self):
        ledger=m.Ledger(PLAN_SHA);success(ledger)
        with self.assertRaisesRegex(ValueError,'CACHE_IDENTITY'):
            ledger.record('CACHE',cache(call_key='same-spelling-different-operation'))

    def test_clock_ns_and_terminal_transitions(self):
        ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan())
        for payload in (start(ns=True),start(ns=-1),start(clock_session='other'),
                start(execution_identity=dict(host='host',job_id=None,pid=True))):
            with self.assertRaises(ValueError):ledger.record('START',payload)
        ledger.record('START',start())
        for payload in (end(ns=9),end(clock_session='other'),end(ate_cycles=True),
                end(d95=1),end(termination_verified=False),end(ns=2**63)):
            with self.assertRaises(ValueError):ledger.record('END',payload)
        ledger.record('END',end())
        with self.assertRaises(ValueError):ledger.record('END',end())

    def test_missing_terminal_is_incomplete_not_free_cost(self):
        ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan())
        for running in (False,True):
            if running:ledger.record('START',start())
            value=ledger.aggregate(['toy-action'])
            self.assertFalse(value['complete'])
            self.assertEqual(value['incomplete_attempt_ids'],['p1'])
            self.assertEqual(value['cost_kind'],'LOWER_BOUND_INCOMPLETE')

    def test_unverified_timeout_and_cancel_are_lower_bounds(self):
        for state in ('TIMEOUT','CANCELLED'):
            ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan());ledger.record('START',start())
            ledger.record('END',end(state=state,termination_verified=False))
            value=ledger.aggregate(['toy-action'])
            self.assertEqual(value['physical_atpg_wall_ns_sum'],10)
            self.assertFalse(value['complete'])
            self.assertEqual(value['unverified_termination_ids'],['p1'])

    def test_explicit_prestart_cancel_only_zero_complete_case(self):
        ledger=m.Ledger(PLAN_SHA);ledger.record('PLAN',plan())
        with self.assertRaises(ValueError):ledger.record('END',end())
        ledger.record('END',end(state='CANCELLED',d95=None,ate_cycles=None,output_artifact_sha256=None))
        value=ledger.aggregate(['toy-action'])
        self.assertTrue(value['complete']);self.assertEqual(value['physical_atpg_wall_ns_sum'],0)

    def test_strict_unknown_keys_and_mutation_failure_atomic(self):
        ledger=m.Ledger(PLAN_SHA)
        for payload in (dict(plan(),cpu_seconds=1),plan(provenance=provenance(extra='x')),
                plan(provenance=provenance(plan_sha256='1'*64))):
            before=(ledger.seq,ledger.head,ledger.snapshot())
            with self.assertRaises(ValueError):ledger.record('PLAN',payload)
            self.assertEqual((ledger.seq,ledger.head,ledger.snapshot()),before)
        event=ledger.event('PLAN',plan());event['seq']=True
        with self.assertRaises(ValueError):ledger.apply(event)

    def test_sum_not_makespan_across_cohorts_overlaps(self):
        ledger=m.Ledger(PLAN_SHA);success(ledger)
        ledger.record('PLAN',plan('p2','second',provenance=provenance(environment_cohort='env2')))
        ledger.record('START',start('p2'));ledger.record('END',end('p2'))
        value=ledger.aggregate(['toy-action','second'])
        self.assertEqual(value['physical_atpg_wall_ns_sum'],20)
        self.assertFalse(value['online_cost_complete'])

    def test_system_clock_helper_explicit_session(self):
        clock=m.SystemClock('synthetic-session')
        with patch.object(m.time,'monotonic_ns',return_value=42,create=True):
            captured=clock.capture()
        self.assertEqual(captured['monotonic_ns'],42)
        self.assertEqual(captured['clock_session'],'synthetic-session')
        m.clock_record(captured)

    def test_windows_identity_exception_is_cross_api_ctime_only(self):
        before=types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=3,st_nlink=1,
            st_size=4,st_mtime_ns=5,st_ctime_ns=6)
        changed=copy.copy(before);changed.st_ctime_ns=7
        with patch.object(m.sys,'platform','win32'):
            self.assertNotEqual(m.file_identity(before),m.file_identity(changed))
            self.assertEqual(m.file_identity(before,True),m.file_identity(changed,True))
            changed.st_mtime_ns=8
            self.assertNotEqual(m.file_identity(before,True),m.file_identity(changed,True))

    def test_bounded_input_rejects_before_copy_or_state_mutation(self):
        ledger=m.Ledger(PLAN_SHA)
        for payload in (dict(plan(),extra='x'*(m.MAX_LINE_BYTES+1)),dict(plan(),extra=float('nan'))):
            with self.assertRaises(ValueError):ledger.record('PLAN',payload)
            self.assertEqual(ledger.seq,0)
        nested=[];root=nested
        for unused in range(20):
            child=[];nested.append(child);nested=child
        with self.assertRaisesRegex(ValueError,'DEPTH'):ledger.record('PLAN',dict(plan(),extra=root))
        with patch.object(m,'MAX_TOTAL_BYTES',ledger.byte_count+1):
            with self.assertRaises(ValueError):ledger.record('PLAN',plan())
        self.assertEqual(ledger.snapshot()['attempts'],{})

    def test_parent_and_action_circuit_binding_for_plan_link_cache(self):
        ledger=m.Ledger(PLAN_SHA);success(ledger)
        success_payload=plan('other','other-action',circuit='toy-other')
        ledger.record('PLAN',success_payload)
        ledger.record('START',start('other'));ledger.record('END',end('other'))
        before=ledger.snapshot()
        for kind,payload in (
                ('PLAN',plan('child','new-action',parents=['other'])),
                ('PLAN',plan('child','toy-action',circuit='toy-other')),
                ('LINK',dict(action='toy-action',attempt_id='other')),
                ('CACHE',cache(action='toy-action',aid='other',circuit='toy-other'))):
            with self.assertRaises(ValueError):ledger.record(kind,payload)
            self.assertEqual(ledger.snapshot(),before)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'toy.jsonl'

    def test_durable_replay_create_once_and_no_invalid_append(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            writer.append('PLAN',plan());writer.append('START',start());writer.append('END',end())
            before=self.path.read_bytes();snapshot=writer.snapshot()
            with self.assertRaises(ValueError):writer.append('END',end())
            self.assertEqual(self.path.read_bytes(),before)
            self.assertEqual(writer.snapshot(),snapshot)
            self.assertEqual(m.load(self.path).snapshot(),snapshot)
            with self.assertRaises(FileExistsError):m.Journal.create(self.path,PLAN_SHA)
        self.assertEqual(m.load(self.path).aggregate(['toy-action'])['physical_atpg_wall_ns_sum'],10)

    def test_chain_tampering_unknown_schema_and_duplicate_keys(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:writer.append('PLAN',plan())
        original=self.path.read_bytes()
        for changed in (original.replace(b'toy-circuit',b'bad-circuit'),
                original.replace(b'"seq":1',b'"seq":2'),
                original.replace(b'"seq":1',b'"seq":1,"seq":1'),
                original.replace(b'prospective_attempt_ledger_v1',b'prospective_attempt_ledger_v0')):
            self.path.write_bytes(changed)
            with self.assertRaises(ValueError):m.load(self.path)
        self.path.write_bytes(original)
        self.assertEqual(m.load(self.path).seq,1)

    def test_torn_tail_rejected_preserved_not_repaired(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:writer.append('PLAN',plan())
        raw=self.path.read_bytes()+b'{"seq":2'
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'INCOMPLETE_PARTIAL_TAIL'):m.load(self.path)
        self.assertEqual(self.path.read_bytes(),raw)

    def test_stale_external_tail_poisons_writer(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            with self.path.open('ab') as external:external.write(b'x')
            with self.assertRaisesRegex(ValueError,'STALE_TAIL'):writer.append('PLAN',plan())
            self.assertEqual(writer.snapshot()['attempts'],{})
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.append('PLAN',plan())
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.aggregate(['toy-action'])

    def test_fsync_failure_poison_and_inmemory_not_published(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            with patch.object(m.os,'fsync',side_effect=OSError('toy-disk-failure')):
                with self.assertRaises(OSError):writer.append('PLAN',plan())
            self.assertEqual(writer.snapshot()['attempts'],{})
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.append('PLAN',plan())
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.aggregate(['toy-action'])
        # Complete bytes may exist despite failed durability acknowledgement. Replay
        # never silently truncates them or claims fsync success.
        self.assertEqual(m.load(self.path).seq,1)

    def test_external_tail_detected_by_aggregate_before_complete_claim(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            writer.append('PLAN',plan());writer.append('START',start());writer.append('END',end())
            self.assertTrue(writer.aggregate(['toy-action'])['complete'])
            with self.path.open('ab') as external:external.write(b'crash-tail')
            with self.assertRaisesRegex(ValueError,'STALE_TAIL'):writer.aggregate(['toy-action'])
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.aggregate(['toy-action'])

    def test_partial_write_crash_poison_and_torn_replay(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            original=writer._stream
            class PartialStream:
                closed=False
                def fileno(self):return original.fileno()
                def write(self,raw):
                    original.write(raw[:5]);original.flush()
                    raise OSError('synthetic-crash')
                def close(self):original.close();self.closed=True
            writer._stream=PartialStream()
            with self.assertRaises(OSError):writer.append('PLAN',plan())
            self.assertEqual(writer.snapshot()['attempts'],{})
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):writer.append('PLAN',plan())
        raw=self.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'PARTIAL_TAIL'):m.load(self.path)
        self.assertEqual(self.path.read_bytes(),raw)

    def test_event_line_and_total_bounds_are_prewrite(self):
        with m.Journal.create(self.path,PLAN_SHA) as writer:
            before=self.path.read_bytes()
            for key,limit in (('MAX_EVENTS',0),('MAX_LINE_BYTES',100),('MAX_TOTAL_BYTES',len(before)+10)):
                with patch.object(m,key,limit):
                    with self.assertRaises(ValueError):writer.append('PLAN',plan())
                self.assertEqual(self.path.read_bytes(),before)
                self.assertEqual(writer.snapshot()['attempts'],{})
            writer.append('PLAN',plan())
        with patch.object(m,'MAX_TOTAL_BYTES',1):
            with self.assertRaises(ValueError):m.load(self.path)

    def test_replay_noncanonical_and_missing_header_rejected(self):
        for raw in (b'',b'{}\n',b'{"schema_version": "prospective_attempt_ledger_v1"}\n'):
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):m.load(self.path)


if __name__=='__main__':
    unittest.main()
