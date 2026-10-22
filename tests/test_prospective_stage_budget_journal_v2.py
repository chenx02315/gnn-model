"""Local journal fault tests only; no child process or external data."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import prospective_stage_budget_journal_v2 as m


def plan():
    return [dict(task_uid='h',kind='TESSENT_STAGE',stage='H',request_sha256='a'*64,
                 depends_on=[],timeout_ns=10,cleanup_ns=2),
            dict(task_uid='translate-m',kind='STATUS_TRANSLATION',stage='M',
                 request_sha256='b'*64,depends_on=[],timeout_ns=10,cleanup_ns=2),
            dict(task_uid='m',kind='TESSENT_STAGE',stage='M',request_sha256='b'*64,
                 depends_on=['translate-m'],timeout_ns=10,cleanup_ns=2)]


def create(path,task_plan=None,**caps):
    return m.Journal.create(path,plan() if task_plan is None else task_plan,
            max_tessent_calls=caps.get('max_tessent_calls',2),
            max_translation_calls=caps.get('max_translation_calls',1),
            phase_envelope_ns=caps.get('phase_envelope_ns',36))


def settle_success(journal,uid):
    token=journal.reserve(uid)
    journal.settle(token,'SUCCESS',8,True)
    return token


class StageJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'events.jsonl'

    def test_complete_three_tasks_live_ack_then_replay_no_historical_ack(self):
        with create(self.path) as journal:
            with self.assertRaisesRegex(ValueError,'EXACT_NEXT_SLOT'):
                journal.reserve('renamed-h')
            tokens=[settle_success(journal,uid) for uid in ('h','translate-m','m')]
            live=journal.snapshot()
            self.assertEqual([t['task']['task_uid'] for t in tokens],['h','translate-m','m'])
            self.assertTrue(live['declared_plan_complete'])
            self.assertTrue(live['durable_debit_ack_verified'])
            self.assertEqual(live['event_count'],6)
            self.assertEqual(live['reserved_envelope_ns'],36)
            self.assertEqual(live['asserted_elapsed_ns_sum'],24)
            self.assertFalse(live['launch_authorized'])
            self.assertFalse(live['execution_ready'])
        self.assertFalse(journal.snapshot()['durable_debit_ack_verified'])
        replay=m.load(self.path)
        self.assertTrue(replay['structural_replay_valid'])
        self.assertTrue(replay['declared_plan_complete'])
        self.assertEqual(replay['head_sha256'],live['head_sha256'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['asserted_elapsed_ns_sum'])
        with self.assertRaises(FileExistsError):
            create(self.path)
        with self.assertRaises(TypeError):
            m.Journal()

    def test_replay_rejects_fifo_before_open_and_uses_nonblocking_flag(self):
        with create(self.path):
            pass
        original_lstat=m.os.lstat
        original_open=m.os.open
        observed=[]

        def record_open(path,flags,*args,**kwargs):
            observed.append(flags)
            return original_open(path,flags,*args,**kwargs)

        with mock.patch.object(m.os,'open',side_effect=record_open):
            self.assertTrue(m.load(self.path)['structural_replay_valid'])
        self.assertTrue(observed)
        if hasattr(os,'O_NONBLOCK'):
            self.assertTrue(observed[-1]&os.O_NONBLOCK)

        def fifo_at_target(path,*args,**kwargs):
            if os.fspath(path)==os.fspath(self.path):
                return SimpleNamespace(st_mode=m.stat.S_IFIFO,st_nlink=1,st_size=0)
            return original_lstat(path,*args,**kwargs)

        with mock.patch.object(m.os,'lstat',side_effect=fifo_at_target):
            with mock.patch.object(m.os,'open') as blocked_open:
                with self.assertRaisesRegex(ValueError,'REPLAY_FILE_IDENTITY'):
                    m.load(self.path)
                blocked_open.assert_not_called()

    def test_dependency_cap_denial_and_no_refund_or_retry(self):
        with create(self.path,max_tessent_calls=1) as journal:
            with self.assertRaisesRegex(ValueError,'EXACT_NEXT_SLOT'):
                journal.reserve('translate-m')
            settle_success(journal,'h')
            settle_success(journal,'translate-m')
            with self.assertRaisesRegex(ValueError,'CENSORED_DECLARED_BUDGET_EXHAUSTED'):
                journal.reserve('m')
            snap=journal.snapshot()
            self.assertEqual(snap['consumed_counts']['TESSENT_STAGE'],1)
            self.assertEqual(snap['event_count'],5)
            with self.assertRaisesRegex(ValueError,'STOPPED_ACTIVE_OR_FINISHED'):
                journal.reserve('m')
        replay=m.load(self.path)
        self.assertEqual(replay['stopped_reason'],'CENSORED_DECLARED_BUDGET_EXHAUSTED')
        self.assertFalse(replay['durable_debit_ack_verified'])

    def test_failed_and_unknown_settlement_never_retry(self):
        for status,elapsed,cleanup in (('FAILED',5,True),('UNKNOWN',None,False)):
            path=Path(self.tmp.name)/(status+'.jsonl')
            with create(path) as journal:
                token=journal.reserve('h')
                journal.settle(token,status,elapsed,cleanup)
                with self.assertRaisesRegex(ValueError,'STOPPED_ACTIVE_OR_FINISHED'):
                    journal.reserve('translate-m')
                self.assertEqual(journal.snapshot()['consumed_counts']['TESSENT_STAGE'],1)
            replay=m.load(path)
            self.assertEqual(replay['event_count'],2)
            self.assertFalse(replay['declared_plan_complete'])

    def test_debit_full_row_fsync_failure_poison_replay_ack_false(self):
        journal=create(self.path)
        try:
            with mock.patch.object(m.os,'fsync',side_effect=OSError('injected')):
                with self.assertRaises(OSError):
                    journal.reserve('h')
            self.assertTrue(journal.snapshot()['writer_poisoned'])
            with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                journal.reserve('h')
        finally:journal.close()
        replay=m.load(self.path)
        self.assertEqual(replay['event_count'],1)
        self.assertEqual(replay['active_slot'],0)
        self.assertFalse(replay['durable_debit_ack_verified'])

    def test_settlement_full_row_fsync_failure_poison_replay_ack_false(self):
        journal=create(self.path)
        token=journal.reserve('h')
        try:
            with mock.patch.object(m.os,'fsync',side_effect=OSError('injected')):
                with self.assertRaises(OSError):
                    journal.settle(token,'SUCCESS',7,True)
            self.assertTrue(journal.snapshot()['writer_poisoned'])
            with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                journal.reserve('translate-m')
        finally:journal.close()
        replay=m.load(self.path)
        self.assertEqual(replay['event_count'],2)
        self.assertEqual(replay['settled_task_count'],1)
        self.assertFalse(replay['fsync_acknowledgments_verified'])

    def test_reentrant_snapshot_during_debit_never_returns_token(self):
        journal=create(self.path)
        original=m.os.fsync
        inner=[]
        def reenter(fd):
            original(fd)
            inner.append(journal.snapshot())
        try:
            with mock.patch.object(m.os,'fsync',side_effect=reenter):
                with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                    journal.reserve('h')
            self.assertTrue(inner[0]['writer_poisoned'])
            self.assertFalse(inner[0]['durable_debit_ack_verified'])
            self.assertTrue(journal.snapshot()['writer_poisoned'])
            with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                journal.reserve('h')
        finally:journal.close()
        self.assertEqual(m.load(self.path)['event_count'],1)

    def test_reentrant_snapshot_during_settlement_never_returns_ack(self):
        journal=create(self.path)
        token=journal.reserve('h')
        original=m.os.fsync
        inner=[]
        def reenter(fd):
            original(fd)
            inner.append(journal.snapshot())
        try:
            with mock.patch.object(m.os,'fsync',side_effect=reenter):
                with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                    journal.settle(token,'SUCCESS',7,True)
            self.assertTrue(inner[0]['writer_poisoned'])
            self.assertFalse(journal.snapshot()['fsync_acknowledgments_verified'])
            with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                journal.settle(token,'SUCCESS',7,True)
        finally:journal.close()
        self.assertEqual(m.load(self.path)['event_count'],2)

    def test_shortwrite_poison_and_torn_replay_rejected(self):
        journal=create(self.path)
        original=m.os.write
        def short(fd,raw):
            original(fd,raw[:-1])
            return len(raw)-1
        try:
            with mock.patch.object(m.os,'write',side_effect=short):
                with self.assertRaisesRegex(ValueError,'SHORT_WRITE'):
                    journal.reserve('h')
            self.assertTrue(journal.snapshot()['writer_poisoned'])
        finally:journal.close()
        with self.assertRaisesRegex(ValueError,'TORN_OR_OVERSIZE_LINE'):
            m.load(self.path)

    def test_path_replace_and_hardlink_poison(self):
        journal=create(self.path)
        try:
            # Windows denies renaming an open fd; simulate a changed pathname
            # identity at the exact check boundary instead of weakening it.
            original=m.os.stat
            info=original(self.path,follow_symlinks=False)
            fields={name:getattr(info,name) for name in
                    ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            fields['st_ino']+=1
            forged=SimpleNamespace(**fields)
            def path_changed(path,*args,**kwargs):
                return forged if os.fspath(path)==os.fspath(self.path) else original(path,*args,**kwargs)
            with mock.patch.object(m.os,'stat',side_effect=path_changed):
                self.assertTrue(journal.snapshot()['writer_poisoned'])
            with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
                journal.reserve('h')
        finally:journal.close()
        path=Path(self.tmp.name)/'linked.jsonl'
        alias=Path(self.tmp.name)/'alias.jsonl'
        journal=create(path)
        try:
            try:os.link(path,alias)
            except OSError:
                original=m.os.fstat
                info=original(journal._fd)
                fields={name:getattr(info,name) for name in
                        ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                fields['st_nlink']=2
                with mock.patch.object(m.os,'fstat',return_value=SimpleNamespace(**fields)):
                    self.assertTrue(journal.snapshot()['writer_poisoned'])
            else:self.assertTrue(journal.snapshot()['writer_poisoned'])
        finally:journal.close()

    def test_symlink_torn_oversize_noncanonical_and_duplicate_json(self):
        with create(self.path):
            pass
        alias=Path(self.tmp.name)/'alias.jsonl'
        try:os.symlink(self.path,alias)
        except (OSError,NotImplementedError):pass
        else:
            with self.assertRaises(ValueError):
                m.load(alias)
        header=self.path.read_bytes()
        for body in (header[:-1],header+b'x'*(m.MAX_LINE+1),
                     header.replace(b'"kind":"HEADER"',b'"kind": "HEADER"'),
                     header.replace(b'"kind":"HEADER"',b'"kind":"HEADER","kind":"HEADER"')):
            path=Path(self.tmp.name)/('bad'+str(len(body))+str(len(list(Path(self.tmp.name).iterdir())))+'.jsonl')
            path.write_bytes(body)
            with self.assertRaises(ValueError):
                m.load(path)

    def test_recomputed_chain_still_rejects_bool_token_alias(self):
        with create(self.path) as journal:
            journal.reserve('h')
        lines=self.path.read_bytes().splitlines()
        event=m.parse(lines[1])
        event['payload']['token']['launch_authorized']=0  # False == 0 in Python only.
        body={key:event[key] for key in ('seq','kind','payload','prev')}
        event['sha256']=m.digest(m.canonical(body))
        self.path.write_bytes(lines[0]+b'\n'+m.canonical(event)+b'\n')
        with self.assertRaisesRegex(ValueError,'DEBIT_TOKEN'):
            m.load(self.path)

    def test_header_shortwrite_preserves_no_recreation(self):
        original=m.os.write
        with mock.patch.object(m.os,'write',side_effect=lambda fd,raw:original(fd,raw[:-1])):
            with self.assertRaisesRegex(ValueError,'SHORT_WRITE'):
                create(self.path)
        self.assertTrue(self.path.exists())
        with self.assertRaises(FileExistsError):
            create(self.path)

    def test_caller_plan_mutation_during_header_fsync_cannot_rebind_live(self):
        supplied=plan()
        original=m.os.fsync
        def mutate(fd):
            supplied[0]['task_uid']='changed'
            return original(fd)
        with mock.patch.object(m.os,'fsync',side_effect=mutate):
            journal=create(self.path,task_plan=supplied)
        with journal:
            with self.assertRaisesRegex(ValueError,'EXACT_NEXT_SLOT'):
                journal.reserve('changed')
            self.assertEqual(journal.reserve('h')['task']['task_uid'],'h')
        self.assertEqual(m.load(self.path)['active_slot'],0)

    def test_close_failure_makes_writer_permanently_unavailable(self):
        journal=create(self.path)
        original=m.os.close
        with mock.patch.object(m.os,'close',side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                journal.close()
        self.assertTrue(journal.snapshot()['writer_poisoned'])
        with self.assertRaisesRegex(ValueError,'JOURNAL_UNAVAILABLE'):
            journal.reserve('h')
        # The real fd was not closed by the injection; this is only test cleanup.
        original(journal._fd)


if __name__=='__main__':
    unittest.main()
