"""Mock-only provisional worker tests; no Linux file/process or A access."""
import ast
import base64
import json
from pathlib import Path
import unittest
from contextlib import ExitStack
from unittest import mock

from src.data import physical_f_replay_execution_e135 as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = Path(__file__).resolve().parents[1]
        raw = (repo.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert m.sha(raw) == m.evidence.E128_SHA
        rows = json.loads(raw)['files']
        cls.tcl = base64.b64decode(next(r for r in rows if r['sha256'] == m.BASE_TCL_SHA256)['body_base64'])

    def setUp(self):
        self.used = m._USED
        m._USED = False

    def tearDown(self):
        m._USED = self.used

    def test_unreviewed_entry_denies_before_all_io_and_never_retries(self):
        with mock.patch.object(m.direct,'Descendants') as domain, mock.patch.object(m,'Files') as files:
            with self.assertRaisesRegex(ValueError,'FINAL_MANUAL'):
                m.worker({})
            with self.assertRaisesRegex(ValueError,'ONE_WORKER'):
                m.worker({})
            domain.assert_not_called()
            files.assert_not_called()

    def test_candidate_preserves_F4_setup_and_gates_before_both_commands(self):
        result = m.build_recipe(self.tcl,b'expected')
        text = result['body'].decode('ascii')
        self.assertFalse(result['command_verified'])
        self.assertIn('import_scan_mode F_fullscan_4ch',text)
        self.assertIn('set_clock_off_simulation ON',text)
        self.assertIn('set_split_capture_cycle ON',text)
        self.assertIn('set_atpg_fill X',text)
        self.assertNotIn('create_patterns',text)
        self.assertNotIn('add_processors',text)
        self.assertNotIn('read_faults $status',text)
        self.assertNotIn('STATUS_FILE',text)
        self.assertLess(text.index('baseline.faults.rpt baseline'),text.index('read_patterns '))
        self.assertLess(text.index('imported.faults.rpt imported'),text.index('simulate_patterns '))
        for stage in ('baseline','imported','simulated'):
            for extension in ('statistics.rpt','faults.rpt','faults.mtfi'):
                self.assertIn('/'+stage+'.'+extension,text)

    def test_recipe_drift_or_extra_command_line_rejected(self):
        with self.assertRaisesRegex(ValueError,'PINNED_F4_TCL'):
            m.build_recipe(self.tcl+b' ',b'')
        with self.assertRaisesRegex(ValueError,'TWO_REPLAY_COMMANDS'):
            m.build_recipe(self.tcl,b'',('read_patterns x\ncreate_patterns','simulate_patterns'))

    def test_baseline_input_pins_are_not_accepted_from_caller_counts(self):
        with self.assertRaisesRegex(ValueError,'BASELINE_INPUT_PINS'):
            m.baseline_expectations(b'3713',b'71216')

    def test_actual_local_baseline_offset_one_produces_small_parser_not_full_payload(self):
        repo = Path(__file__).resolve().parents[1]
        files = repo.parent/'runtime_training_staging_20260928/v6_e133_eq_group_readback_20261027_r1/files'
        raw = m.baseline_expectations((files/m.F_BASIC_SHA256).read_bytes(),
                                     (files/m.evidence.PINS['mapping'][1]).read_bytes())
        self.assertLess(len(raw),2048)
        self.assertEqual(raw,m.EXPECTED_INIT.encode('ascii'))

    def test_inherited_clock_projection_exact_pin_boot_and_original_durations(self):
        clock = dict(schema='physical-f-replay-package-clock-e135-v1',authorization_sha256=m.AUTH_SHA256,
            proposal_sha256='a'*64,reader_payload_sha256='b'*64,initial_response_sha256='c'*64,start_file_sha256='d'*64,
            boot_id='mockboot',remote_start_monotonic=100.,remote_deadline_monotonic=3700.,
            remote_clock_sample_monotonic=105.,remote_utc_sample='2026-10-28T00:00:05.000000+00:00',
            local_utc_start='2026-10-28T00:00:00.000000+00:00',local_utc_deadline='2026-10-28T01:00:00.000000+00:00',
            local_monotonic_start=10.,local_monotonic_deadline=3610.,local_clock_domain={'host':'local','clock':'test'})
        raw = m.canonical(clock)
        with mock.patch.object(m,'INITIAL_CLOCK_SHA256',m.sha(raw)),mock.patch.object(m.process,'_boot_id',return_value='mockboot'):
            result = m.package_clock(raw)
            self.assertEqual(result['monotonic_end'],3700.)
            with self.assertRaisesRegex(ValueError,'PINNED_FIRST_CALL_CLOCK'):
                m.package_clock(raw+b' ')
        bad = m.canonical(dict(clock,remote_deadline_monotonic=4000.))
        with mock.patch.object(m,'INITIAL_CLOCK_SHA256',m.sha(bad)),mock.patch.object(m.process,'_boot_id',return_value='mockboot'):
            with self.assertRaisesRegex(ValueError,'ORIGINAL_CLOCK_DURATION'):
                m.package_clock(bad)

    def test_private_storage_and_stream_namespaces_do_not_patch_old_globals(self):
        root,end = m.storage.ROOT,m.storage.END
        persist, monitor = m._storage(1234)
        self.assertEqual(persist.__globals__['ROOT'],m.ROOT)
        self.assertEqual(monitor.sample.__func__.__globals__['END'],1234)
        self.assertEqual((m.storage.ROOT,m.storage.END),(root,end))
        namespace = m._stream_io(lambda:None)
        self.assertEqual(namespace['MAX_TREE'],2147483648)
        self.assertEqual(namespace['MAX_DEPTH'],32)
        self.assertEqual(m.io.MAX_TREE,134217728)
        self.assertIs(namespace['_tree'].__code__,m.io._tree.__code__)

    def test_live_observer_bytecode_reused_with_strict_new_root_validator(self):
        captured = {}
        def intercept(code,namespace,*args):
            captured.update(code=code,namespace=namespace)
            return mock.Mock(return_value={'mock':True})
        with mock.patch.object(m.types,'FunctionType',side_effect=intercept):
            self.assertEqual(m._observer({},1,object(),[1],lambda x:True,None),{'mock':True})
        self.assertIs(captured['code'],m.process.observe_tessent.__code__)
        self.assertIsNot(captured['namespace'],m.process.observe_tessent.__globals__)
        with self.assertRaises(ValueError):
            captured['namespace']['_validate_launch']({})

    def test_tcl_gate_offline_interpreter_positive_and_contaminated_cases(self):
        try:
            import tkinter
            tcl = tkinter.Tcl()
        except (ImportError,RuntimeError) as exc:
            self.skipTest('No local Tcl interpreter: '+type(exc).__name__)
        # Test the exact parser/control flow with only the immutable production
        # cardinalities reduced for tiny in-RAM synthetic input; no file opens.
        gate = m.GATE.replace('!= 71216','!= 2').replace('!= 3713','!= 1')
        tcl.eval('rename open real_open; rename gets real_gets; rename close real_close')
        tcl.eval('proc open {path args} {set ::i 0; if {$path eq "report"} {set ::active $::report_rows} else {set ::active $::rows}; return fake}; proc close {args} {}; '
                 'proc gets {fd name} {upvar 1 $name line; if {$::i >= [llength $::active]} {return -1}; '
                 'set line [lindex $::active $::i]; incr ::i; return [string length $line]}')
        tcl.eval(gate)
        tcl.setvar('native_header',tuple(x.rstrip('\n') for x in m.faults.HEADER))
        tcl.setvar('native_footer',tuple(x.rstrip('\n') for x in m.faults.FOOTER))
        tcl.eval('set expected_keys [dict create [list 0 /a] 1 [list 1 /b] 1]; '
                 'set expected_di [dict create [list 0 /a] DI.SCAN]')
        def run(rows):
            tcl.setvar('rows',tuple(x.rstrip('\n') for x in m.faults.HEADER)+tuple(rows)+tuple(x.rstrip('\n') for x in m.faults.FOOTER))
            tcl.setvar('report_rows',('','    type    code    pin_pathname',
                '    ----   ------   ------------------------------------',' 0 DI.SCAN /a',' 1 UC /b'))
            return tcl.eval('baseline_gate native report baseline')
        run(['      0,  DI.SCAN,    "/a";',' 1, UC, "/b";'])
        for rows in ([' 0, DS, "/a";',' 1, UC, "/b";'],
                     [' 0, DI.UNKNOWN, "/a";',' 1, UC, "/b";'],
                     [' 0, DI.SCAN, "/a";',' 0, UC, "/a";'],
                     [' 0, DI.SCAN, "/a";'],
                     [' 0, DI.SCAN, "/a";',' 1, AU.NEW, "/b";']):
            with self.assertRaises(tkinter.TclError):
                run(rows)
        tcl.setvar('rows',('MALICIOUS_HEADER',))
        with self.assertRaises(tkinter.TclError):
            tcl.eval('baseline_gate native report baseline')

    def test_report_group_expansion_rejects_DI_EQ_outside_baseline_and_accepts_UC_EQ(self):
        try:
            import tkinter
            tcl = tkinter.Tcl()
        except (ImportError,RuntimeError) as exc:
            self.skipTest('No local Tcl interpreter: '+type(exc).__name__)
        gate = m.GATE.replace('!= 71216','!= 3').replace('!= 3713','!= 1')
        tcl.eval('proc open {path args} {set ::i 0;set ::active [set ::$path];return fake}; '
                 'proc close {args} {};proc gets {fd name} {upvar 1 $name line; '
                 'if {$::i >= [llength $::active]} {return -1};set line [lindex $::active $::i];incr ::i;return [string length $line]}')
        tcl.eval(gate)
        header = tuple(x.rstrip('\n') for x in m.faults.HEADER)
        footer = tuple(x.rstrip('\n') for x in m.faults.FOOTER)
        tcl.setvar('native_header',header)
        tcl.setvar('native_footer',footer)
        opaque = '/\\text_in_r_reg[0] /Q'
        tcl.setvar('opaque',opaque)
        tcl.eval('set expected_keys [dict create [list 0 /a] 1 [list 1 $opaque] 1 [list 0 /c] 1]; '
                 'set expected_di [dict create [list 0 /a] DI.CLK]')
        report_header = ('','    type    code    pin_pathname','    ----   ------   ------------------------------------')
        # MTFI order is deliberately DI(a),EQ(b),UC(c). Report order puts b
        # under UC(c), and opposite polarities/opaque quoted paths are legal.
        tcl.setvar('native',header+('      0,  DI.CLK,    "/a";',
                                  '      1,  EQ,    "'+opaque+'";',
                                  '      0,  UC,    "/c";')+footer)
        good = ('      0    DI.CLK   /a','      0    UC   /c','      1    EQ   "'+opaque+'"')
        tcl.setvar('report',report_header+good)
        tcl.eval('baseline_gate native report baseline')
        bad = (good[0],good[2],good[1])
        tcl.setvar('report',report_header+bad)
        with self.assertRaisesRegex(tkinter.TclError,'REPORT_EXPANDED_DI_OUTSIDE_BASELINE'):
            tcl.eval('baseline_gate native report baseline')
        for rows in ((good[2],good[0],good[1]), (good[0],good[1],good[1]),
                     (good[0],good[1],good[2]+'"'), (good[0],good[1],'1 EQ ""'),
                     (good[0],good[1],'1 EQ "'+opaque),
                     (good[0],good[1],'1 UC "'+opaque+'"')):
            tcl.setvar('report',report_header+rows)
            with self.assertRaises(tkinter.TclError):
                tcl.eval('baseline_gate native report baseline')

    def test_source_AST36_and_no_shell_or_ATPG_launch(self):
        source = Path(m.__file__).read_text(encoding='utf-8')
        ast.parse(source,feature_version=(3,6))
        self.assertNotIn('shell=True',source)
        self.assertNotIn('subprocess.Popen',source)

    def _flow(self, log_failure=False, post_clock_failure=False, selfcheck_failure=False):
        events = []
        closure_digest = 'a'*64
        spec = dict(authority_base64=base64.b64encode(b'auth').decode(),package_clock_base64='',
            input_files=[dict(role=role,target=m.ROOT+'/inputs/'+name,path='/source/'+name,bytes=1,sha256='b'*64,identity={})
                         for role,name in [('library','cells.lib'),('basic','F.basic'),('pattern','tester.stil')]],
            tsdb=dict(path='/source/tree'),code_base64={name:base64.b64encode(b'code').decode()
                for name in ('expected_baseline.tcl','replay.tcl')},
            execution_closure=[dict(path='/cad/'+name,bytes=1,sha256=closure_digest) for name in ('launcher','engine')],
            launch=dict(launch_spec_sha256='c'*64))
        class FakeFiles(object):
            def __init__(self,tick):
                pass
            def directory(self,*a,**k):
                return 10
            def copy(self,*a,**k):
                events.append('copy')
            def publish(self,name,raw,check=True):
                if log_failure and name == 'stdout.log':
                    raise OSError('mocklogfail')
                events.append(name)
        domain = mock.Mock(peak=0)
        monitor = mock.Mock()
        monitor.sample.return_value = dict(sampled_named_bytes=10)
        after_observer = [False]
        def now():
            if after_observer[0] and post_clock_failure:
                raise RuntimeError('mockclockfail')
            return 110
        def observe(launch,end,dom,budget,spawn,scratch):
            events.append('observe')
            self.assertLess(events.index('launch_intent.json'),events.index('observe'))
            spawn(dict(child_pid=123))
            after_observer[0] = True
            return dict(output=b'PREFIX',failure=None,cleaned=True,returncode=0)
        def checks(ctx,dom):
            events.append('selfchecks')
            if selfcheck_failure:
                raise ValueError('checkfail')
            return [dict(case=name,passed=True,cleaned=True,authenticated_claim=True) for name in m.SELFTEST_CASES]
        patches = [mock.patch.object(m,'COMMANDS_VERIFIED',True),
            mock.patch.object(m.process,'__source_sha256__',m.PROCESS_SOURCE_SHA256,create=True),
            mock.patch.object(m,'REVIEWED_SPEC_SHA256',m.sha(m.canonical(spec))),
            mock.patch.object(m,'AUTH_SHA256',m.sha(b'auth')),
            mock.patch.object(m,'package_clock',return_value=dict(remote_start_monotonic=100,monotonic_end=3700,utc_end=9999)),
            mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os.sys,'platform','linux'),
            mock.patch.object(m.time,'monotonic',side_effect=now),
            mock.patch.object(m.time,'time',return_value=1000),
            mock.patch.object(m.direct,'Descendants',return_value=domain),
            mock.patch.object(m,'_storage',return_value=(lambda raw:events.append('initial'),monitor)),
            mock.patch.object(m,'Files',FakeFiles), mock.patch.object(m,'_tree_copy',side_effect=lambda *a:events.append('tree')),
            mock.patch.object(m,'run_selftests',side_effect=checks),
            mock.patch.object(m.io,'_directory',return_value=10), mock.patch.object(m.io,'_publish'),
            mock.patch.object(m,'_stream_io',return_value={'_read_at':lambda *a,**k:(b'',1,closure_digest)}),
            mock.patch.object(m.os,'open',return_value=11),mock.patch.object(m.os,'close'),
            mock.patch.object(m,'_observer',side_effect=observe)]
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            try:
                result = m.worker(spec)
            except Exception as exc:
                result = exc
        return result,events

    def test_closed_loop_debit_before_single_observe_and_metadata_before_raw_log(self):
        result,events = self._flow()
        self.assertEqual(result['launch_debit'],1)
        self.assertEqual(events.count('observe'),1)
        self.assertLess(events.index('selfchecks'),events.index('launch_intent.json'))
        self.assertLess(events.index('observation.json'),events.index('stdout.log'))
        self.assertLess(events.index('stdout.log'),events.index('stdout_ack.json'))

    def test_failed_log_or_post_clock_retains_observation_prefix_metadata(self):
        for kwargs in (dict(log_failure=True),dict(post_clock_failure=True)):
            m._USED = False
            result,events = self._flow(**kwargs)
            self.assertIsInstance(result,Exception)
            self.assertIn('observation.json',events)
            self.assertEqual(events.count('observe'),1)

    def test_failed_selfcheck_prevents_launch_and_debit(self):
        result,events = self._flow(selfcheck_failure=True)
        self.assertIsInstance(result,ValueError)
        self.assertNotIn('observe',events)
        self.assertNotIn('launch_intent.json',events)

    def test_selfcheck_helpers_exact_AST_copy_not_new_monitor_algorithm(self):
        repo = Path(__file__).resolve().parents[1]
        original = ast.parse((repo/'scripts/worker_pt_label_generation_e127.py').read_text(encoding='utf-8'))
        self.assertEqual(m.sha((repo/'scripts/worker_pt_label_generation_e127.py').read_bytes()),m.SELFTEST_ORIGIN_SHA256)
        current = ast.parse(Path(m.__file__).read_text(encoding='utf-8'))
        for name in ('run_selftests','SimpleMonitor'):
            old = next(n for n in original.body if getattr(n,'name',None) == name)
            new = next(n for n in current.body if getattr(n,'name',None) == name)
            self.assertEqual(ast.dump(old),ast.dump(new))


if __name__ == '__main__':
    unittest.main()
