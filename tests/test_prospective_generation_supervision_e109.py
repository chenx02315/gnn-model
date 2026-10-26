"""Mock Popen/select/proc only: no real subprocess, server or Tcl execution."""
import copy
from contextlib import ExitStack
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from src.data import prospective_generation_supervision_e109 as m
from tests import test_prospective_generation_recipe_e108 as fixtures


class Process:
    def __init__(self):
        self.returncode=0
        self.stdout=Mock();self.stdout.fileno.return_value=9
    def poll(self):return self.returncode
    def wait(self,timeout):return self.returncode


class Selector:
    def __init__(self):self.mapping={}
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def register(self,stream,events):self.mapping[9]=SimpleNamespace(fileobj=stream)
    def get_map(self):return self.mapping
    def select(self,timeout):return [(key,1) for key in self.mapping.values()]
    def unregister(self,stream):self.mapping.clear()


class Domain:
    peak=123
    def __init__(self):self.samples=0;self.cleanups=0;self.fail_sample=None;self.fail_cleanup=False;self.pending=False
    def sample(self):
        self.samples+=1
        if self.samples==self.fail_sample:raise ValueError('MEMORY_STOP')
    def cleanup(self,proc,end):
        self.cleanups+=1
        if self.fail_cleanup:raise RuntimeError('private cleanup detail')
        return True
    def _direct_batch(self):return ([1] if self.pending else []),False


class Tests(unittest.TestCase):
    def setUp(self):
        source=fixtures.Tests();source.setUp();self.fixture=source
        self.freeze,binder=source.binder()
        self.binding=binder.bind_next(source.plan['phases'][0]['tasks'][0]['task_uid'])
        self.cwd=m.recipe.ROOT+'/aes_core/runs/e109-test/scratch/one'
        self.runtime={'PATH':'/usr/bin:/bin','MGC_HOME':'/cad/mentor/tessent2021_2',
                      'MGLS_LICENSE_FILE':'27000@synthetic-license-host'}
        self.launch=self.prepare()

    def prepare(self,runtime=None,cwd=None):
        return m.prepare_launch(self.freeze,self.binding,self.fixture.sources,
            self.runtime if runtime is None else runtime,self.cwd if cwd is None else cwd)

    def observe(self,domain=None,budget=None,clock=None,spawn_error=None,scratch=None):
        domain=domain or Domain();proc=Process();shared=[100] if budget is None else budget
        with ExitStack() as stack:
            spawn=stack.enter_context(patch.object(m.subprocess,'Popen',side_effect=spawn_error,return_value=proc))
            stack.enter_context(patch.object(m.selectors,'DefaultSelector',return_value=Selector()))
            stack.enter_context(patch.object(m.os,'read',side_effect=[b'OK',b'']))
            stack.enter_context(patch.object(m.time,'monotonic',side_effect=clock,return_value=1))
            observed=m._observe(self.launch,100,domain,shared,scratch)
        return observed,spawn,proc,domain,shared

    def test_environment_replacement_excludes_parent_poison_and_preserves_only_fixed_controls(self):
        with patch.dict(os.environ,{'BASH_ENV':'/bad','PATTERN_LIMIT':'999','LD_PRELOAD':'/bad.so'}):
            observed,spawn,proc,domain,shared=self.observe()
        env=spawn.call_args[1]['env']
        self.assertEqual(env,self.launch['env'])
        self.assertNotIn('BASH_ENV',env);self.assertNotIn('LD_PRELOAD',env)
        self.assertEqual(env['PATTERN_LIMIT'],self.binding['recipe']['env']['PATTERN_LIMIT'])
        self.assertEqual(env['HOME'],self.cwd);self.assertEqual(env['TMPDIR'],self.cwd)
        self.assertEqual(env['LC_ALL'],'C')
        self.assertTrue(spawn.call_args[1]['start_new_session'])
        self.assertFalse(observed['physical_process_identity_authenticated'])
        self.assertIsNone(observed['actual_atpg_runtime_ns'])
        self.assertNotIn('synthetic-license-host',repr(observed))

    def test_success_keeps_output_cleanup_budget_and_explicit_environment_digest(self):
        observed,spawn,proc,domain,shared=self.observe()
        self.assertEqual(observed['output'],b'OK');self.assertIsNone(observed['failure'])
        self.assertTrue(observed['cleaned']);self.assertEqual(domain.cleanups,1)
        self.assertEqual(shared,[98]);self.assertEqual(spawn.call_count,1)
        self.assertEqual(observed['environment_sha256'],m.sha(m.canonical(self.launch['env'])))
        proc.stdout.close.assert_called_once()

    def test_forbidden_runtime_keys_or_relative_search_paths_are_rejected_before_spawn(self):
        for key in ('LD_PRELOAD','LD_AUDIT','BASH_ENV','PATTERN_LIMIT','HOME','LC_ALL'):
            runtime=dict(self.runtime);runtime[key]='bad'
            with self.assertRaises(ValueError):self.prepare(runtime)
        for path in ('/usr/bin:',':/bin','relative:/bin','/usr/../bin:/bin','/bin\n'):
            runtime=dict(self.runtime,PATH=path)
            with self.assertRaises(ValueError):self.prepare(runtime)

    def test_cwd_is_a_namespace_claim_not_the_tcl_output_directory(self):
        for path in ('/outside',m.recipe.ROOT+'/../outside',self.binding['recipe']['result_dir'].replace(m.recipe.stage.ROOT,m.recipe.ROOT)):
            with self.assertRaises(ValueError):self.prepare(cwd=path)

    def test_spec_tamper_rejected_before_popen(self):
        value=copy.deepcopy(self.launch);value['env']['PATH']='/other'
        with patch.object(m.subprocess,'Popen') as spawn,self.assertRaises(ValueError):
            m._observe(value,100,Domain(),[10])
        spawn.assert_not_called()

    def test_resigned_none_or_loader_taint_is_not_explicit_environment(self):
        for environment in (None,dict(self.launch['env'],LD_PRELOAD='/bad.so'),dict(self.launch['env'],PATH='.:/bin')):
            value=copy.deepcopy(self.launch);value['env']=environment
            value['environment_sha256']=m.sha(m.canonical(environment))
            value['launch_spec_sha256']=m.sha(m.canonical({k:v for k,v in value.items() if k!='launch_spec_sha256'}))
            with patch.object(m.subprocess,'Popen') as spawn,self.assertRaises(ValueError):
                m._observe(value,100,Domain(),[10])
            spawn.assert_not_called()

    def test_memory_sampling_failure_preserves_known_handle_and_attempted_cost_interval(self):
        domain=Domain();domain.fail_sample=2
        observed,spawn,proc,domain,shared=self.observe(domain)
        self.assertEqual(observed['failure'],'MEMORY_STOP');self.assertEqual(domain.cleanups,1)
        self.assertTrue(observed['launch_attempted']);self.assertTrue(observed['known_process_handle'])
        self.assertIsNotNone(observed['observed_wrapper_interval_seconds'])

    def test_timeout_and_scratch_failure_still_cleanup(self):
        observed,spawn,proc,domain,shared=self.observe(clock=[0,1,2,95,96])
        self.assertEqual(observed['failure'],'CASE_TIMEOUT');self.assertEqual(domain.cleanups,1)
        self.assertEqual(observed['observed_wrapper_interval_seconds'],94)
        scratch=Mock();scratch.sample.side_effect=[None,ValueError('SCRATCH_STOP')]
        observed,spawn,proc,domain,shared=self.observe(scratch=scratch)
        self.assertEqual(observed['failure'],'SCRATCH_STOP');self.assertEqual(domain.cleanups,1)

    def test_cleanup_failure_returns_observation_instead_of_losing_prior_output(self):
        domain=Domain();domain.fail_cleanup=True
        observed,spawn,proc,domain,shared=self.observe(domain)
        self.assertEqual(observed['output'],b'OK');self.assertFalse(observed['cleaned'])
        self.assertEqual(observed['failure'],'CLEANUP_UNCONFIRMED')
        self.assertEqual(observed['cleanup_error'],'RuntimeError')

    def test_failed_spawn_is_unknown_handle_no_retry_and_no_secret_exception_text(self):
        domain=Domain();domain.pending=True
        observed,spawn,proc,domain,shared=self.observe(domain,spawn_error=OSError('private license details'))
        self.assertEqual(spawn.call_count,1);self.assertFalse(observed['known_process_handle'])
        self.assertFalse(observed['cleaned']);self.assertEqual(observed['failure'],'OSError')
        self.assertNotIn('private license',repr(observed));self.assertEqual(shared,[100])

    def test_output_censor_retains_bytes_and_does_not_refund(self):
        observed,spawn,proc,domain,shared=self.observe(budget=[2])
        self.assertEqual(observed['output'],b'OK');self.assertEqual(observed['failure'],'OUTPUT_STOP')
        self.assertEqual(shared,[0]);self.assertEqual(domain.cleanups,1)

    def test_prelaunch_failure_does_not_claim_attempt_or_impute_interval(self):
        observed,spawn,proc,domain,shared=self.observe(budget=[0])
        self.assertFalse(observed['launch_attempted']);self.assertIsNone(observed['observed_wrapper_interval_seconds'])
        spawn.assert_not_called()

    def test_backward_clock_cannot_become_a_negative_or_zero_runtime_label(self):
        observed,spawn,proc,domain,shared=self.observe(clock=[0,1,20,2,3,4,10])
        self.assertEqual(observed['failure'],'CLOCK_INTERVAL_UNAVAILABLE')
        self.assertIsNone(observed['observed_wrapper_interval_seconds'])
        self.assertIsNone(observed['actual_atpg_runtime_ns'])
