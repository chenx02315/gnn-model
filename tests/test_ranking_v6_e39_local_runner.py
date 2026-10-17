"""Injected metadata buffers only; never read actual staging inputs."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from scripts import run_ranking_v6_e39_local_join as runner


class LocalJoinRunnerTests(unittest.TestCase):
    def edge(self,circuit='spi',source='spi:hf_coarse:H64-F4:1',action='spi:HF:h64'):
        row={key:'' for key in runner.FIELDS}
        row.update(circuit=circuit,source_candidate_uid=source,action_uid=action)
        return row

    def table(self,rows):
        output=io.StringIO()
        import csv
        writer=csv.DictWriter(output,fieldnames=runner.FIELDS,delimiter='\t',lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue().encode()

    def run_fake(self,raw,helper=None,argv=None):
        out=io.StringIO()
        with patch.object(runner.stable_reader,'_stable_bytes',side_effect=[b'{}',raw]) as read, \
             patch.object(runner.scope_join,'summarize',side_effect=helper or (lambda *args:dict(status='SYNTHETIC',physical_files_read=False))) as join, \
             patch.object(runner.sys,'argv',argv or ['fixed']), \
             patch('builtins.open',side_effect=AssertionError('ACTUAL_IO')), \
             patch('subprocess.Popen',side_effect=AssertionError('REMOTE')), \
             contextlib.redirect_stdout(out):
            code=runner.main()
        return code,json.loads(out.getvalue()),read,join

    def test_exact_pinned_inputs_filter_before_join_and_reference_projection(self):
        raw=self.table([self.edge(),self.edge(),self.edge(circuit='s5378',source='not-analysed',action='not-analysed')])
        code,result,read,join=self.run_fake(raw)
        self.assertEqual(code,0)
        self.assertEqual(read.call_count,2)
        self.assertEqual([call.args[1] for call in read.call_args_list],[spec[1] for spec in runner.SPECS])
        self.assertEqual(join.call_args.args[1],[dict(circuit='spi',source_candidate_uid='spi:hf_coarse:H64-F4:1',action_uid='spi:HF:h64')])
        self.assertEqual(result['fixed_local_input_audit']['mixed_edge_rows'],3)
        self.assertEqual(result['fixed_local_input_audit']['train_session_edge_rows'],2)
        self.assertEqual(result['fixed_local_input_audit']['validation_metadata_rows_filtered_before_join'],1)
        self.assertEqual(result['local_metadata_files_read'],2)
        self.assertFalse(result['pure_join_function_performed_io'])
        self.assertNotIn('physical_files_read',result)

    def test_wrong_role_schema_and_width_fail_closed_without_join(self):
        for raw in (self.table([self.edge(circuit='s9234')]),b'other\nsecret\n',self.table([])+b'short\n'):
            code,result,read,join=self.run_fake(raw)
            self.assertEqual(code,2)
            self.assertEqual(result,dict(status='FAIL_CLOSED_LOCAL_SCOPE_JOIN',code='INPUT_OR_JOIN_REJECTED'))
            self.assertFalse(join.called)

    def test_no_dynamic_paths_and_helper_failure_or_output_overflow(self):
        code,result,read,join=self.run_fake(b'ignored',argv=['fixed','other-path'])
        self.assertEqual(code,2)
        self.assertFalse(read.called)
        def fail(*args): raise ValueError('DO_NOT_ECHO_ROW_OR_PRIVATE_PATH')
        code,result,read,join=self.run_fake(self.table([self.edge()]),helper=fail)
        self.assertEqual(code,2)
        self.assertNotIn('DO_NOT_ECHO',repr(result))
        code,result,read,join=self.run_fake(self.table([self.edge()]),helper=lambda *args:dict(physical_files_read=False,oversized='x'*65536))
        self.assertEqual(code,2)


if __name__=='__main__':
    unittest.main()
