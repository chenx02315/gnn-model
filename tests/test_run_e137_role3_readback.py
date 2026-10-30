"""Local inert role3 closure checks; no phase inputs, SSH or tool calls."""
import sys
import unittest
from unittest import mock

from scripts import run_e137_role3_readback as m
from scripts import worker_e137_batch as worker


class SourceClosureTests(unittest.TestCase):
    def test_role3_rejects_short_original_budget_before_transport_or_directory(self):
        plan={key:'synthetic' for key in m.REVIEW_KEYS}
        review=m.canonical(dict(status='PASS',reviewed=plan))
        with mock.patch.object(m,'prepare',return_value=plan), mock.patch.object(m,'_bounded',side_effect=[review,b'{}']), \
                mock.patch.object(m.ledger,'remaining',return_value=10.9), \
                mock.patch.object(m.control,'load_transport') as load, mock.patch.object(m.Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(ValueError,'INSUFFICIENT_ORIGINAL_CLEANUP_RESERVE'):
                m.execute('synthetic-review.json','synthetic')
        load.assert_not_called();mkdir.assert_not_called()

    def test_actual_full_source_closure_loads_without_cached_children_or_io(self):
        with mock.patch.object(m.control,'load_transport') as transport:
            rows=m._sources()
        transport.assert_not_called()
        pins={row['name']:row['sha256'] for row in rows}
        self.assertIn('prospective_acquisition_pilot_v1',pins)
        self.assertIn('physical_e137_role3_binding',pins)
        saved={key:value for key,value in sys.modules.items() if key=='src' or key.startswith('src.')}
        try:
            with mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn:
                modules=worker.load_sources(rows,pins)
            opened.assert_not_called();spawn.assert_not_called()
            self.assertEqual(set(modules),set(pins))
            for name,module in modules.items():
                self.assertEqual(module.__source_sha256__,pins[name])
        finally:
            for key in list(sys.modules):
                if key=='src' or key.startswith('src.'):
                    del sys.modules[key]
            sys.modules.update(saved)
