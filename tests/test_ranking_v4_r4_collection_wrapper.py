from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import run_ranking_v4_r4_collection as wrapper


class R4CollectionWrapperTests(unittest.TestCase):
    def test_wrong_cwd_never_runs(self):
        with patch.object(wrapper.runpy, 'run_path') as run:
            with self.assertRaisesRegex(ValueError, 'PATH'):
                wrapper.main()
            run.assert_not_called()

    def test_oversize_or_wrong_sha_never_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = Path(directory) / 'collector.py'
            with patch.object(wrapper, 'CODE', Path.cwd()), patch.object(wrapper, 'COLLECTOR', collector), \
                 patch.object(wrapper.runpy, 'run_path') as run:
                collector.write_bytes(b'x' * 20001)
                with self.assertRaisesRegex(ValueError, 'SHA'):
                    wrapper.main()
                collector.write_bytes(b'bad hash')
                with self.assertRaisesRegex(ValueError, 'SHA'):
                    wrapper.main()
                run.assert_not_called()

    def test_symlink_never_runs(self):
        with patch.object(wrapper, 'CODE', Path.cwd()), patch.object(Path, 'is_symlink', return_value=True), \
             patch.object(wrapper.runpy, 'run_path') as run:
            with self.assertRaisesRegex(ValueError, 'PATH'):
                wrapper.main()
            run.assert_not_called()
