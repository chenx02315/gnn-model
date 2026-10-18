import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from scripts import discover_ranking_v6_e50_local_metadata as p


class LocalNamesTests(unittest.TestCase):
    def test_exact_metadata_and_archive_names(self):
        self.assertEqual(p.match_kind('source_provenance_v2.tsv'),'named_metadata')
        self.assertEqual(p.match_kind('formal_candidate_space_v2.tar.gz'),'named_archive_candidate')
        self.assertIsNone(p.match_kind('outcomes.tsv'))
        self.assertIsNone(p.match_kind('checkpoint.pt'))
        self.assertTrue(p.skip_name('BLIND_TEST'))
        self.assertTrue(p.skip_name('validation_runtime'))

    def test_names_only_excludes_denied_and_no_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'backup').mkdir(); (root/'denied').mkdir()
            (root/'backup'/'source_provenance_v2.tsv').touch();(root/'denied'/'receipt_v2.json').touch()
            with patch('builtins.open',side_effect=AssertionError('NO_CONTENT')):
                result=p.discover([root],root/'denied')
            self.assertEqual(len(result['matches']),1)
            self.assertEqual(result['excluded_directories'],1)
            self.assertFalse(result['file_contents_opened'])

    def test_bounds_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'child').mkdir()
            with patch.object(p,'MAX_DIRS',1):
                with self.assertRaisesRegex(ValueError,'DIRECTORY_BOUND'):p.discover([root],root/'denied')

    def test_unavailable_not_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'missing';result=p.discover([root],root/'denied')
            self.assertEqual(result['matches'],[])
            self.assertEqual(result['unavailable'][0]['code'],'FileNotFoundError')

    def test_case_variants_excluded_before_entry_stat(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries=[]
            for name in ('MEASUREMENTS','NetLists','CHECKPOINTS','BLIND_TEST','Validation_Runtime'):
                entry=MagicMock();entry.name=name
                entry.stat.side_effect=AssertionError('EXCLUDED_BEFORE_STAT')
                entries.append(entry)
            manager=MagicMock();manager.__enter__.return_value=iter(entries)
            with patch.object(p.os,'scandir',return_value=manager):
                result=p.discover([Path(tmp)],Path(tmp)/'denied')
            self.assertEqual(result['excluded_directories'],5)
            for entry in entries:entry.stat.assert_not_called()


if __name__=='__main__':unittest.main()
