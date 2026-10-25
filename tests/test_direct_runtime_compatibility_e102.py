import ast
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from src.data import direct_runtime_compatibility_e102 as m


class Tests(unittest.TestCase):
    def info(self,mode=stat.S_IFSOCK,uid=1047,links=1,size=0):
        return SimpleNamespace(st_mode=mode,st_uid=uid,st_nlink=links,st_size=size)

    def test_expected_socket_is_metadata_not_regular_body(self):
        self.assertEqual(m.classify_leaf(self.info(),'pvmtmp.1047.63195.bupt-vncs2.0',1047,'bupt-vncs2'),
                         'OWNED_PVM_UNIX_SOCKET_METADATA_ONLY')
        self.assertEqual(m.classify_leaf(self.info(stat.S_IFREG),'any.log',1047,'bupt-vncs2'),'REGULAR_SINGLE_LINK')

    def test_no_generic_socket_symlink_foreign_owner_or_hardlink_relaxation(self):
        name='pvmtmp.1047.63195.bupt-vncs2.0'
        for info,n in ((self.info(), 'unreviewed.sock'),(self.info(uid=0),name),
                       (self.info(links=2),name),(self.info(stat.S_IFLNK),name),
                       (self.info(stat.S_IFIFO),name),(self.info(size=1),name),
                       (self.info(),name+'/child'),(self.info(),name.replace('1047','1048'))):
            with self.assertRaises(ValueError):m.classify_leaf(info,n,1047,'bupt-vncs2')

    def test_warning_classification_never_accepts_warning(self):
        log=(b'// Warning: Rule FN1 violation occurs 6 times\n'
             b'// command: read_faults {fixed}\n'
             b'// Warning: unknown import diagnostic\n')
        value=m.warning_inventory(log)
        self.assertEqual(value['warnings'][0]['category'],'FN1')
        self.assertEqual(value['warnings'][0]['reported_number'],6)
        self.assertEqual(value['warnings'][1]['category'],'UNKNOWN')
        self.assertEqual(value['warnings'][1]['phase'],'FAULT_IMPORT_OR_LATER')
        self.assertFalse(value['warning_acceptance_policy_changed'])
        self.assertTrue(all(not row['reviewed_for_acceptance'] for row in value['warnings']))

    def test_command_option_not_a_warning(self):
        self.assertEqual(m.warning_inventory(b'// command: read_faults {p} -show_warnings\n')['warnings'],[])

    def test_input_bound(self):
        with self.assertRaises(ValueError):m.warning_inventory('not bytes')

    def test_warning_count_is_bounded(self):
        with self.assertRaisesRegex(ValueError,'INVENTORY_BOUND'):
            m.warning_inventory(b'// Warning: unknown\n'*129)

    def test_python36(self):ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
