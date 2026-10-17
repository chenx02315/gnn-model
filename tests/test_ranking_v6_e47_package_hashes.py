import copy
import hashlib
import json
import stat
import types
import unittest
from unittest.mock import patch
from scripts import project_ranking_v6_e47_package_hashes as p
from scripts import run_ranking_v6_e47_package_hashes as t


def fixture():
    return {'schema_version':'runtime-training-package-v2',
        'source_sha256':{'candidate_receipt':'a'*64,'candidate_space':p.EXPECTED_CANDIDATES,
                         'normalized_measurements':p.EXPECTED_NORMALIZED},
        'ignored':{'quality':'PRIVATE_VALUE_MARKER','arr':[1,-2.5e3,True,False,None,{'x':'PRIVATE_NESTED_MARKER'}]}}


def info(n):
    return types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o644,st_nlink=1,
        st_uid=1027,st_gid=1027,st_size=n,st_mtime_ns=3,st_ctime_ns=4)


class PackageTests(unittest.TestCase):
    def setUp(self):
        # Pure mocked Linux FD tests on Windows, not Linux execution evidence.
        for key,value in (('O_DIRECTORY',0x10000),('O_NOFOLLOW',0x20000),('O_NONBLOCK',0x800)):
            if not hasattr(p.os,key):
                mocker=patch.object(p.os,key,value,create=True)
                mocker.start()
                self.addCleanup(mocker.stop)

    def test_only_selected_values_decoded(self):
        raw=json.dumps(fixture()).encode('ascii')
        decode=json.loads
        calls=[]
        def traced(value,*args,**kw):
            calls.append(value)
            return decode(value,*args,**kw)
        with patch.object(p.json,'loads',side_effect=traced): result=p.project(raw)
        self.assertEqual(set(result),{'schema_version','source_sha256'})
        self.assertFalse(any('PRIVATE_' in c for c in calls))
        self.assertEqual(result['source_sha256']['candidate_receipt'],'a'*64)

    def test_escaped_keys_and_ignored_values(self):
        raw=json.dumps(fixture()).encode().replace(b'candidate_receipt',b'candidate_\\u0072eceipt')
        self.assertEqual(p.project(raw)['source_sha256']['candidate_receipt'],'a'*64)

    def test_reject_bad_selected_shape_and_anchors(self):
        for value in (True,{},'x','b'*64):
            row=fixture();row['source_sha256']['candidate_space']=value
            with self.assertRaises(ValueError):p.project(json.dumps(row).encode())

    def test_reject_invalid_and_duplicate_json(self):
        raw=json.dumps(fixture()).encode()
        bad=(raw+b' x',raw.replace(b'"schema_version":',b'"schema_version":0,"schema_version":'),
             raw.replace(b'PRIVATE_VALUE_MARKER',b'bad\\q'),raw.replace(b'"PRIVATE_VALUE_MARKER"',b'NaN'),
             b' '*131073,b'[]',raw.replace(b'"PRIVATE_VALUE_MARKER"',b'01'))
        for item in bad:
            with self.assertRaises(ValueError):p.project(item)

    def test_structure_bound(self):
        row=fixture();row['ignored']='x'
        raw=json.dumps(row).encode().replace(b'"x"', b'['*34+b'0'+b']'*34)
        with self.assertRaisesRegex(ValueError,'STRUCTURE_BOUND'):p.project(raw)

    def test_fixed_read_closes_fds_and_preserves_bytes(self):
        raw=json.dumps(fixture()).encode();meta=info(len(raw));opens=[];closed=[]
        def opening(name,flags,**kw):
            opens.append((name,flags));return len(opens)
        with patch.object(p,'EXPECTED_SHA',hashlib.sha256(raw).hexdigest()),patch.object(p.os,'open',side_effect=opening),patch.object(p.os,'close',side_effect=closed.append),patch.object(p.os,'fstat',return_value=meta),patch.object(p.os,'stat',return_value=meta),patch.object(p.os,'read',side_effect=[raw,b'']):
            self.assertEqual(p.read_fixed(),raw)
        self.assertEqual(sorted(closed),list(range(1,len(opens)+1)))
        self.assertTrue(all(flags & p.os.O_NOFOLLOW for name,flags in opens))
        self.assertTrue(all('/' not in name for name,flags in opens[1:]))

    def test_hardlink_rejected_without_read(self):
        meta=info(5);meta.st_nlink=2
        with patch.object(p.os,'open',return_value=5),patch.object(p.os,'close'),patch.object(p.os,'fstat',return_value=meta),patch.object(p.os,'read',side_effect=AssertionError('NO_READ')):
            with self.assertRaisesRegex(ValueError,'FILE_GATE'):p.read_fixed()

    def test_changed_identity_rejected(self):
        raw=b'{}';before=info(2);after=copy.copy(before);after.st_mtime_ns+=1
        with patch.object(p.os,'open',return_value=5),patch.object(p.os,'close'),patch.object(p.os,'fstat',side_effect=[before,after]),patch.object(p.os,'read',side_effect=[raw,b'']):
            with self.assertRaisesRegex(ValueError,'FILE_CHANGED'):p.read_fixed()

    def test_hash_mismatch_rejected_before_projection(self):
        raw=b'{}';meta=info(2)
        with patch.object(p.os,'open',return_value=5),patch.object(p.os,'close'),patch.object(p.os,'fstat',return_value=meta),patch.object(p.os,'stat',return_value=meta),patch.object(p.os,'read',side_effect=[raw,b'']):
            with self.assertRaisesRegex(ValueError,'PACKAGE_SHA_MISMATCH'):p.read_fixed()

    def test_transport_rejects_excess_and_quality_fields(self):
        row=dict(status='PASS_PACKAGE_HASH_PROJECTION',hostname='bupt-gpus1',path=p.PATH,byte_count=123,
            file_sha256=p.EXPECTED_SHA,selected=p.project(json.dumps(fixture()).encode()),whole_bytes_read_for_sha=True,
            nonwhitelist_values_decoded=False,remote_files_written=False,protected_directory_visited=False,training_release=False)
        self.assertTrue(t.validate_response(json.dumps(row).encode()))
        row['quality']=1
        self.assertFalse(t.validate_response(json.dumps(row).encode()))


if __name__ == '__main__':unittest.main()
