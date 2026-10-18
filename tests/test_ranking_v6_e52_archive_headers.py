import io
import tarfile
import unittest
import types
from unittest.mock import patch
from scripts import inspect_ranking_v6_e52_archive_headers as p


def fixture(names):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w')as archive:
        for name in names:
            info=tarfile.TarInfo(name);info.size=6
            archive.addfile(info,io.BytesIO(b'SECRET'))
    buf.seek(0)
    return buf


class HeaderTests(unittest.TestCase):
    def test_only_metadata_names_no_member_decode(self):
        with patch.object(tarfile.TarFile,'extractfile',side_effect=AssertionError('NO_PAYLOAD')):
            result=p.inspect_stream(fixture(['pkg/outcomes.tsv','pkg/receipt_v2.json','pkg/source_provenance_v2.tsv']))
        self.assertEqual(result['logical_members_scanned'],3)
        self.assertEqual([x['name']for x in result['metadata_members']],['pkg/receipt_v2.json','pkg/source_provenance_v2.tsv'])

    def test_bad_paths_and_duplicate_rejected(self):
        for names in (['../receipt_v2.json'],['/receipt_v2.json'],['pkg\\receipt_v2.json'],['receipt_v2.json']*2):
            with self.assertRaisesRegex(ValueError,'MEMBER_PATH'):p.inspect_stream(fixture(names))

    def test_member_bound(self):
        with patch.object(p,'MAX_MEMBERS',1):
            with self.assertRaisesRegex(ValueError,'MEMBER_BOUND'):p.inspect_stream(fixture(['x','y']))

    def test_decompression_bound(self):
        reader=p.LimitedReader(io.BytesIO(b'012345'),4)
        with self.assertRaisesRegex(ValueError,'DECOMPRESSED_BOUND'):reader.read(6)

    def test_pax_metadata_is_acknowledged_not_exported(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w',format=tarfile.PAX_FORMAT)as archive:
            info=tarfile.TarInfo('pkg/receipt_v2.json');info.size=1;info.pax_headers={'comment':'NOT_EXPORTED'}
            archive.addfile(info,io.BytesIO(b'Q'))
        buf.seek(0);result=p.inspect_stream(buf)
        self.assertEqual(result['logical_members_scanned'],1)
        self.assertTrue(result['extension_header_metadata_may_be_decoded'])
        self.assertNotIn('NOT_EXPORTED',str(result))

    def identities(self):
        return types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=3,st_nlink=1,st_size=4,st_mtime_ns=5,st_ctime_ns=6)

    def test_windows_cross_api_ctime_difference_allowed_only_between_apis(self):
        a=self.identities();b=self.identities();b.st_ctime_ns=100
        with patch.object(p.sys,'platform','win32'):p.verify_identity(a,b,a,b)

    def test_same_api_change_always_rejected(self):
        a=self.identities();changed=self.identities();changed.st_ctime_ns+=1
        for platform in ('win32','linux'):
            with patch.object(p.sys,'platform',platform):
                with self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):p.verify_identity(a,a,changed,a)
                with self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):p.verify_identity(a,a,a,changed)

    def test_posix_cross_api_ctime_difference_rejected(self):
        a=self.identities();b=self.identities();b.st_ctime_ns+=1
        with patch.object(p.sys,'platform','linux'):
            with self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):p.verify_identity(a,b,a,b)


if __name__=='__main__':unittest.main()
