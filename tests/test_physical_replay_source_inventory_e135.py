"""Virtual fixed-tree IO, never actual A/source reads."""
import copy
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import physical_replay_source_inventory_e135 as inv
from src.data import physical_replay_source_reader_e135 as core
from tests.test_hf_credit_artifact_reader_e134 import Files


class Stream(object):
    def __init__(self,names):
        self.names = iter(names)
        self.reads = 0
    def __enter__(self):
        return self
    def __exit__(self,*args):
        return False
    def __iter__(self):
        return self
    def __next__(self):
        value = next(self.names)
        self.reads += 1
        return SimpleNamespace(name=value)


class TreeFiles(Files):
    def __init__(self):
        records = list(core.FILES)+list(inv.INPUTS)
        super(TreeFiles,self).__init__(records,[b'synthetic-'+str(i).encode('ascii') for i in range(len(records))])
        self.info[core.FILES[1]['path']].st_uid = 0
        self.add(inv.TREE,directory=True)
        self.add(inv.TREE+'/d',directory=True)
        self.add(inv.TREE+'/d/a',raw=b'tree-body')
        self.add(inv.TREE+'/z',raw=b'')
        self.streams = []
    def open(self,name,flags,dir_fd=None):
        path = self.handles[dir_fd][0]+'/'+name
        self.opened.append(path)
        return self.handle(path)
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        if dir_fd is None and name.startswith('/proc/self/fd/'):
            return self.fstat(int(name.rsplit('/',1)[1]))
        return super(TreeFiles,self).stat(name,dir_fd,follow_symlinks)
    def readlink(self,alias):
        return self.handles[int(alias.rsplit('/',1)[1])][0]
    def scandir(self,alias):
        if type(alias) is int:
            raise TypeError('Python3.6 integer scandir unsupported')
        parent = self.readlink(alias)
        stream = Stream([p[len(parent)+1:] for p in self.info if p.startswith(parent+'/') and '/' not in p[len(parent)+1:]])
        self.streams.append(stream)
        return stream


def install(test):
    fs = TreeFiles()
    inputs = tuple(dict(pin,bytes=len(fs.body[pin['path']]),sha256=core.sha(fs.body[pin['path']])) for pin in inv.INPUTS)
    for patch in (mock.patch.object(inv,'INPUTS',inputs),
        mock.patch.object(inv.anchored,'_directory',side_effect=fs.directory),
        mock.patch.object(inv.os,'stat',side_effect=fs.stat),mock.patch.object(inv.os,'fstat',side_effect=fs.fstat),
        mock.patch.object(inv.os,'open',side_effect=fs.open),mock.patch.object(inv.os,'close',side_effect=fs.close),
        mock.patch.object(inv.os,'read',side_effect=fs.read),mock.patch.object(inv.os,'readlink',side_effect=fs.readlink),
        mock.patch.object(inv.os,'scandir',side_effect=fs.scandir),
        mock.patch.object(inv.os,'O_NOFOLLOW',131072,create=True),mock.patch.object(inv.os,'O_NONBLOCK',262144,create=True),
        mock.patch.object(inv.os,'O_DIRECTORY',65536,create=True)):
        patch.start()
        test.addCleanup(patch.stop)
    test.addCleanup(lambda:test.assertEqual(fs.handles,{}))
    return fs


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.fs = install(self)
        self.tick = mock.Mock()

    def test_full_sorted_depth_first_tree_hash_inventory_no_body(self):
        result = inv.inventory(self.tick)
        self.assertTrue(result['complete'])
        self.assertEqual([r['relative'] for r in result['rows']],['','d','d/a','z'])
        self.assertEqual(result['bytes'],len(b'tree-body'))
        self.assertEqual(result['entries'],3)
        self.assertNotIn('body_base64',core.canonical(result).decode('ascii'))
        for pin in inv.INPUTS:
            self.assertEqual(inv.read_input(pin,self.tick)['sha256'],pin['sha256'])

    def test_entry_depth_byte_metadata_caps_and_no_overfetch(self):
        with mock.patch.object(inv,'MAX_ENTRIES',2):
            with self.assertRaisesRegex(ValueError,'TREE_ENTRY_CAP'):
                inv.inventory(self.tick)
        self.assertEqual(sum(s.reads for s in self.fs.streams),2)
        for key,value,code in [('MAX_DEPTH',1,'TREE_DEPTH_CAP'),('MAX_BYTES',1,'INVENTORY_BYTE_CAP'),('MAX_METADATA',10,'TREE_METADATA_CAP')]:
            with mock.patch.object(inv,key,value):
                with self.assertRaisesRegex(ValueError,code):
                    inv.inventory(self.tick)

    def test_alias_wrong_target_link_special_owner_fail_preopen(self):
        with mock.patch.object(inv.os,'readlink',return_value='/other'):
            with self.assertRaisesRegex(ValueError,'TREE_FD_ALIAS_CHANGED'):
                inv.inventory(self.tick)
        import stat
        path = inv.TREE+'/d/a'
        for key,value in [('st_mode',stat.S_IFLNK),('st_mode',stat.S_IFIFO),('st_nlink',2),('st_uid',0)]:
            old = getattr(self.fs.info[path],key)
            setattr(self.fs.info[path],key,value)
            with self.assertRaises(ValueError):
                inv.inventory(self.tick)
            setattr(self.fs.info[path],key,old)
        self.assertNotIn(path,self.fs.opened)

    def test_mutation_truncation_input_hash_and_injected_tick(self):
        path = inv.TREE+'/d/a'
        self.fs.body[path] = b''
        with self.assertRaisesRegex(ValueError,'INVENTORY_SHORT_READ'):
            inv.inventory(self.tick)
        self.fs.body[path] = b'tree-body'
        self.fs.read_hook = lambda p:setattr(self.fs.info[p],'st_ctime_ns',101)
        with self.assertRaisesRegex(ValueError,'INVENTORY_FILE_CHANGED'):
            inv.inventory(self.tick)
        self.fs.read_hook = None
        pin = inv.INPUTS[0]
        self.fs.body[pin['path']] = b'x'*pin['bytes']
        with self.assertRaisesRegex(ValueError,'FIXED_INPUT_SHA'):
            inv.read_input(pin,self.tick)
        with self.assertRaisesRegex(ValueError,'EXACT_FIXED_INPUT'):
            inv.read_input(dict(pin,path='/elsewhere'),self.tick)
        with self.assertRaisesRegex(ValueError,'STOP'):
            inv.inventory(mock.Mock(side_effect=ValueError('STOP')))

    def test_protected_names_rejected_before_any_child_open_or_visit(self):
        names = ('.ssh','ssh','token','tokens','private_key','id_rsa','log','logs','logs_more',
            'data.log','data.ckpt','data.pt','data.pth','BLIND_data','x_checkpoint','x_secret',
            'x_credential','x_outcome','TOKEN','DATA.LOG')
        for name in names:
            path = inv.TREE+'/'+name
            self.fs.add(path,raw=b'never read',directory=(name == '.ssh'))
            self.fs.opened.clear()
            with self.assertRaisesRegex(ValueError,'TREE_ENTRY_NAME'):
                inv.inventory(self.tick)
            self.assertEqual(self.fs.opened,[])
            del self.fs.info[path]
            del self.fs.body[path]


if __name__ == '__main__':
    unittest.main()
