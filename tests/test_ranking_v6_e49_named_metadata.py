import copy
import errno
import json
import stat
import types
import unittest
from unittest.mock import patch

from scripts import probe_ranking_v6_e49_named_metadata as probe
from scripts import run_ranking_v6_e49_named_metadata as transport


class Entries:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return (types.SimpleNamespace(name=n) for n in self.names)

    def __exit__(self, *args):
        pass


class FakeOS:
    O_RDONLY, O_DIRECTORY, O_NOFOLLOW = 0, 1, 2

    def __init__(self, tree=None):
        self.tree = tree or {}
        self.fds = {0: ''}
        self.next_fd = 1
        self.opened, self.stats = [], []
        self.ids = {}
        self.closed = []

    def info(self, path, mode):
        if path not in self.ids:
            self.ids[path] = len(self.ids) + 1
        return types.SimpleNamespace(st_mode=mode, st_dev=1, st_ino=self.ids[path])

    def open(self, name, flags, dir_fd):
        assert flags & self.O_DIRECTORY and flags & self.O_NOFOLLOW
        path = '/'.join(filter(None, (self.fds[dir_fd], name)))
        self.opened.append(path)
        if path not in self.tree:
            raise OSError(errno.ENOENT, 'missing')
        if type(self.tree[path]) is not list:
            raise OSError(errno.ELOOP, 'not directory')
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = path
        return fd

    def close(self, fd):
        self.closed.append(fd)
        del self.fds[fd]

    def fstat(self, fd):
        return self.info(self.fds[fd], stat.S_IFDIR)

    def stat(self, name, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        path = self.fds[dir_fd] + '/' + name
        self.stats.append(path)
        obj = self.tree.get(path)
        mode = stat.S_IFDIR if type(obj) is list else (stat.S_IFLNK if obj == 'link' else stat.S_IFREG)
        return self.info(path, mode)

    def scandir(self, fd):
        return Entries(self.tree[self.fds[fd]])

    def uname(self):
        return types.SimpleNamespace(nodename='bupt-gpus1')


def empty_payload():
    return probe.locate(0, FakeOS())


class NamedMetadataTests(unittest.TestCase):
    def test_frozen_scope_and_transport(self):
        self.assertEqual(len(probe.ROOTS), 72)
        self.assertEqual(len(set(probe.ROOTS)), 72)
        self.assertNotIn(probe.PROTECTED, probe.ROOTS)
        self.assertTrue(transport.validate_response(json.dumps(empty_payload()).encode('ascii')))
        self.assertEqual(transport.COMMAND[-2], 'cjc@gpuserver.buptic.top')
        self.assertIn('StrictHostKeyChecking=yes', transport.COMMAND)
        self.assertIn('HostKeyAlgorithms=ssh-ed25519', transport.COMMAND)
        self.assertEqual(transport.SOURCE.name, 'probe_ranking_v6_e49_named_metadata.py')

    def test_filter_before_stat_and_no_contents(self):
        root = probe.ROOTS[0].split('/')[-1]
        api = FakeOS({root: ['multimode_ate_gnn_v1', 'graphs', 'venv', 'runs', 'results',
                            'outcome_split', 'checkpoints', 'data', 'receipt_v2.json'],
                      root + '/data': ['source_provenance_v2.tsv'],
                      root + '/receipt_v2.json': 'file',
                      root + '/data/source_provenance_v2.tsv': 'file'})
        data = probe.locate(0, api)
        self.assertTrue(probe.validate_response(data))
        self.assertEqual(set(api.stats), {root + '/data', root + '/receipt_v2.json',
                                         root + '/data/source_provenance_v2.tsv'})
        self.assertFalse(any('multimode_ate_gnn_v1' in p for p in api.opened + api.stats))
        self.assertEqual(data['directory_count'], 2)
        self.assertEqual(data['total_entries'], 10)
        self.assertEqual(api.fds, {0: ''})

    def test_symlinks_and_nondirs_skipped_without_open(self):
        root = probe.ROOTS[0].split('/')[-1]
        api = FakeOS({root: ['data', 'manifests', 'receipt_v2.json'],
                      root + '/data': 'link', root + '/manifests': 'file',
                      root + '/receipt_v2.json': []})
        result = probe.locate(0, api)
        self.assertEqual(result['roots'][0]['directories'][0]['skipped'], 3)
        self.assertNotIn(root + '/data', api.opened)
        self.assertTrue(probe.validate_response(result))

    def test_depth_bound_reports_pruning(self):
        root = probe.ROOTS[0].split('/')[-1]
        api = FakeOS({root: ['data'], root+'/data': ['manifests'],
                      root+'/data/manifests': ['input'],
                      root+'/data/manifests/input': ['package', 'receipt_v2.json'],
                      root+'/data/manifests/input/package': ['source_provenance_v2.tsv']})
        result = probe.locate(0, api)
        self.assertTrue(probe.validate_response(result))
        rows = result['roots'][0]['directories']
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[-1]['depth_limited'], 1)
        self.assertNotIn(root+'/data/manifests/input/package', api.opened)

    def test_entry_bounds_duplicate_and_bad_name(self):
        for names in (['data', 'data'], ['x'+str(i) for i in range(2049)],
                      ['formal_candidate_space/../escape']):
            with self.assertRaises(ValueError):
                probe.classify(names, lambda n: None)
        root = probe.ROOTS[0].split('/')[-1]
        api = FakeOS({root: ['x'+str(i) for i in range(2049)]})
        with self.assertRaises(ValueError):
            probe.locate(0, api)
        self.assertEqual(api.fds, {0: ''})

    def test_total_and_directory_bounds(self):
        root = probe.ROOTS[0].split('/')[-1]
        for key, cap in (('MAX_TOTAL_ENTRIES', 1), ('MAX_DIRECTORIES', 1)):
            api = FakeOS({root: ['data', 'input'], root+'/data': [], root+'/input': []})
            with patch.object(probe, key, cap):
                with self.assertRaises(ValueError):
                    probe.locate(0, api)
            self.assertEqual(api.fds, {0: ''})

    def test_duplicate_identity_and_directory_swap_rejected(self):
        root = probe.ROOTS[0].split('/')[-1]
        api = FakeOS({root: ['receipt_v2.json', 'source_provenance_v2.tsv']})
        api.ids[root+'/receipt_v2.json'] = 7
        api.ids[root+'/source_provenance_v2.tsv'] = 7
        with self.assertRaisesRegex(ValueError, 'GLOBAL_DUPLICATE'):
            probe.locate(0, api)
        api = FakeOS({root: ['data'], root+'/data': []})
        original = api.fstat
        def swapped(fd):
            value = original(fd)
            if api.fds[fd].endswith('/data'):
                value.st_ino += 100
            return value
        api.fstat = swapped
        with self.assertRaisesRegex(ValueError, 'DIRECTORY_CHANGED'):
            probe.locate(0, api)

    def test_schema_wrong_scope_counts_and_flags(self):
        base = empty_payload()
        for key, value in (('hostname', 'other'), ('coverage', 'all B'),
                           ('directory_count', True), ('total_entries', 1),
                           ('global_absence_claimed', True), ('quality', 1)):
            data = copy.deepcopy(base)
            data[key] = value
            self.assertFalse(probe.validate_response(data))
        for key, value in (('root', probe.PROTECTED), ('availability', 'unknown')):
            data = copy.deepcopy(base)
            data['roots'][0][key] = value
            self.assertFalse(probe.validate_response(data))
        root = probe.ROOTS[0].split('/')[-1]
        base = probe.locate(0, FakeOS({root: []}))
        for key, value in (('path', '../data'), ('path', 'graphs'),
                           ('directories', ['checkpoints']), ('directories', ['data']),
                           ('named_files', ['outcomes.tsv']), ('skipped', 1),
                           ('depth_limited', 1), ('entry_count', True)):
            data = copy.deepcopy(base)
            data['roots'][0]['directories'][0][key] = value
            self.assertFalse(probe.validate_response(data))
        data = copy.deepcopy(base)
        data['roots'][0]['directories'] *= 2
        self.assertFalse(probe.validate_response(data))

    def test_transport_rejects_duplicate_keys_and_output_bound(self):
        raw = json.dumps(empty_payload()).encode('ascii')
        self.assertFalse(transport.validate_response(raw[:-1] + b', "hostname":"bupt-gpus1"}'))
        self.assertFalse(transport.validate_response(b'x' * (probe.MAX_OUTPUT + 1)))


if __name__ == '__main__':
    unittest.main()

