"""Metadata mocks only; retains all frozen monitor regression cases."""
import stat
from unittest.mock import patch

from src.data import direct_scratch_monitor_e102 as monitor
from tests import test_prospective_acceptance_scratch_v1 as legacy


class Tests(legacy.Tests):
    def setUp(self):
        binding = patch.object(legacy, 'm', monitor)
        binding.start()
        self.addCleanup(binding.stop)

    def test_owned_socket_is_metadata_only_and_charged(self):
        leaf = legacy.info(11, blocks=1, mode=stat.S_IFSOCK | 0o700)
        leaf.st_uid = 1047
        with legacy.tree({'pvmtmp.1047.63195.bupt-vncs2.0': leaf}) as (opened, read), \
                patch.object(monitor.os, 'getuid', return_value=1047, create=True):
            result = monitor._sample(10, 10)
            self.assertEqual(result['named_bytes'], 512)
            opened.assert_not_called()
            read.assert_not_called()

    def test_unknown_or_foreign_socket_rejected(self):
        for name, uid in [('other.sock', 1047),
                          ('pvmtmp.1047.63195.bupt-vncs2.0', 1000)]:
            leaf = legacy.info(11, mode=stat.S_IFSOCK | 0o700)
            leaf.st_uid = uid
            with self.subTest(name=name, uid=uid), legacy.tree({name: leaf}), \
                    patch.object(monitor.os, 'getuid', return_value=1047, create=True):
                with self.assertRaisesRegex(ValueError, 'SCRATCH_UNREVIEWED_LEAF'):
                    monitor._sample(10, 10)
