"""Local synthetic checks only; all remote entrypoints mocked or uncalled."""
import base64
import json
import unittest
from unittest import mock
from scripts import probe_linux_lifecycle_images_e74 as image
from scripts import run_linux_lifecycle_phase_e74 as phase


class ImageTests(unittest.TestCase):
    def test_read_never_consumes_above_remaining_budget(self):
        pipe=mock.MagicMock()
        pipe.fileno.return_value=123
        proc=mock.MagicMock(stdout=pipe)
        proc.poll.return_value=0
        selector=mock.MagicMock()
        selector.__enter__.return_value=selector
        selector.get_map.return_value=True
        selector.select.return_value=[(mock.Mock(fileobj=pipe),None)]
        with mock.patch.object(image.subprocess,'Popen',return_value=proc), \
             mock.patch.object(image.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(image.os,'read',return_value=b'x'*6) as read:
            budget=[4090]
            with self.assertRaisesRegex(ValueError,'METADATA_BYTES'):image.capture(['fake'],budget)
        read.assert_called_once_with(123,6)
        self.assertEqual(budget[0],4096)

    def rows(self, volumes=None):
        return ('\n'.join(json.dumps(x) for ident in image.IDS for x in
            (ident, 'linux', 'amd64', ['python3'], None, volumes))+'\n').encode()

    def test_only_fixed_projection(self):
        with mock.patch.object(image.sys,'platform','linux'), \
             mock.patch.object(image.socket,'gethostname',return_value='bupt-gpus1'), \
             mock.patch.object(image,'capture',side_effect=[b'"2"\n"linux"\ntrue\n',self.rows()]) as call:
            result=image.probe()
        self.assertEqual(len(result['records']),2)
        self.assertTrue(all(r['declared_python_command'] for r in result['records']))
        self.assertEqual(call.call_args_list[1].args[0][-2:],list(image.IDS))
        self.assertFalse(result['new_inventory_scan'])
        self.assertEqual(result['actual_containers_created'],0)

    def test_volume_record_not_admitted(self):
        with mock.patch.object(image.sys,'platform','linux'), \
             mock.patch.object(image.socket,'gethostname',return_value='bupt-gpus1'), \
             mock.patch.object(image,'capture',side_effect=[b'"2"\n"linux"\ntrue\n',self.rows({'/data':{}})]):
            self.assertTrue(all(not r['volumes_empty'] for r in image.probe()['records']))

    def test_wrong_host_before_commands(self):
        with mock.patch.object(image.socket,'gethostname',return_value='foreign'), \
             mock.patch.object(image,'capture',side_effect=AssertionError('COMMAND')):
            with self.assertRaisesRegex(ValueError,'B_HOST_ONLY'):image.probe()

    def test_bad_projection(self):
        with mock.patch.object(image.sys,'platform','linux'), \
             mock.patch.object(image.socket,'gethostname',return_value='bupt-gpus1'), \
             mock.patch.object(image,'capture',side_effect=[b'"2"\n"linux"\ntrue\n',b'null\n']):
            with self.assertRaisesRegex(ValueError,'IMAGE_PROJECTION_ROWS'):image.probe()


class PhaseTests(unittest.TestCase):
    def test_compressed_payload_exact_source(self):
        wire=phase.payload('image',b'def main():return 0\n')
        with self.assertRaises(SystemExit) as result:exec(wire,{})
        self.assertEqual(result.exception.code,0)
        self.assertLess(len(wire),4096)

    def test_decompression_bound(self):
        wire=phase.payload('image',b'x'*20481)
        with self.assertRaises(AssertionError):exec(wire,{})

    def test_invalid_mode_before_io(self):
        with mock.patch.object(phase,'read',side_effect=AssertionError('IO')):
            with self.assertRaisesRegex(ValueError,'FIXED_MODE'):phase.run('arbitrary')

    def test_auth_pin_before_transport(self):
        with mock.patch.object(phase,'read',return_value=b'wrong'), \
             mock.patch.object(phase.io,'transport',side_effect=AssertionError('SSH')):
            with self.assertRaisesRegex(ValueError,'AMENDMENT_AUTH_PIN'):phase.run('image')

    def test_source_fits_payload_bound(self):
        self.assertLessEqual(len(phase.read(phase.SOURCES['execute'])),20480)


if __name__=='__main__':unittest.main()
