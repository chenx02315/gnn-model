"""Pure planner checks; static local fixtures, never a scheduler call."""
import ast
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from src.data import prospective_acceptance_registration_e97 as m

ROOT = Path(__file__).resolve().parents[1]
OBS = (ROOT / 'data/manifests/ranking_v6_e97_lsf_setup_observation_20261024_r1.json').read_bytes()
AUTH = (ROOT / 'contracts/prospective_acceptance_authorization_e97_20261024.json').read_bytes()


def state():
    return dict(job_id=123, state='PSUSP', queue='normal', job_name=m.JOB_NAME,
                number_processes=1, rerunnable=False, array=False, requested_host='bupt-vncs2')


class RegistrationTests(unittest.TestCase):
    def test_fixed_plan(self):
        plan = m.build_registration(OBS, AUTH, 'a' * 64)
        self.assertEqual(plan['argv'], [m.BINDIR + 'bsub', '-H', '-rn', '-n', '1',
            '-q', 'normal', '-m', 'bupt-vncs2', '-J', 'gnn_e97_acceptance_r1', '-M', '512', '-R',
            'rusage[mem=512] span[hosts=1]', '-W', '45', '-cwd', m.ROOT, '-oo',
            m.ROOT + '/registration/stdout.log', '-eo', m.ROOT + '/registration/stderr.log',
            m.BINDIR + 'blaunch', '/usr/bin/python3', '-I', '-S', '-B',
            m.ROOT + '/scripts/run_acceptance_job_e97.py'])
        self.assertFalse(plan['automatic_resume'])
        self.assertFalse(plan['actual_job_memory_proof'])
        self.assertTrue(plan['unknown_submission_consumes_only_attempt'])
        self.assertEqual(plan['required_fresh_config_sha256'], m.CONFIG_SHA256)

    def test_pins_before_parsing(self):
        for observation, auth in ((b'{', AUTH), (OBS, b'{'), (OBS + b' ', AUTH)):
            with mock.patch.object(m.json, 'loads') as parse:
                with self.assertRaisesRegex(m.RegistrationError, 'SOURCE_PIN'):
                    m.build_registration(observation, auth, 'a' * 64)
                if observation != OBS:
                    parse.assert_not_called()

    def test_invalid_manifest_pin(self):
        for pin in (True, 'A' * 64, '../foo', ''):
            with self.assertRaises(m.RegistrationError):
                m.build_registration(OBS, AUTH, pin)

    def test_explicit_mb_single_literal_required(self):
        for key, item in (('raw_token', 'KB'), ('raw_token', 'mb'), ('count', True),
                          ('count', 2), ('status', 'ambiguous')):
            value = json.loads(OBS.decode('ascii'))
            value['config']['selected_parameters']['LSF_UNIT_FOR_LIMITS'][key] = item
            with self.assertRaisesRegex(m.RegistrationError, 'MB_REQUIRED'):
                m._observation(value)

    def test_executable_and_config_pins(self):
        for target in ('config', 'executable', 'metadata'):
            value = json.loads(OBS.decode('ascii'))
            if target == 'config':
                value['config']['sha256'] = '0' * 64
            elif target == 'executable':
                value['executables']['bsub']['path'] = '/tmp/bsub'
            else:
                value['executables']['bsub']['metadata']['size'] = True
            with self.assertRaises(m.RegistrationError):
                m._observation(value)

    def test_literal_submission(self):
        self.assertEqual(m.parse_submission(b'Job <123> is submitted to queue <normal>.\n'), 123)
        self.assertEqual(m.build_registration_query(123), [m.BINDIR + 'bjobs', '-l', '123'])

    def test_ambiguous_unknown_submission_consumed(self):
        good = b'Job <123> is submitted to queue <normal>.\n'
        for raw in (b'', good + good, b'warning\n' + good, good.replace(b'normal', b'other'),
                    good.replace(b'123', b'0'), good.replace(b'123', b'123[1]')):
            with self.assertRaises(m.RegistrationError):
                m.parse_submission(raw)

    def test_reviewed_held_registration(self):
        self.assertTrue(m.validate_registration(state(), 123)['registration_fields_verified'])

    def test_missing_review_fields(self):
        for key in state():
            value = state(); del value[key]
            with self.assertRaisesRegex(m.RegistrationError, 'FIELDS_REQUIRED'):
                m.validate_registration(value, 123)

    def test_invalid_state_and_booleans(self):
        for key, item in (('state', 'PEND'), ('state', 'UNKNOWN'), ('queue', 'other'),
                          ('job_name', m.JOB_NAME + '[1]'), ('job_id', True),
                          ('number_processes', True), ('rerunnable', 0), ('array', None)):
            value = state(); value[key] = item
            with self.assertRaises(m.RegistrationError):
                m.validate_registration(value, 123)
        with self.assertRaises(m.RegistrationError):
            m.validate_registration(state(), True)

    def test_host_affinity_is_explicit_not_span_only(self):
        argv = m.build_registration(OBS, AUTH, 'a' * 64)['argv']
        self.assertEqual(argv[argv.index('-m') + 1], 'bupt-vncs2')
        for host in ('other', '', None, ['bupt-vncs2']):
            value = state(); value['requested_host'] = host
            with self.assertRaisesRegex(m.RegistrationError, 'REQUESTED_HOST'):
                m.validate_registration(value, 123)
        value = state(); del value['requested_host']
        with self.assertRaisesRegex(m.RegistrationError, 'FIELDS_REQUIRED'):
            m.validate_registration(value, 123)

    def test_python36_and_no_io_process_imports(self):
        source = (ROOT / 'src/data/prospective_acceptance_registration_e97.py').read_text()
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        tree = ast.parse(source, **kwargs)
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names]
        self.assertEqual(imports, ['hashlib', 'json', 're'])


if __name__ == '__main__':
    unittest.main()
