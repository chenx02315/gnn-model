import ast
from pathlib import Path
import unittest
from scripts import execute_acceptance_resume_e98 as m


class Tests(unittest.TestCase):
    def test_observe_payload_py36(self):
        raw=m.prepare('pre_resume_observation',m.control.sha(m.SOURCE.read_bytes()))
        self.assertLess(len(raw),65536)
        ast.parse(raw.decode('ascii'),feature_version=(3,6))

    def test_bad_operation_or_pin(self):
        for op,pin in (('cancel','0'*64),('registration_review','0'*64)):
            with self.assertRaises(ValueError):m.prepare(op,pin)

    def test_resume_needs_external_review_pins(self):
        with self.assertRaisesRegex(ValueError,'INDEPENDENT_REVIEW_PINS_REQUIRED'):
            m.prepare('resume',m.control.sha(m.SOURCE.read_bytes()))

    def test_controller_py36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__=='__main__':unittest.main()
