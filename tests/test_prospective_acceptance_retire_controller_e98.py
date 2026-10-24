import ast
from pathlib import Path
import unittest
from scripts import execute_acceptance_retirement_e98 as m


class Tests(unittest.TestCase):
    def test_observe_payload_is_py36_and_bound(self):
        payload=m.prepare('retire_observe',m.control.sha(m.SOURCE.read_bytes()))
        self.assertLess(len(payload),131072)
        ast.parse(payload.decode('ascii'),feature_version=(3,6))

    def test_bad_source_or_op(self):
        for op,pin in (('retire_observe','0'*64),('register','0'*64)):
            with self.assertRaises(ValueError): m.prepare(op,pin)

    def test_controller_py36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__=='__main__': unittest.main()
