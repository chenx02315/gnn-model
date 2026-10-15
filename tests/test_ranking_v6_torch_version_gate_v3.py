"""Stdlib regression for real PyTorch's string-subclass representation."""
import unittest
from src.models.ranking_v6_torch_version_gate_v3 import validate_torch_runtime_version as validate


class TorchVersionLike(str):
    pass


class MisleadingString(str):
    def __eq__(self, other): return True
    def __str__(self): return '2.5.1+cu124'


class GateTests(unittest.TestCase):
    def test_plain_and_string_subclass_exact_build_pass(self):
        for value in ('2.5.1+cu124', TorchVersionLike('2.5.1+cu124')):
            self.assertEqual(validate(value, {'torch_runtime_version':'2.5.1+cu124'}), '2.5.1+cu124')

    def test_wrong_builds_and_overloaded_comparison_reject(self):
        for value in ('2.5.1', '2.5.1+cpu', '2.5.1+cu121', '2.5.1+cu124x',
                      TorchVersionLike('2.5.1+cpu'), MisleadingString('wrong')):
            with self.assertRaises(ValueError): validate(value, {'torch_runtime_version':'2.5.1+cu124'})

    def test_non_strings_never_coerced(self):
        class NoCoerce:
            def __str__(self): raise AssertionError('must not coerce')
        for value in (None, True, 2.5, NoCoerce(), b'2.5.1+cu124'):
            with self.assertRaises(ValueError): validate(value, {'torch_runtime_version':'2.5.1+cu124'})

    def test_contract_cannot_change_pin(self):
        for contract in (None, {}, {'torch_runtime_version':'2.5.1+cpu'},
                         {'torch_runtime_version':TorchVersionLike('2.5.1+cu124')}):
            with self.assertRaises(ValueError): validate('2.5.1+cu124', contract)


if __name__ == '__main__': unittest.main()
