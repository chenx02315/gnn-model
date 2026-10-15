"""Prepared E21 version-gate repair only; no Torch import or run release.

PyTorch exports TorchVersion, a str subclass with overloaded comparison.
Accept string instances, then compare their base-string contents exactly.
Do not coerce arbitrary objects or use TorchVersion's semantic __eq__.
The failed v2 deployment and sources remain immutable evidence.
"""
TORCH_RUNTIME_VERSION = '2.5.1+cu124'


def validate_torch_runtime_version(observed, contract):
    expected = contract.get('torch_runtime_version') if type(contract) is dict else None
    if type(expected) is not str or expected != TORCH_RUNTIME_VERSION or not isinstance(observed, str):
        raise ValueError('TORCH_RUNTIME_VERSION')
    value = str.__str__(observed)
    if type(value) is not str or value != TORCH_RUNTIME_VERSION:
        raise ValueError('TORCH_RUNTIME_VERSION')
    return value
