"""Immutable, fresh E124 execution clock; importing locally grants no runtime.

The bootstrap must capture the clock before loading the reviewed source bundle.
No environment reads, remote calls, or renewal mechanism live in this module.
"""
import hashlib
import json
import math
import re
from types import MappingProxyType

AUTH_SHA256 = 'b9fb213ad18081dd0970ab765cf869e9591621c0dabf5c9184f629e98e4317b0'
ROOT = '/temp/jiangchuanc/multimode_ate_identifier_repair_e124_20261027_r1'
WALL_SECONDS = 50400
PROPOSAL_SHA256 = 'a6eca925c4df7ab378cb072ee8e8c0df8960bf81e91786560052a06c17751e97'


def require(condition, label):
    if not condition:
        raise ValueError(label)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_AUTHORITY_KEY')
        result[key] = value
    return result


def build_context(authority_bytes, boot_id, start_monotonic, current_monotonic):
    require(type(authority_bytes) is bytes and len(authority_bytes) <= 65536 and
            hashlib.sha256(authority_bytes).hexdigest() == AUTH_SHA256, 'AUTHORITY_PIN')
    authority = json.loads(authority_bytes.decode('utf-8'), object_pairs_hook=_pairs)
    require(authority.get('schema') == 'prospective-identifier-repair-authorization-e124-v1' and
            authority.get('approval_source') == 'explicit_user_reply' and
            authority.get('user_authorization_received') is True and
            authority.get('proposal_sha256') == PROPOSAL_SHA256 and
            authority.get('new_output_root') == ROOT and
            authority.get('old_package_clock_and_evidence_immutable') is True, 'AUTHORITY_SCOPE')
    scope = authority['approved_scope']
    expected = dict(actions=18, tessent_attempts_max=48, translation_attempts_max=30,
        linux_process_selftests_max=3, versions_max=1, workers=1, automatic_retries=0,
        sampled_memory_stop_bytes=536870912, sampled_directory_stop_bytes=8589934592,
        new_package_wall_seconds_max=WALL_SECONDS)
    require(all(type(scope.get(key)) is int and scope[key] == value
                for key, value in expected.items()), 'AUTHORITY_LIMITS')
    require(scope.get('host') == 'A_ONLY' and scope.get('circuits') == ['aes_core', 'spi'] and
            scope.get('role') == 'TRAIN_DATA_ACQUISITION_ONLY' and
            scope.get('stop_on_first_failure') is True and
            scope.get('new_timer_start') == 'FIRST_APPROVED_A_CALL_OF_NEW_PACKAGE_AFTER_LOCAL_GATES' and
            type(scope.get('additional_historical_reports')) is int and
            scope['additional_historical_reports'] == 0 and
            all(scope.get(key) is False for key in
                ('LSF_allowed', 'B_allowed', 'training_allowed', 'BLIND_allowed')),
            'AUTHORITY_BOUNDARIES')
    require(type(boot_id) is str and re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot_id) is not None,
        'BOOT_ID')
    for value in (start_monotonic, current_monotonic):
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                'BOOTSTRAP_CLOCK_TYPE')
    require(0 <= current_monotonic - start_monotonic <= 30, 'BOOTSTRAP_CLOCK_FRESHNESS')
    return MappingProxyType(dict(AUTH_SHA256=AUTH_SHA256, BOOT_ID=boot_id,
        PACKAGE_START=start_monotonic, PACKAGE_END=start_monotonic + WALL_SECONDS,
        ROOT=ROOT, SIDECAR=ROOT + '.initial_intent.json', WALL_SECONDS=WALL_SECONDS))


# Only the reviewed remote bootstrap injects this object. Local imports are inert.
CONFIG = None
if '__runtime_context__' in globals():
    _bootstrap = globals()['__runtime_context__']
    require(type(_bootstrap) is dict and set(_bootstrap) ==
            {'authority_bytes', 'boot_id', 'start_monotonic', 'current_monotonic'},
            'BOOTSTRAP_CONTEXT_SHAPE')
    CONFIG = build_context(**_bootstrap)
    del _bootstrap
