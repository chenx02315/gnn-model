"""Pure compatibility adapter; runtime values stay in caller RAM, never receipts.

Not environment capture or authentication, nor an execution grant. The trusted
controller must bind the E112 response and reread deployed launcher identity.
Missing optional MGC roots are not invented. Historical E112 stays unchanged.
"""
from . import prospective_runtime_profile_e112 as profile
from . import prospective_generation_supervision_e109 as supervisor
from . import prospective_tessent_acceptance_v1 as pins

ROOTLESS_KEYS = frozenset(('PATH', 'LD_LIBRARY_PATH', 'LM_LICENSE_FILE', 'MGLS_LICENSE_FILE'))


def prepare_runtime(runtime_values, observed_metadata, launcher_sha256):
    if type(runtime_values) is not dict or set(runtime_values) - set(profile.KEYS):
        raise ValueError('RUNTIME_ALLOWLIST_ONLY')
    current = profile.snapshot(dict(runtime_values), False)
    if current != observed_metadata:
        raise ValueError('RUNTIME_PROFILE_DRIFT')
    if launcher_sha256 != pins.LAUNCHER_SHA256:
        raise ValueError('PINNED_ABSOLUTE_LAUNCHER_REQUIRED')
    all_compatible = all(row['compatible'] for row in current['normalization'].values())
    rootless = (not current['vendor_root_present'] and set(current['keys']) == ROOTLESS_KEYS and
                current['license_present'] and not current['missing_required_keys'] and all_compatible)
    if not current['strict_compatible'] and not rootless:
        raise ValueError('UNQUALIFIED_RUNTIME_PROFILE')
    normalized = {}
    for key, value in runtime_values.items():
        parts = value.split(':') if key in profile.SEARCH else [value]
        cleaned = []
        for part in parts:
            if not part and key in profile.SEARCH:
                continue
            cleaned.append(part.rstrip('/') or '/')
        normalized[key] = ':'.join(cleaned) if key in profile.SEARCH else cleaned[0]
    # Reuse actual launch-spec bounds, including its stricter 4096B per value.
    supervisor._runtime_values(normalized)
    normalized_snapshot = profile.snapshot(normalized, False)
    if normalized_snapshot['raw_sha256'] != current['normalized_sha256']:
        raise ValueError('NORMALIZATION_DIGEST_MISMATCH')
    receipt = dict(schema='prospective-runtime-compatibility-e114-v1',
        status='COMPATIBLE_SHAPE_ONLY_NOT_ENVIRONMENT_AUTHENTICATION',
        compatibility_branch='OBSERVED_ROOTLESS_ABSOLUTE_LAUNCHER' if rootless else 'EXPLICIT_VENDOR_ROOT',
        raw_sha256=current['raw_sha256'], normalized_sha256=current['normalized_sha256'],
        keys=list(current['keys']), launcher_sha256=launcher_sha256,
        missing_mgc_root_preserved=not current['vendor_root_present'],
        values_disclosed_in_receipt=False, executable_tree_authenticated=False,
        runtime_launch_success_verified=False, execution_ready=False, training_release=False)
    return normalized, receipt
