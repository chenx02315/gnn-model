"""Pure environment normalization; no reads, execution or authenticity claim.

Default snapshots never return environment values. disclose=True is exclusively
for a future trusted worker's RAM and must never be sent as collector evidence.
"""
import hashlib
import json
import re

KEYS = ('PATH', 'LD_LIBRARY_PATH', 'MGC_HOME', 'MGC_ROOT',
        'LM_LICENSE_FILE', 'MGLS_LICENSE_FILE')
SEARCH = ('PATH', 'LD_LIBRARY_PATH', 'LM_LICENSE_FILE', 'MGLS_LICENSE_FILE')
SCHEMA = 'e112-runtime-profile-v1'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _path(value):
    if not value:
        return value, False
    trimmed = value.rstrip('/') or '/'
    good = (trimmed.startswith('/') and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in trimmed)
            and '\\' not in trimmed and all(part not in ('.', '..', '')
                for part in trimmed.split('/')[1:]))
    if trimmed == '/':
        good = True
    return trimmed, good


def snapshot(environ, disclose=False):
    if type(environ) is not dict or type(disclose) is not bool:
        raise ValueError('PROFILE_ARGUMENTS')
    raw, normalized, rows = {}, {}, {}
    valid = True
    for key in KEYS:
        if key not in environ:
            continue
        value = environ[key]
        if type(value) is not str or len(value) > 16384:
            raise ValueError('PROFILE_VALUE_BOUND_OR_TYPE')
        raw[key] = value
        parts = value.split(':') if key in SEARCH else [value]
        cleaned, empty, slashes, compatible = [], 0, 0, True
        for part in parts:
            if part == '' and key in SEARCH:
                empty += 1
                continue
            if key in ('LM_LICENSE_FILE', 'MGLS_LICENSE_FILE') and re.fullmatch(
                    r'(?:[1-9][0-9]{0,4})?@[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', part):
                item, good = part, True
                port = part.split('@', 1)[0]
                good = not port or int(port) <= 65535
            else:
                item, good = _path(part)
            slashes += len(part) - len(item) if part.endswith('/') else 0
            compatible = compatible and good
            cleaned.append(item)
        normalized[key] = ':'.join(cleaned) if key in SEARCH else cleaned[0]
        compatible = compatible and bool(normalized[key])
        rows[key] = dict(empty_search_items_removed=empty, trailing_slashes_removed=slashes,
                         compatible=compatible)
        valid = valid and compatible
    vendor = sorted(k for k in environ if type(k) is str and len(k) <= 128 and
                    re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) and
                    k.startswith(('MGC_', 'MGLS_', 'LM_', 'TESSENT', 'MENTOR')) and k not in KEYS)
    if len(vendor) > 128:
        raise ValueError('PROFILE_VENDOR_KEY_BOUND')
    required = ('PATH',)
    missing = [key for key in required if not normalized.get(key)]
    # Missing vendor root/license means unknown deployment compatibility.
    root_present = bool(normalized.get('MGC_HOME') or normalized.get('MGC_ROOT'))
    license_present = bool(normalized.get('LM_LICENSE_FILE') or normalized.get('MGLS_LICENSE_FILE'))
    result = dict(schema=SCHEMA, keys=sorted(raw), raw_sha256=_sha(raw),
                  normalized_sha256=_sha(normalized), normalization=rows,
                  missing_required_keys=missing, vendor_root_present=root_present,
                  license_present=license_present, vendor_key_names=vendor,
                  strict_compatible=valid and not missing and root_present and license_present,
                  values_disclosed=disclose, environment_authenticated=False)
    if disclose:
        if not result['strict_compatible']:
            raise ValueError('PROFILE_NOT_STRICT_COMPATIBLE')
        result['normalized_values'] = normalized
    return result
