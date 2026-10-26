"""Fixed read-only E112 collector; no CLI, deployment or ATPG entry point.

Root's independently reviewed controller supplies bound module source bytes.
Only the module-loaded environment metadata child is launched. No files are
written explicitly. Shell startup/module side effects are not attested absent.
"""
import base64
import hashlib
import json
import os
import platform
import shlex
import stat
import sys
import time

from src.data import prospective_acceptance_materializer_v1 as io
from src.data import prospective_tessent_acceptance_v1 as pins
from src.data import prospective_runtime_profile_e112 as profile
from src.data import direct_tessent_acceptance_e104 as direct

E88_SHA256 = 'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8'
SCHEMA = 'e112-readonly-preparation-v1'
NONCE = 'E112_PROFILE_METADATA_V1'
CHUNK = 65536
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_RESPONSE = 1024 * 1024
MARKER = b'TesterCycle:'
require = pins.require


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


class Budget(object):
    def __init__(self, domain, end):
        self.domain, self.end = domain, end
        self.bytes = 0
        self.next_sample = 0

    def tick(self):
        now = time.monotonic()
        require(now < self.end, 'COLLECTOR_DEADLINE')
        if now >= self.next_sample:
            self.domain.sample()
            self.next_sample = time.monotonic() + .25
        require(time.monotonic() < self.end, 'COLLECTOR_DEADLINE')


class Evidence(object):
    """Bounded prefix/body and raw STIL marker evidence, never a parser."""
    def __init__(self, report=False, stil=False, small_body=False):
        self.report, self.stil, self.small_body = report, stil, small_body
        self.prefix, self.body = bytearray(), bytearray()
        self.marker_count, self.tail = 0, b''
        self.samples = []
        self.line_number, self.line_bytes = 1, 0
        self.line_prefix, self.line_tail, self.line_match = bytearray(), b'', False

    def block(self, raw):
        if self.report:
            self.prefix.extend(raw[:max(0, 32768 - len(self.prefix))])
        if self.small_body:
            self.body.extend(raw)
        if not self.stil:
            return
        combined = self.tail + raw
        self.marker_count += combined.count(MARKER)
        self.tail = combined[-(len(MARKER) - 1):]
        pieces = raw.split(b'\n')
        for index, piece in enumerate(pieces):
            self.line_match = self.line_match or MARKER in self.line_tail + piece
            self.line_tail = (self.line_tail + piece)[-(len(MARKER) - 1):]
            self.line_bytes += len(piece)
            self.line_prefix.extend(piece[:max(0, 512 - len(self.line_prefix))])
            if index < len(pieces) - 1:
                self.finish_line()

    def finish_line(self):
        if self.line_match and len(self.samples) < 16:
            self.samples.append(dict(line_number=self.line_number, line_bytes=self.line_bytes,
                prefix_base64=_b64(bytes(self.line_prefix)), truncated=self.line_bytes > 512))
        self.line_number += 1
        self.line_bytes, self.line_prefix, self.line_tail, self.line_match = 0, bytearray(), b'', False

    def metadata(self):
        result = {}
        if self.report:
            result.update(prefix_base64=_b64(bytes(self.prefix)), prefix_bytes=len(self.prefix),
                          prefix_is_complete_parse=False)
        if self.small_body:
            result['body_base64'] = _b64(bytes(self.body))
        if self.stil:
            if self.line_bytes:
                self.finish_line()
            result.update(marker=MARKER.decode('ascii'), raw_marker_count=self.marker_count,
                          line_samples=self.samples, new_cycles_or_labels_derived=False)
        return result


def _read_at(parent, name, budget, expected=None, report=False, stil=False, launcher=False):
    budget.tick()
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1, 'SINGLE_LINK_REGULAR_REQUIRED')
    require(0 <= named.st_size <= MAX_FILE and budget.bytes + named.st_size <= MAX_TOTAL, 'BODY_BYTE_BOUND')
    if expected is not None:
        require(named.st_size == expected['bytes'], 'PINNED_SIZE_MISMATCH')
    require(not launcher or named.st_size <= 65536, 'LAUNCHER_BODY_BOUND')
    evidence = Evidence(report, stil, launcher or (report and not stil and named.st_size <= 65536))
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        require(io._identity(named) == io._identity(before), 'SOURCE_CHANGED')
        remaining = named.st_size
        while remaining:
            budget.tick()
            raw = os.read(fd, min(CHUNK, remaining))
            require(bool(raw), 'SHORT_READ')
            remaining -= len(raw)
            budget.bytes += len(raw)
            digest.update(raw)
            evidence.block(raw)
        budget.tick()
        require(io._identity(before) == io._identity(os.fstat(fd)) ==
                io._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'SOURCE_CHANGED')
        observed = digest.hexdigest()
        require(expected is None or 'sha256' not in expected or observed == expected['sha256'], 'FROZEN_INPUT_SHA')
        return dict(bytes=before.st_size, sha256=observed, whole_file_hashed=True, **evidence.metadata())
    finally:
        os.close(fd)


def _read_file(path, budget, expected=None, report=False, stil=False, launcher=False):
    parent, name = path.rsplit('/', 1)
    fd = io._directory(parent)
    try:
        return dict(_read_at(fd, name, budget, expected, report, stil, launcher), path=path, kind='file')
    finally:
        os.close(fd)


def _tree(path, pin, budget):
    """E85 ordered DFS digest, adapted only to add per-block budget hooks."""
    rows, counts, body = [], [0, 0], [0]
    def visit(fd, relative, depth):
        budget.tick()
        require(depth <= io.MAX_DEPTH, 'TREE_DEPTH_BOUND')
        counts[1] += 1
        require(counts[1] <= pin['directories'], 'TREE_DIRECTORY_BOUND')
        before = os.fstat(fd)
        rows.append([relative, 'directory', 0, None])
        names = []
        with os.scandir('/proc/self/fd/%d' % fd) as stream:
            for entry in stream:
                budget.tick()
                require(len(rows) + len(names) < io.MAX_ENTRIES, 'TREE_ENTRY_BOUND')
                names.append(entry.name)
        for name in sorted(names):
            require(name not in ('', '.', '..') and '/' not in name and '\x00' not in name and len(name) <= 255 and
                    name.lower() not in ('.ssh', 'ssh', 'token', 'tokens', 'private_key', 'id_rsa', 'log', 'logs') and
                    not name.lower().startswith('logs_') and not name.lower().endswith(('.log', '.ckpt', '.pt', '.pth')) and
                    not any(t in name.lower() for t in ('blind', 'checkpoint', 'secret', 'credential', 'outcome')),
                    'PROTECTED_OR_INVALID_TREE_NAME')
            rel = relative + '/' + name if relative else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(io._identity(info) == io._identity(os.fstat(child)), 'SOURCE_CHANGED')
                    visit(child, rel, depth + 1)
                    require(io._identity(info) == io._identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'SOURCE_CHANGED')
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'TREE_SPECIAL_OR_HARDLINK')
                counts[0] += 1
                require(counts[0] <= pin['regular_files_hashed'] and body[0] + info.st_size <= pin['body_bytes'],
                        'TREE_PINNED_BOUND')
                row = _read_at(fd, name, budget, expected={'bytes': info.st_size})
                body[0] += row['bytes']
                rows.append([rel, 'file', row['bytes'], row['sha256']])
        require(io._identity(before) == io._identity(os.fstat(fd)), 'SOURCE_DIRECTORY_CHANGED')
    root_fd = io._directory(path)
    try:
        visit(root_fd, '', 0)
        fresh = io._directory(path)
        try:
            require(io._identity(os.fstat(root_fd)) == io._identity(os.fstat(fresh)), 'SOURCE_ROOT_REPLACED')
        finally:
            os.close(fresh)
    finally:
        os.close(root_fd)
    digest = io._tree_digest(rows)
    require(digest == pin['tree_sha256'] and body[0] == pin['body_bytes'] and
            counts == [pin['regular_files_hashed'], pin['directories']], 'FROZEN_TREE_IDENTITY')
    return dict(path=path, kind='tree', bytes=body[0], sha256=digest,
                regular_files=counts[0], directories=counts[1], whole_file_hashed=True,
                sha256_scope='E85_SORTED_CHILD_DEPTH_FIRST_TREE')


def _capture_profile(source, domain, end):
    require(type(source) is bytes and 0 < len(source) <= 32768 and
            getattr(profile, '__source_sha256__', None) == pins.sha(source), 'PROFILE_SOURCE_BINDING')
    code = (source.decode('utf-8') + '\nimport os\nprint(json.dumps({"nonce":' + repr(NONCE) +
        ',"profile":snapshot(dict(os.environ),False)},sort_keys=True,separators=(",",":")))\n')
    command = 'module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c ' + shlex.quote(code)
    observed = direct.base.supervise(['/bin/bash', '-lc', command], '/', min(end, time.monotonic() + 30),
                                     domain, [65536])
    require(observed['returncode'] == 0 and observed['failure'] is None and observed['cleaned'] is True,
            'PROFILE_CHILD_FAILED')
    raw = observed['output']
    require(type(raw) is bytes and len(raw) <= 65536, 'PROFILE_RESPONSE_BOUND')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=pins._pairs)
        require(type(value) is dict and set(value) == {'nonce', 'profile'} and value['nonce'] == NONCE,
                'PROFILE_NONCE_OR_KEYS')
        result = value['profile']
        _validate_profile_metadata(result)
        return result
    except (ValueError, UnicodeError, TypeError, KeyError):
        return dict(schema='e112-runtime-profile-unqualified-v1', qualified=False,
                    reason='UNKNOWN_METADATA_FORMAT', values_disclosed=False)


def _validate_profile_metadata(value):
    require(type(value) is dict and set(value) == set(profile.snapshot({}, False)) and
            value['schema'] == profile.SCHEMA and value['values_disclosed'] is False and
            value['environment_authenticated'] is False, 'PROFILE_METADATA_KEYS')
    for key in ('strict_compatible', 'vendor_root_present', 'license_present'):
        require(type(value[key]) is bool, 'PROFILE_BOOLEAN')
    for key in ('raw_sha256', 'normalized_sha256'):
        require(type(value[key]) is str and pins.SHA_RE.fullmatch(value[key]) is not None, 'PROFILE_SHA')
    for key in ('keys', 'missing_required_keys'):
        require(type(value[key]) is list and len(value[key]) <= len(profile.KEYS) and
                all(type(item) is str and item in profile.KEYS for item in value[key]) and
                len(set(value[key])) == len(value[key]), 'PROFILE_KEY_NAMES')
    require(type(value['vendor_key_names']) is list and len(value['vendor_key_names']) <= 128 and
            all(type(k) is str and len(k) <= 128 and
                profile.re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) is not None and
                k.startswith(('MGC_', 'MGLS_', 'LM_', 'TESSENT', 'MENTOR'))
                for k in value['vendor_key_names']), 'PROFILE_VENDOR_NAMES')
    normalization = value['normalization']
    require(type(normalization) is dict and set(normalization) == set(value['keys']), 'PROFILE_NORMALIZATION_KEYS')
    for row in normalization.values():
        require(type(row) is dict and set(row) == {'empty_search_items_removed', 'trailing_slashes_removed', 'compatible'} and
                type(row['compatible']) is bool and all(type(row[k]) is int and 0 <= row[k] <= 16384
                    for k in ('empty_search_items_removed', 'trailing_slashes_removed')), 'PROFILE_NORMALIZATION_VALUE')
    require(not value['strict_compatible'] or (not value['missing_required_keys'] and
            value['vendor_root_present'] and value['license_present'] and 'PATH' in value['keys'] and
            all(row['compatible'] for row in normalization.values())), 'PROFILE_STRICT_CLAIM')


def collect(raw_e85, raw_e88, profile_source_bytes):
    started = time.monotonic()
    result = dict(schema=SCHEMA, capture_complete=False, error=None,
        remote_start_monotonic=started, remote_end_monotonic=None, boot_id=None,
        hostname=platform.node(), uid=os.getuid() if hasattr(os, 'getuid') else None,
        frozen_inputs=[], reports=[], runtime_profile=None, launcher=None,
        body_bytes_hashed=0, sampled_peak_rss_swap_bytes=0, explicit_filesystem_writes=0,
        atpg_launches=0, training_runs=0, execution_ready=False, training_release=False,
        qualification='CAPTURE_FACTS_ONLY_NOT_DATA_OR_RUNTIME_GATE',
        shell_module_side_effects_attested_absent=False)
    budget = domain = None
    try:
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and
                result['uid'] == 1047, 'FIXED_HOST_UID_PLATFORM')
        boot = direct.base._small('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        require(len(boot) == 36 and all(c in '0123456789abcdef-' for c in boot), 'BOOT_ID_FORMAT')
        result['boot_id'] = boot
        e85 = pins.observation(raw_e85, pins.E85_SHA256, pins.E85_SHA256, 'E85')
        trees = pins.validate_e85(e85)
        e88 = pins.observation(raw_e88, E88_SHA256, E88_SHA256, 'E88')
        require(e88['schema'] == 'e88-acquisition-semantics-probe-v1' and
                {row['circuit'] for row in e88['roots']} == set(pins.TOPS), 'E88_SHAPE')
        domain = direct.Descendants()
        budget = Budget(domain, started + 90)
        budget.tick()
        result['runtime_profile'] = _capture_profile(profile_source_bytes, domain, budget.end)
        budget.tick()
        launcher_pin = dict(bytes=e85['binary']['bytes'], sha256=pins.LAUNCHER_SHA256)
        result['launcher'] = _read_file(pins.LAUNCHER, budget, launcher_pin, launcher=True)
        result['frozen_inputs'].append(_read_file(pins.LIBRARY, budget,
            dict(bytes=e85['library']['bytes'], sha256=pins.LIBRARY_SHA256)))
        for circuit in ('aes_core', 'spi'):
            root = next(row for row in e88['roots'] if row['circuit'] == circuit)
            require(root['expected_common_count'] == pins.COUNTS[circuit], 'E88_COMMON_COUNT')
            common = pins.PHASE4 + '/' + circuit + '/03_fault_universe/common_' + circuit + '_m16_phase4_v2/'
            for name in ('manifest.json', 'canonical_fault_mapping.tsv', 'H_common_initial_faults.basic',
                         'M_common_initial_faults.basic', 'F_common_initial_faults.basic'):
                result['frozen_inputs'].append(_read_file(common + name, budget, root['files'][name]))
            for mode in ('H', 'M', 'F'):
                tree = trees[(circuit, mode)]
                result['frozen_inputs'].append(_tree(tree['root'], tree, budget))
            report_base = pins.PHASE4 + '/' + circuit + '/04_single_mode/H_' + circuit + '_H_full_phase4_v2/'
            for name in ('statistics.rpt', 'patterns.rpt', 'tester.stil'):
                result['reports'].append(_read_file(report_base + name, budget, report=True, stil=name == 'tester.stil'))
        budget.tick()
        result['capture_complete'] = True
    except Exception as exc:
        result['error'] = dict(type=type(exc).__name__, code=str(exc) if type(exc) is ValueError else 'READONLY_CAPTURE_FAILED')
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        if budget is not None:
            result['body_bytes_hashed'] = budget.bytes
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    if len(pins.canonical(result)) > MAX_RESPONSE:
        result.update(capture_complete=False, error=dict(type='ValueError', code='RESPONSE_BOUND'))
        result['reports'] = []
        result['runtime_profile'] = None
    return result
