"""Fixed owned-output readback only; offline review precedes one A read call.

No tool launch, retry, source mutation, environment capture or historical-report
access. Local transport imports are delayed; the frozen remote reader uses only
stdlib and the already pinned anchored-IO/E104 sampling bundle.
"""
import ast
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

ROOT = '/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1'
SIDECAR = ROOT + '.initial_intent.json'
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'
START = 2409047.850488485
END = 2459447.850488485
AUTH_SHA = '106c9d5c874b79a2400ca11b17c08708c285cfcdd8147c226af10d81a9c73e52'
E112_SHA = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
PRIOR_SHA = 'fe39d58b6d30379e268f7f77db084c0d7e942f719f118958ff38797cc2586dbd'
SCHEMA = 'pt-label-owned-failure-readback-e128-v1'
MAX_METADATA = 65536
MAX_LOG = 2 * 1048576
MAX_TOTAL = 5 * 1048576
MAX_RESPONSE = 8 * 1048576
JOURNAL = ROOT + '/journal/'
TOOL_LOG = ROOT + '/aes_core/runs/e116-aes_core/logs/F_aes_core:HF:h1:F.log'
STATISTICS = ROOT + '/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/statistics.rpt'
MTFI = ROOT + '/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/faults.mtfi'
MAX_MTFI = 8 * 1048576
EXPECTED_ROWS = 71216
PATHS = (SIDECAR, ROOT+'/code/common.tcl', ROOT+'/code/incremental.tcl') + tuple(
    JOURNAL+name for name in ('package_summary.json','initialization.json','selftest_intent.json',
        'selftest_observation.json','selftest_callback_bootstrap_metadata.json')) + tuple(
    JOURNAL+'selftest_callback_'+case+'_'+name for case in ('success','timeout','setsid_child')
    for name in ('observation.json','receipt.json','output.log')) + tuple(
    JOURNAL+'task_000_'+name for name in ('intent.json','preparation.json','spawn_identity.json',
        'observation.json','stdout.log','stdout_ack.json','reference.json','artifact_metadata.json','ack.json')) + tuple(
    JOURNAL+'task_001_'+name for name in ('intent.json','translation_observation.json','reference.json',
        'artifact_metadata.json','ack.json')) + tuple(
    JOURNAL+'task_002_'+name for name in ('intent.json','preparation.json','spawn_identity.json',
        'observation.json','stdout.log','stdout_ack.json')) + (STATISTICS,TOOL_LOG,MTFI)
LOGS = frozenset((JOURNAL+'task_000_stdout.log',JOURNAL+'task_002_stdout.log',TOOL_LOG))
REVIEW_KEYS = ('payload_sha256', 'controller_sha256', 'source_sha256',
               'authorization_sha256', 'prior_response_sha256', 'original_clock_sha256',
               'execution_review_sha256', 'execution_source_sha256', 'local_deadline_sha256')
LOCAL_END = datetime.datetime(2026, 10, 27, 16, 45, 37, 214284, tzinfo=datetime.timezone.utc)
EXECUTION_REVIEW = 'data/manifests/ranking_v6_e127_pre_review_20261027_r1.json'
EXECUTION_PAYLOAD_SHA = '283e866d817f69c434e3a2ff76f468dad3214f982641e18cd9232e9efba543da'
EXECUTION_REVIEW_SHA = '5658e8ee97fa9db33ccac0b90f3ddf57fbff49e9b77656092a8cfffc53591360'
EXECUTION_START_SHA = '4abf1bd232a425d966456e085cdf221ce70141fb531c66e2d8b9186c6d7c51ad'
EXECUTION_CLOCK_SHA = '8e557bbbc6d4742f40ad16641616b2e99156f79abc1083bb2248592170bf23d4'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


class MtfiInventory(object):
    """Strict complete stream inventory; unknown classes are never detections."""
    def __init__(self, expected_rows=EXPECTED_ROWS):
        from src.data import prospective_fault_translation_v2 as faults
        self.faults = faults
        self.expected = expected_rows
        self.pending, self.line_number = b'', 0
        self.header = self.footer = self.rows = 0
        self.counts, self.examples, self.unknown_examples = {}, {}, []

    def block(self, raw):
        require(type(raw) is bytes and 0 < len(raw) <= 65536, 'MTFI_STREAM_CHUNK')
        lines = (self.pending+raw).split(b'\n')
        self.pending = lines.pop()
        require(len(self.pending) <= 4095, 'MTFI_LINE_BOUND')
        for line in lines:
            require(len(line) <= 4095 and b'\r' not in line and b'\x00' not in line, 'MTFI_LINE_ENCODING_BOUND')
            self.line_number += 1
            text = line.decode('utf-8')+'\n'
            if self.header < len(self.faults.HEADER):
                require(text == self.faults.HEADER[self.header], 'MTFI_EXACT_HEADER')
                self.header += 1
            elif self.rows < self.expected:
                match = self.faults.FAULT_RE.fullmatch(text.rstrip('\n'))
                require(match is not None, 'MTFI_STRICT_FAULT_ROW')
                stuck, label, location = match.groups()
                self.faults.valid_path(location, 'MTFI_LOCATION')
                require(len(label) <= 128 and (label in self.counts or len(self.counts) < 64), 'MTFI_CLASS_BOUND')
                self.rows += 1
                self.counts[label] = self.counts.get(label,0)+1
                if label not in self.examples:
                    sample = dict(fault_class=label, known_to_frozen_parser=self.faults.valid_class(label),
                        line_number=self.line_number, line_bytes=len(line)+1,
                        line_base64=base64.b64encode(line+b'\n').decode('ascii'))
                    self.examples[label] = sample
                    if not sample['known_to_frozen_parser'] and len(self.unknown_examples) < 8:
                        self.unknown_examples.append(dict(sample))
            else:
                require(self.footer < len(self.faults.FOOTER) and text == self.faults.FOOTER[self.footer],
                        'MTFI_EXACT_FOOTER')
                self.footer += 1

    def finish(self):
        require(not self.pending and self.header == len(self.faults.HEADER) and
            self.rows == self.expected and self.footer == len(self.faults.FOOTER), 'MTFI_COMPLETE_ENVELOPE_ROW_COUNT')
        return dict(row_count=self.rows, expected_row_count=self.expected, class_counts=dict(self.counts),
            unknown_labels=sorted(label for label in self.counts if not self.faults.valid_class(label)),
            class_examples=[self.examples[label] for label in sorted(self.examples)],
            unknown_examples=self.unknown_examples, full_envelope_verified=True,
            strict_fault_row_syntax_verified=True, detected_count_inferred=False,
            namespace_or_unique_fault_set_verified=False)


def collect(remote_start=None):
    from src.data import prospective_acceptance_materializer_v1 as io
    from src.data import direct_tessent_acceptance_e104 as direct
    started = time.monotonic() if remote_start is None else remote_start
    result = dict(schema=SCHEMA, capture_complete=False, error=None, hostname=platform.node(),
        uid=os.getuid() if hasattr(os, 'getuid') else None, boot_id=None,
        remote_start_monotonic=started, remote_end_monotonic=None,
        original_start_monotonic=START, original_deadline_monotonic=END,
        clock_must_not_be_reset=True, files=[], body_bytes_hashed=0, mtfi_bytes_hashed=0,
        sampled_peak_rss_swap_bytes=0, explicit_filesystem_writes=0, child_launches=0,
        environment_reads=0, atpg_launches=0, training_runs=0, additional_historical_reports=0,
        execution_ready=False, training_release=False, sampling_is_hard_memory_guarantee=False)
    domain, deadline, total, next_sample, mtfi_total = None, None, [0], [0], [0]
    def tick():
        now = time.monotonic()
        require(now < deadline, 'READBACK_DEADLINE')
        if now >= next_sample[0]:
            require(not domain.sample(), 'UNEXPECTED_CHILDREN')
            require(domain.peak <= 536870912, 'SAMPLED_MEMORY_STOP')
            next_sample[0] = time.monotonic() + .25
        require(time.monotonic() < deadline, 'READBACK_DEADLINE')
    def read(path):
        tick()
        parent, name = path.rsplit('/', 1)
        directory = io._directory(parent)
        fd = None
        try:
            parent_identity = (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
            try:
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                require(path == TOOL_LOG, 'REQUIRED_OWNED_FILE_MISSING')
                return dict(path=path, status='MISSING')
            cap = MAX_MTFI if path == MTFI else MAX_LOG if path in LOGS else MAX_METADATA
            require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 1047,
                    'SINGLE_LINK_OWNED_REGULAR_REQUIRED')
            require(0 <= named.st_size <= cap and (path == MTFI or total[0] + named.st_size <= MAX_TOTAL),
                    'READBACK_BODY_BOUND')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(fd)
            require(io._identity(named) == io._identity(before) and before.st_uid == 1047, 'OWNED_FILE_CHANGED')
            remaining, blocks, digest = named.st_size, [], hashlib.sha256()
            inventory = MtfiInventory(EXPECTED_ROWS) if path == MTFI else None
            while remaining:
                tick()
                raw = os.read(fd, min(65536, remaining))
                require(bool(raw), 'OWNED_FILE_SHORT_READ')
                remaining -= len(raw)
                if inventory is None:
                    total[0] += len(raw)
                else:
                    mtfi_total[0] += len(raw)
                    require(mtfi_total[0] <= MAX_MTFI, 'MTFI_TOTAL_BOUND')
                digest.update(raw)
                if inventory is None:
                    blocks.append(raw)
                else:
                    inventory.block(raw)
            require(not os.read(fd, 1), 'OWNED_FILE_GREW')
            tick()
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(io._identity(before) == io._identity(os.fstat(fd)) == io._identity(after) and
                    after.st_uid == 1047, 'OWNED_FILE_CHANGED')
            fresh = io._directory(parent)
            try:
                info = os.fstat(fresh)
                require((info.st_dev, info.st_ino) == parent_identity, 'OWNED_PARENT_REPLACED')
            finally:
                os.close(fresh)
            if inventory is not None:
                return dict(inventory.finish(), path=path, status='MTFI_INVENTORY', bytes=before.st_size,
                            sha256=digest.hexdigest(), whole_file_hashed=True)
            return dict(path=path, status='READ', bytes=before.st_size, sha256=digest.hexdigest(),
                        body_base64=base64.b64encode(b''.join(blocks)).decode('ascii'), whole_file_hashed=True)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)
    try:
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and result['uid'] == 1047,
                'FIXED_HOST_UID_PLATFORM')
        require(type(started) in (int, float) and math.isfinite(started) and START <= started < END,
                'ORIGINAL_CLOCK_REQUIRED')
        deadline = min(END, started + 30)
        boot = direct.base._small('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        result['boot_id'] = boot
        require(boot == BOOT, 'ORIGINAL_BOOT_REQUIRED')
        domain = direct.Descendants()
        tick()
        for path in PATHS:
            result['files'].append(read(path))
        tick()
        result['capture_complete'] = True
    except BaseException as exc:
        result['error'] = dict(type=type(exc).__name__, code=str(exc) if type(exc) is ValueError else 'OWNED_READBACK_FAILED')
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        result['body_bytes_hashed'] = total[0]
        result['mtfi_bytes_hashed'] = mtfi_total[0]
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(result)) <= MAX_RESPONSE, 'READBACK_RESPONSE_BOUND')
    return result


def _local_remaining():
    from scripts import acceptance_transport_e98 as control
    raw = (control.STAGING/'v6_e127_pt_label_generation_20261027_r1/start.json').read_bytes()
    require(sha(raw) == EXECUTION_START_SHA, 'ACTUAL_FIRST_CALL_INTENT_CHANGED')
    encoded = _json(raw)['local_utc_deadline']
    end = datetime.datetime.strptime(encoded, '%Y-%m-%dT%H:%M:%S.%f%z')
    require(end == LOCAL_END, 'ACTUAL_LOCAL_DEADLINE_CHANGED')
    value = (end - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    require(value > 1, 'ORIGINAL_LOCAL_DEADLINE_EXPIRED')
    return value


def _derived_paths(compiled, repo, completed_tasks):
    """Pure isolated source loading through E108 only; no controller or worker run."""
    import types
    saved = {name:module for name,module in sys.modules.items() if name == 'src' or name.startswith('src.')}
    created = []
    try:
        for name in ('src','src.data'):
            module = types.ModuleType(name)
            module.__path__ = []
            sys.modules[name] = module
            created.append(name)
            if name == 'src.data':
                sys.modules['src'].data = module
        recipe = None
        for row in compiled['sources']:
            if row['name'] == 'prospective_generation_context_e124':
                continue  # No execution context or synthetic runtime permission is needed to compile E108.
            name = 'src.data.'+row['name']
            raw = base64.b64decode(row['body'],validate=True)
            require(sha(raw) == row['sha256'], 'DERIVED_SOURCE_BODY_SHA')
            module = types.ModuleType(name)
            module.__package__ = 'src.data'
            sys.modules[name] = module
            setattr(sys.modules['src.data'],row['name'],module)
            created.append(name)
            exec(compile(raw,'<e128-offline-'+row['name']+'>','exec'),module.__dict__)
            if row['name'] == 'prospective_generation_recipe_e108':
                recipe = module
                break
        require(recipe is not None, 'REVIEWED_E108_SOURCE_REQUIRED')
        e88 = _json((repo/'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json').read_bytes())
        common_pin = next(root for root in e88['roots'] if root['circuit'] == 'aes_core')['files']['manifest.json']['sha256']
        plan = recipe.pilot.build_plan()
        freeze = recipe.requests.freeze_acquisition(plan,'aes_core',recipe.identities.COUNTS['aes_core'],common_pin)
        binder = recipe.bindings.Binder(plan,'aes_core',freeze,'e116-aes_core')
        binding = binder.bind_next('aes_core:HF:h1:H')
        node = plan['phases'][0]['tasks'][2]
        refs = {row['task_uid']:row for row in completed_tasks}
        h_uid, t_uid = 'aes_core:HF:h1:H', 'aes_core:HF:h1:F:translate'
        require(set(refs) == {h_uid,t_uid} and node['task_uid'] == 'aes_core:HF:h1:F', 'EXACT_COMPLETED_REFERENCE_ROSTER')
        # Offline path projection only: actual summary reference hashes are retained;
        # unavailable receipt hashes are explicit placeholder claims, never runtime ACKs.
        binding.update(slot=2,target_mode='F',task_uid=node['task_uid'],control=node['control'],
            previous_receipt_sha256='0'*64,parent_task_uid=h_uid,parent_result_sha256=refs[h_uid]['output_sha256'],
            parent_receipt_sha256='0'*64,translation_task_uid=t_uid,translation_result_sha256=refs[t_uid]['output_sha256'],
            translation_receipt_sha256='0'*64)
        binding['request'].update(attempt_uid=node['task_uid'],stage='F',stage_index=node['stage_index'],
            control=node['control'],parent_attempt_uid=h_uid,parent_result_sha256=refs[h_uid]['output_sha256'])
        binding['recipe'] = recipe.stage.compile_stage(freeze,binding['request'])
        binding['binding_sha256'] = recipe.sha(recipe.canonical({k:v for k,v in binding.items() if k != 'binding_sha256'}))
        templates = repo/'src/data/templates'
        sources = recipe.freeze_sources((templates/'e108_common_base.tcl').read_bytes(),
                                         (templates/'e108_incremental_base.tcl').read_bytes())
        envelope = recipe.compile_execution(freeze,binding,sources)
        return envelope['output_paths']['statistics'],envelope['argv'][5],envelope['output_paths']['mtfi']
    finally:
        for name in created:
            sys.modules.pop(name,None)
        sys.modules.update(saved)


def _execution_proof(repo, control):
    require(sha((repo/'contracts/prospective_pt_label_repair_authorization_e127_20261027.json').read_bytes()) == AUTH_SHA,
            'ACTUAL_NEW_AUTHORITY_CHANGED')
    phase = control.STAGING/'v6_e127_pt_label_generation_20261027_r1'
    raw = (phase/'stdout.json').read_bytes()
    require(sha(raw) == PRIOR_SHA, 'ACTUAL_FAILED_WORKER_RESPONSE_CHANGED')
    worker = _json(raw)
    summary = worker.get('summary',{})
    require(worker.get('status') == 'STOPPED_FIRST_FAILURE' and
        summary.get('counts') == dict(tessent_debited=2,translation_debited=1,committed_tasks=2,
            selftest_cases_reserved=3,selftest_cases_accepted=3) and
        summary.get('failed_task_uid') == 'aes_core:HF:h1:F' and
        summary.get('error',{}).get('code') == 'UNKNOWN_SOURCE_CLASS', 'EXACT_FIRST_F_FAILURE_PROOF')
    clock_raw = (phase/'package_clock.json').read_bytes()
    expected_clock = dict(authorization_sha256=AUTH_SHA,boot_id=BOOT,cohort_snapshot_is_clock=False,
        deadline_monotonic=END,new_authorized_package_clock=True,root=ROOT,start_monotonic=START)
    require(sha(clock_raw) == EXECUTION_CLOCK_SHA and _json(clock_raw) == expected_clock and
            worker.get('clock') == expected_clock, 'ACTUAL_E127_CLOCK_CHANGED')
    start_raw = (phase/'start.json').read_bytes()
    require(sha(start_raw) == EXECUTION_START_SHA and
        _json(start_raw)['local_utc_deadline'] == LOCAL_END.isoformat(), 'ACTUAL_LOCAL_DEADLINE_CHANGED')
    review_raw = (repo/EXECUTION_REVIEW).read_bytes()
    require(sha(review_raw) == EXECUTION_REVIEW_SHA, 'ACTUAL_EXECUTION_REVIEW_CHANGED')
    reviewed = _json(review_raw)
    require(reviewed.get('status') == 'PASS' and reviewed['reviewed']['payload_sha256'] == EXECUTION_PAYLOAD_SHA,
            'ACTUAL_EXECUTION_REVIEW_REQUIRED')
    for name, relative in (
        ('e88','data/manifests/ranking_v6_e88_input_observation_20261023_r1.json'),
        ('common_tcl','src/data/templates/e108_common_base.tcl'),
        ('incremental_tcl','src/data/templates/e108_incremental_base.tcl')):
        require(sha((repo/relative).read_bytes()) == reviewed['reviewed']['input_sha256'][name],
                'ACTUAL_DERIVED_PATH_INPUT_CHANGED')
    from src.data import prospective_pt_label_bundle_e127 as bundle
    compiled = bundle.build_sources()
    source_sha = {row['name']:row['sha256'] for row in compiled['sources']}
    require(source_sha == reviewed['reviewed']['source_sha256'] and
            compiled['manifest']['manifest_sha256'] == reviewed['reviewed']['bundle_manifest_sha256'],
            'ACTUAL_DERIVED_EXECUTION_SOURCES_CHANGED')
    require(_derived_paths(compiled,repo,summary['completed_tasks']) == (STATISTICS,TOOL_LOG,MTFI),
            'EXACT_DERIVED_FAILED_F_PATHS')
    return dict(clock_sha256=sha(clock_raw),review_sha256=sha(review_raw),source_sha256=source_sha,
                local_deadline_sha256=sha(start_raw))


def prepare():
    from scripts import acceptance_transport_e98 as control
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    proof = _execution_proof(repo, control)
    sources = []
    for name, pin in list(PINS) + [('e128_failure_readback', None)]:
        path = Path(__file__) if pin is None else repo / ('src/data/' + name + '.py')
        source = path.read_bytes()
        digest = sha(source)
        require(pin is None or digest == pin, 'PINNED_LEGACY_SOURCE_CHANGED')
        ast.parse(source.decode('utf-8'), feature_version=(3, 6))
        sources.append(dict(name=name, sha256=digest, body=base64.b64encode(source).decode('ascii')))
    package = json.dumps(dict(sources=sources), separators=(',', ':'))
    payload = ('import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads(' + repr(package) + ')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' assert hashlib.sha256(raw).hexdigest()==row["sha256"]\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<frozen-"+row["name"]+">","exec"),m.__dict__)\n'
        ' m.__source_sha256__=row["sha256"]\n'
        'result=sys.modules["src.data.e128_failure_readback"].collect(bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    require(len(payload) <= 1048576, 'READBACK_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'), feature_version=(3, 6))
    return dict(payload=payload, payload_sha256=sha(payload), controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={row['name']: row['sha256'] for row in sources}, authorization_sha256=AUTH_SHA,
        prior_response_sha256=PRIOR_SHA, original_clock_sha256=proof['clock_sha256'],
        execution_review_sha256=proof['review_sha256'], execution_source_sha256=proof['source_sha256'],
        local_deadline_sha256=proof['local_deadline_sha256'])


def _validate_inventory(row):
    from src.data import prospective_fault_translation_v2 as faults
    fields = {'path','status','bytes','sha256','whole_file_hashed','row_count','expected_row_count',
        'class_counts','unknown_labels','class_examples','unknown_examples','full_envelope_verified',
        'strict_fault_row_syntax_verified','detected_count_inferred','namespace_or_unique_fault_set_verified'}
    require(set(row) == fields and row['path'] == MTFI and row['status'] == 'MTFI_INVENTORY' and
        type(row['bytes']) is int and 0 < row['bytes'] <= MAX_MTFI and
        type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None and
        all(row[k] is True for k in ('whole_file_hashed','full_envelope_verified','strict_fault_row_syntax_verified')) and
        row['detected_count_inferred'] is False and row['namespace_or_unique_fault_set_verified'] is False and
        type(row['row_count']) is int and type(row['expected_row_count']) is int and
        row['row_count'] == row['expected_row_count'] == EXPECTED_ROWS, 'MTFI_COMPLETE_INVENTORY_FIELDS')
    counts = row['class_counts']
    require(type(counts) is dict and 1 <= len(counts) <= 64 and
        all(type(k) is str and len(k) <= 128 and re.fullmatch('[A-Z0-9_.]+',k) is not None and
            type(v) is int and 0 < v <= EXPECTED_ROWS for k,v in counts.items()) and
        sum(counts.values()) == EXPECTED_ROWS, 'MTFI_CLASS_COUNTS')
    unknown = sorted(label for label in counts if not faults.valid_class(label))
    require(row['unknown_labels'] == unknown, 'MTFI_EXACT_UNKNOWN_LABELS')
    examples = row['class_examples']
    require(type(examples) is list and len(examples) == len(counts), 'MTFI_CLASS_EXAMPLE_COUNT')
    seen, line_numbers = {}, set()
    for example in examples:
        require(type(example) is dict and set(example) == {'fault_class','known_to_frozen_parser','line_number','line_bytes','line_base64'},
                'MTFI_EXAMPLE_FIELDS')
        label = example['fault_class']
        require(label in counts and label not in seen and
            example['known_to_frozen_parser'] is faults.valid_class(label) and
            type(example['line_number']) is int and len(faults.HEADER) < example['line_number'] <= len(faults.HEADER)+EXPECTED_ROWS and
            example['line_number'] not in line_numbers and
            type(example['line_bytes']) is int and 0 < example['line_bytes'] <= 4096, 'MTFI_EXAMPLE_CONTEXT')
        raw = base64.b64decode(example['line_base64'],validate=True)
        require(len(raw) == example['line_bytes'] and raw.endswith(b'\n') and b'\n' not in raw[:-1] and
                b'\r' not in raw and b'\x00' not in raw,
                'MTFI_EXAMPLE_BYTES')
        match = faults.FAULT_RE.fullmatch(raw.decode('utf-8').rstrip('\n'))
        require(match is not None and match.group(2) == label, 'MTFI_EXAMPLE_STRICT_CLASS')
        faults.valid_path(match.group(3),'MTFI_EXAMPLE_LOCATION')
        seen[label] = example
        line_numbers.add(example['line_number'])
    extra = row['unknown_examples']
    require(type(extra) is list and len(extra) == min(8,len(unknown)) and
        all(type(sample) is dict and sample.get('fault_class') in unknown and sample == seen[sample['fault_class']] for sample in extra) and
        len({sample['fault_class'] for sample in extra}) == len(extra), 'MTFI_BOUNDED_UNKNOWN_EXAMPLES')


def validate_response(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE, 'READBACK_RESPONSE_BOUND')
    value = _json(raw)
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('hostname') == 'bupt-vncs2' and
            type(value.get('uid')) is int and value['uid'] == 1047 and value.get('boot_id') == BOOT and
            value.get('original_start_monotonic') == START and value.get('original_deadline_monotonic') == END and
            value.get('clock_must_not_be_reset') is True, 'READBACK_IDENTITY_CLOCK')
    for key in ('execution_ready', 'training_release', 'sampling_is_hard_memory_guarantee'):
        require(value.get(key) is False, 'NO_RELEASE_OR_HARD_MEMORY_CLAIM')
    for key in ('explicit_filesystem_writes', 'child_launches', 'environment_reads', 'atpg_launches',
                'training_runs', 'additional_historical_reports'):
        require(type(value.get(key)) is int and value[key] == 0, 'READONLY_OWNED_OUTPUTS_ONLY')
    start, end = value.get('remote_start_monotonic'), value.get('remote_end_monotonic')
    require(all(type(t) in (int, float) and math.isfinite(t) for t in (start, end)) and
            START <= start <= end < END and end - start < 30, 'READBACK_CLOCK_INTERVAL')
    rows = value.get('files')
    require(type(rows) is list and len(rows) <= len(PATHS), 'READBACK_FILE_COUNT')
    total, mtfi_total = 0, 0
    for index, row in enumerate(rows):
        require(type(row) is dict and row.get('path') == PATHS[index], 'ORDERED_FIXED_FIRST_FAILURE_PREFIX')
        if row['path'] == MTFI:
            _validate_inventory(row)
            mtfi_total = row['bytes']
            continue
        if row.get('status') == 'MISSING':
            require(set(row) == {'path', 'status'} and row['path'] == TOOL_LOG, 'ONLY_OPTIONAL_TOOL_LOG_MAY_BE_MISSING')
            continue
        require(set(row) == {'path', 'status', 'bytes', 'sha256', 'body_base64', 'whole_file_hashed'} and
                row['status'] == 'READ' and row['whole_file_hashed'] is True and type(row['bytes']) is int and
                0 <= row['bytes'] <= (MAX_LOG if row['path'] in LOGS else MAX_METADATA), 'READBACK_FILE_BOUND')
        body = base64.b64decode(row['body_base64'], validate=True)
        require(len(body) == row['bytes'] and sha(body) == row['sha256'], 'READBACK_FILE_BYTES_SHA')
        total += len(body)
    require(type(value.get('body_bytes_hashed')) is int and total <= value['body_bytes_hashed'] <= MAX_TOTAL and
            type(value.get('mtfi_bytes_hashed')) is int and mtfi_total <= value['mtfi_bytes_hashed'] <= MAX_MTFI and
            type(value.get('sampled_peak_rss_swap_bytes')) is int and
            0 <= value['sampled_peak_rss_swap_bytes'] <= 536870912, 'READBACK_RESOURCE_RECEIPTS')
    require(type(value.get('capture_complete')) is bool, 'READBACK_CAPTURE_STATUS')
    if value['capture_complete']:
        require(len(rows) == len(PATHS) and value.get('error') is None and total == value['body_bytes_hashed'] and
                mtfi_total == value['mtfi_bytes_hashed'],
                'READBACK_COMPLETE_SCOPE')
    else:
        require(type(value.get('error')) is dict, 'READBACK_FIRST_FAILURE_REQUIRED')
    return value


def execute(review_path, reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    _local_remaining()
    plan = prepare()
    review = _json(Path(review_path).read_bytes())
    expected = {key: plan[key] for key in REVIEW_KEYS}
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and
            reviewed_payload_sha == plan['payload_sha256'], 'INDEPENDENT_EXACT_REVIEW_REQUIRED')
    _local_remaining()
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING / 'v6_e128_failure_readback_20261027_r1'
    phase.mkdir(exist_ok=False)
    helper.TIMEOUT = min(40, max(1, int(_local_remaining())))
    control.write_new(phase / 'start.json', control.encode(dict(expected, host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, owned_outputs_only=True, new_historical_reports=0,
        original_deadline_monotonic=END, original_boot_id=BOOT, response_cap=MAX_RESPONSE)))
    try:
        observed = helper.transport(helper.command('A'), plan['payload'], MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(phase / 'transport.json', control.encode(dict(error_type=type(exc).__name__,
            status='TRANSPORT_RAISED_NO_RETRY')))
        raise
    control.write_new(phase / 'stdout.json', observed['stdout'])
    control.write_new(phase / 'stderr.log', observed['stderr'])
    receipt = {k: v for k, v in observed.items() if k not in ('stdout', 'stderr')}
    for key in ('stdout', 'stderr'):
        receipt[key + '_bytes'], receipt[key + '_sha256'] = len(observed[key]), sha(observed[key])
    control.write_new(phase / 'transport.json', control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in
        ('timeout', 'overflow', 'write_failed', 'threads_incomplete')), 'TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    result = validate_response(observed['stdout'])
    control.write_new(phase / 'validated.json', control.encode(dict(capture_complete=result['capture_complete'],
        files=len(result['files']), execution_ready=False, training_release=False)))
    require(result['capture_complete'], 'OWNED_READBACK_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(phase), files=len(result['files']), capture_complete=True,
                execution_ready=False, training_release=False)


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({k: v for k, v in prepare().items() if k != 'payload'}, sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        print(json.dumps(execute(args[1], args[2]), sort_keys=True))
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
