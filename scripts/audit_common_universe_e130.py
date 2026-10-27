"""One bounded audit of current owned common inputs and H/F outputs; no tool run.

The larger read budget covers existing owned copies, not historical reports or
a renewed acquisition grant. Aggregate statistics never replace explicit union.
"""
import ast
import base64
from collections import Counter
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
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'
START, END = 2409047.850488485, 2459447.850488485
AUTH_SHA = '106c9d5c874b79a2400ca11b17c08708c285cfcdd8147c226af10d81a9c73e52'
E128_SHA = 'd70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
E88_SHA = 'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8'
F_MTFI_SHA = '55f6850eee753e3aff90b7b2199a366cb635a7b6a00adae84b1f20fc049ded5f'
F_STATS_SHA = '629b433cd87ad7e471834decf9cce0f47735268da7028215b0eed68f8c60fff4'
PURE = (('prospective_fault_translation_e129','f659ca52bc6c48645736162223d1f6a931c343d4dd6cafac690aaeff90a2c681'),
        ('prospective_report_dialect_e115','102ed449c9f12f46edebd5ab31bb99b8e14c3f465b0ac70b5121606ad3617b0d'),
        ('prospective_report_dialect_e126','12fdb3e3cb7b52c32465f461fa63a6598f6bac555669d63540ac18e0bd3174a0'))
COMMON_COUNT = 71216
MAX_FILE, MAX_METADATA, MAX_TOTAL, MAX_RESPONSE = 8*1048576, 65536, 40*1048576, 1048576
COMMON = ROOT+'/aes_core/03_fault_universe/common_frozen/'
H_DIR = ROOT+'/aes_core/runs/e116-aes_core/attempts/H_aes_core:HF:h1:H/'
F_DIR = ROOT+'/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/'
PATHS = dict(manifest=COMMON+'manifest.json',mapping=COMMON+'canonical_fault_mapping.tsv',
    H_basic=COMMON+'H_common_initial_faults.basic',F_basic=COMMON+'F_common_initial_faults.basic',
    H_mtfi=H_DIR+'faults.mtfi',F_mtfi=F_DIR+'faults.mtfi',F_statistics=F_DIR+'statistics.rpt',
    F_pre_statistics=F_DIR+'pre_atpg_statistics.rpt',F_faults_report=F_DIR+'faults.rpt')
ORDER = ('manifest','mapping','H_basic','F_basic','H_mtfi','F_mtfi','F_statistics','F_pre_statistics','F_faults_report')
SCHEMA = 'owned-common-universe-audit-e130-v1'
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','authorization_sha256',
    'e128_response_sha256','execution_review_sha256','execution_source_sha256','original_clock_sha256',
    'local_deadline_sha256','audit_plan_sha256','e88_sha256')


def require(ok,code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _json(raw):
    def pairs(items):
        value = {}
        for k,v in items:
            require(k not in value,'DUPLICATE_JSON_KEY')
            value[k] = v
        return value
    return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def _inventory(raw, faults):
    counts = Counter()
    for line in faults._lines(raw,'MTFI_ENCODING_OR_LINE_ENDINGS')[len(faults.HEADER):-len(faults.FOOTER)]:
        match = faults.FAULT_RE.fullmatch(line.rstrip('\n'))
        require(match is not None,'STRICT_NATIVE_ROW')
        counts[match.group(2)] += 1
    require(len(counts) <= 64,'CLASS_INVENTORY_BOUND')
    return dict(counts)


def audit_bodies(bodies,count,mapping_sha,h_statistics,minimum_pre_detected,tick):
    """Pure supplied-body checks; caller must perform pinned physical reads first."""
    from src.data import prospective_fault_translation_v2 as v2
    from src.data import prospective_fault_translation_e129 as faults
    from src.data import prospective_report_dialect_e126 as reports
    tick()
    manifest = _json(bodies['manifest'])
    require(manifest.get('schema') == 'multimode_common_fault_universe_v1' and
        manifest.get('fault_model') == 'stuck-at' and manifest.get('common_fault_count') == count and
        manifest.get('mapping',{}).get('sha256') == mapping_sha == sha(bodies['mapping']), 'FROZEN_MANIFEST_AND_MAPPING')
    offset = manifest.get('f_flat_instance_offset')
    require(type(offset) is int and -2048 <= offset <= 2048,'F_OFFSET')
    lookup,h_keys = faults.mapping_lookup(bodies['mapping'],count,offset,'F','H')
    tick()
    h_basic = faults.parse_target_basic(bodies['H_basic'],count,h_keys)
    tick()
    f_basic = faults.parse_target_basic(bodies['F_basic'],count,set(lookup))
    tick()
    h_rows = v2.parse_source_mtfi(bodies['H_mtfi'],count,h_keys)
    tick()
    h_checked = faults.parse_source_mtfi(bodies['H_mtfi'],count,h_keys)
    require(h_rows == h_checked,'H_FROZEN_V2_AND_E129_DISAGREE')
    tick()
    f_rows = faults.parse_source_mtfi(bodies['F_mtfi'],count,set(lookup))
    tick()
    h_set = {key for key,label in h_rows}
    f_set = {lookup[key] for key,label in f_rows}
    union = h_set | f_set
    h_classes,f_classes = _inventory(bodies['H_mtfi'],faults),_inventory(bodies['F_mtfi'],faults)
    tick()
    stats = reports.parse_statistics(bodies['F_statistics'],count)
    tick()
    before = reports.parse_statistics(bodies['F_pre_statistics'],count,patterns_required=False)
    tick()
    native_top = Counter()
    for label,value in f_classes.items():
        if label == 'EQ':
            continue
        top = 'DI' if label != 'DS' and faults.detected(label) else label.split('.',1)[0]
        native_top[top] += value
    delta = {key:stats['classes'].get(key,0)-native_top.get(key,0)
             for key in sorted(set(stats['classes']) | set(native_top)) if key != 'FU'}
    eq = f_classes.get('EQ',0)
    h_native_top = Counter()
    for label,value in h_classes.items():
        if label != 'EQ':
            h_native_top['DI' if label != 'DS' and faults.detected(label) else label.split('.',1)[0]] += value
    h_delta = {key:h_statistics['classes'].get(key,0)-h_native_top.get(key,0)
        for key in sorted(set(h_statistics['classes']) | set(h_native_top)) if key != 'FU'}
    union_count = len(union)
    return dict(common_count=count,namespace_keyset_verified=True,
        H_v2_source_parser_passed=True,H_e129_source_parser_passed=True,F_e129_source_parser_passed=True,
        H_class_counts=h_classes,F_class_counts=f_classes,unknown_classes=[],
        H_basic_full_keyset_verified=True,F_basic_full_keyset_verified=True,
        H_basic_explicit_detected=len(h_basic),F_basic_explicit_detected=len(f_basic),
        H_explicit_detected=len(h_set),F_explicit_detected=len(f_set),
        H_F_explicit_intersection=len(h_set & f_set),H_F_explicit_union=union_count,
        d95_integer_threshold=(95*count+99)//100,explicit_union_meets_d95_math=100*union_count >= 95*count,
        F_statistics=stats,F_pre_statistics=before,H_statistics_from_frozen_reference=h_statistics,
        translated_explicit_minimum_pre_detected=minimum_pre_detected,
        H_statistics_source='FROZEN_REFERENCE_METADATA_NOT_REREAD_H_STATISTICS',
        H_reported_DS_DI=h_statistics['detected_common_faults'],F_reported_DS_DI=stats['detected_common_faults'],
        native_explicit_top_class_counts=dict(native_top),statistics_minus_native_explicit_top_class_delta=delta,
        expanded_statistics_delta_sum=sum(delta.values()),F_EQ_rows=eq,
        H_native_explicit_top_class_counts=dict(h_native_top),H_statistics_minus_native_explicit_top_class_delta=h_delta,
        H_expanded_statistics_delta_sum=sum(h_delta.values()),H_EQ_rows=h_classes.get('EQ',0),
        necessary_conditions=dict(expanded_class_deltas_nonnegative=all(value >= 0 for value in delta.values()),
            expanded_delta_sum_equals_EQ_rows=sum(delta.values()) == eq,
            H_frozen_metadata_expanded_delta_sum_equals_EQ_rows=sum(h_delta.values()) == h_classes.get('EQ',0),
            pre_reported_DS_DI_at_least_translated_explicit_minimum=before['detected_common_faults'] >= minimum_pre_detected),
        eq_adjacency_detection_inferred=False,aggregate_counts_replace_explicit_union_contract=False,
        coverage_semantics_proven=False,frozen_contract_d95_pass=False,training_release=False)


def read_file(path,cap,tick,total,expected=None,keep=True):
    from src.data import prospective_acceptance_materializer_v1 as io
    require(path in PATHS.values() and 0 < cap <= MAX_FILE,'FIXED_AUDIT_PATH_BOUND')
    tick()
    parent,name = path.rsplit('/',1)
    parent_fd,fd = io._directory(parent),None
    try:
        parent_identity = io._identity(os.fstat(parent_fd))
        named = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 1047,
                'SINGLE_LINK_OWNED_REGULAR_REQUIRED')
        require(0 < named.st_size <= cap and total[0]+named.st_size <= MAX_TOTAL,'AUDIT_TOTAL_OR_FILE_BOUND')
        require(expected is None or named.st_size == expected['bytes'],'PINNED_SIZE_CHANGED')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        opened = os.fstat(fd)
        require(io._identity(named) == io._identity(opened) and opened.st_uid == 1047,'AUDIT_SOURCE_CHANGED')
        digest,parts,prefix,remaining = hashlib.sha256(),[],bytearray(),named.st_size
        while remaining:
            tick()
            raw = os.read(fd,min(65536,remaining))
            require(bool(raw),'AUDIT_SHORT_READ')
            remaining -= len(raw)
            total[0] += len(raw)
            digest.update(raw)
            if keep:
                parts.append(raw)
            else:
                prefix.extend(raw[:max(0,32768-len(prefix))])
        require(not os.read(fd,1),'AUDIT_FILE_GREW')
        tick()
        opened_after = os.fstat(fd)
        named_after = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        require(io._identity(named) == io._identity(opened_after) == io._identity(named_after) and
            opened_after.st_uid == named_after.st_uid == 1047, 'AUDIT_SOURCE_CHANGED')
        fresh = io._directory(parent)
        try:
            require(io._identity(os.fstat(fresh)) == parent_identity,'AUDIT_PARENT_CHANGED')
        finally:
            os.close(fresh)
        receipt = dict(path=path,bytes=named.st_size,sha256=digest.hexdigest(),whole_file_hashed=True,
            matched_expected_pin=expected is not None,expected_sha256=expected['sha256'] if expected is not None else None)
        require(expected is None or (receipt['bytes'],receipt['sha256']) == (expected['bytes'],expected['sha256']),
                'PINNED_SOURCE_SHA_CHANGED')
        if not keep:
            receipt.update(prefix_bytes=len(prefix),prefix_base64=base64.b64encode(bytes(prefix)).decode('ascii'),
                           excerpt_is_not_complete_report=len(prefix) != named.st_size)
        return b''.join(parts) if keep else None,receipt
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def collect(plan,remote_start=None):
    from src.data import direct_tessent_acceptance_e104 as direct
    started = time.monotonic() if remote_start is None else remote_start
    result = dict(schema=SCHEMA,capture_complete=False,error=None,hostname=platform.node(),
        uid=os.getuid() if hasattr(os,'getuid') else None,boot_id=None,original_start_monotonic=START,
        original_deadline_monotonic=END,remote_start_monotonic=started,remote_end_monotonic=None,
        clock_must_not_be_reset=True,files=[],metrics=None,body_bytes_hashed=0,sampled_peak_rss_swap_bytes=0,
        explicit_filesystem_writes=0,child_launches=0,environment_reads=0,atpg_launches=0,
        additional_historical_reports=0,training_runs=0,training_release=False,execution_ready=False,
        coverage_semantics_proven=False,frozen_contract_d95_pass=False,sampling_is_hard_memory_guarantee=False)
    domain,total,next_sample = None,[0],[0]
    deadline = min(END,started+30)
    def tick(force=False):
        require(time.monotonic() < deadline,'AUDIT_DEADLINE')
        if force or time.monotonic() >= next_sample[0]:
            require(not domain.sample() and domain.peak <= 536870912,'CHILD_OR_MEMORY_STOP')
            next_sample[0] = time.monotonic()+.25
        require(time.monotonic() < deadline,'AUDIT_DEADLINE')
    try:
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and result['uid'] == 1047,
                'FIXED_HOST_UID_PLATFORM')
        require(type(started) in (int,float) and math.isfinite(started) and START <= started < END,'ACTUAL_E127_CLOCK')
        result['boot_id'] = direct.base._small('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        require(result['boot_id'] == BOOT,'ACTUAL_E127_BOOT')
        require(set(plan['files']) == set(ORDER) and plan['common_count'] == COMMON_COUNT and
            all(plan['files'][role]['path'] == PATHS[role] for role in ORDER),'EXACT_NINE_FILE_AUDIT_PLAN')
        domain = direct.Descendants()
        bodies = {}
        for role in ORDER:
            cap = MAX_METADATA if role in ('manifest','F_statistics','F_pre_statistics') else MAX_FILE
            bodies[role],receipt = read_file(PATHS[role],cap,tick,total,plan['files'][role].get('pin'),role != 'F_faults_report')
            result['files'].append(receipt)
        result['metrics'] = audit_bodies(bodies,plan['common_count'],plan['files']['mapping']['pin']['sha256'],
            plan['H_statistics'],plan['minimum_pre_detected'],lambda:tick(True))
        tick()
        result['capture_complete'] = True
    except BaseException as exc:
        result['error'] = dict(type=type(exc).__name__,code=str(exc) if type(exc) is ValueError else 'OWNED_AUDIT_FAILED')
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        result['body_bytes_hashed'] = total[0]
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(result)) <= MAX_RESPONSE,'AUDIT_RESPONSE_BOUND')
    return result


def _F_envelope(compiled,binding,repo,manifest_pin):
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
        for row in compiled['sources']:
            if row['name'] == 'prospective_generation_context_e127':
                continue
            raw = base64.b64decode(row['body'],validate=True)
            require(sha(raw) == row['sha256'],'DERIVED_BODY_SHA')
            name = 'src.data.'+row['name']
            module = types.ModuleType(name)
            module.__package__ = 'src.data'
            sys.modules[name] = module
            setattr(sys.modules['src.data'],row['name'],module)
            created.append(name)
            exec(compile(raw,'<e130-pure-path-'+row['name']+'>','exec'),module.__dict__)
            if row['name'] == 'prospective_generation_recipe_e108':
                recipe = module
                plan = recipe.pilot.build_plan()
                freeze = recipe.requests.freeze_acquisition(plan,'aes_core',COMMON_COUNT,manifest_pin)
                templates = repo/'src/data/templates'
                sources = recipe.freeze_sources((templates/'e108_common_base.tcl').read_bytes(),
                    (templates/'e108_incremental_base.tcl').read_bytes())
                return recipe.compile_execution(freeze,binding,sources)
        raise ValueError('EXACT_RECIPE_SOURCE_REQUIRED')
    finally:
        for name in created:
            sys.modules.pop(name,None)
        sys.modules.update(saved)


def prepare():
    from scripts import acceptance_transport_e98 as control
    from scripts import read_pt_label_failure_e128 as proof
    from scripts.run_direct_tessent_e104 import PINS
    from src.data import prospective_pt_label_bundle_e127 as bundle
    repo = Path(__file__).resolve().parents[1]
    execution_proof = proof._execution_proof(repo,control)
    raw = (control.STAGING/'v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
    require(sha(raw) == E128_SHA,'ACTUAL_E128_RESPONSE_CHANGED')
    prior = _json(raw)
    require(prior['capture_complete'] is True and prior['error'] is None,'E128_COMPLETE_PROOF_REQUIRED')
    rows = {row['path']:row for row in prior['files']}
    def body(name):
        row = rows[ROOT+'/journal/'+name]
        raw = base64.b64decode(row['body_base64'],validate=True)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],'E128_REFERENCE_BODY_SHA')
        return raw
    href_raw,tref_raw = body('task_000_reference.json'),body('task_001_reference.json')
    href,tref = _json(href_raw),_json(tref_raw)
    require(href['statistics']['sha256'] == href['artifacts']['statistics']['sha256'] and
        href['statistics']['bytes'] == href['artifacts']['statistics']['bytes'],'H_REFERENCE_STATISTICS_PIN')
    worker = _json((control.STAGING/'v6_e127_pt_label_generation_20261027_r1/stdout.json').read_bytes())
    completed = worker['summary']['completed_tasks']
    require(sha(href_raw) == completed[0]['output_sha256'] and sha(tref_raw) == completed[1]['output_sha256'] and
        href['task_uid'] == completed[0]['task_uid'] and tref['task_uid'] == completed[1]['task_uid'] and
        tref['parent_reference_sha256'] == sha(href_raw),'EXACT_COMMITTED_REFERENCE_CHAIN')
    binding = _json(body('task_002_intent.json'))['binding']
    require(binding['parent_result_sha256'] == sha(href_raw) and binding['translation_result_sha256'] == sha(tref_raw) and
        binding['parent_task_uid'] == href['task_uid'] and binding['translation_task_uid'] == tref['task_uid'],
        'EXACT_F_REFERENCE_JOIN')
    e88_raw = (repo/'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json').read_bytes()
    require(sha(e88_raw) == E88_SHA,'ACTUAL_FROZEN_E88_CHANGED')
    common = next(row for row in _json(e88_raw)['roots'] if row['circuit'] == 'aes_core')
    require(common['expected_common_count'] == COMMON_COUNT,'FROZEN_COMMON_N')
    compiled = bundle.build_sources()
    envelope = _F_envelope(compiled,binding,repo,common['files']['manifest.json']['sha256'])
    require(envelope['output_paths']['mtfi'] == PATHS['F_mtfi'] and
        envelope['output_paths']['statistics'] == PATHS['F_statistics'] and
        envelope['output_paths']['faults_report'] == PATHS['F_faults_report'] and
        envelope['pre_statistics_path'] == PATHS['F_pre_statistics'] and
        href['artifacts']['mtfi']['path'] == PATHS['H_mtfi'] and
        envelope['envelope_sha256'] == _json(body('task_002_preparation.json'))['effective_envelope_sha256'],
        'EXACT_PHYSICAL_OWNED_PATHS_FROM_BOUND_RECIPE')
    files = {role:dict(path=PATHS[role]) for role in ORDER}
    for role,name in (('manifest','manifest.json'),('mapping','canonical_fault_mapping.tsv'),
                      ('H_basic','H_common_initial_faults.basic'),('F_basic','F_common_initial_faults.basic')):
        files[role]['pin'] = common['files'][name]
    files['H_mtfi']['pin'] = {k:href['artifacts']['mtfi'][k] for k in ('bytes','sha256')}
    for role,digest in (('F_mtfi',F_MTFI_SHA),('F_statistics',F_STATS_SHA)):
        row = rows[PATHS[role]]
        require(row['sha256'] == digest and row['whole_file_hashed'] is True,'ACTUAL_E128_F_ARTIFACT_PIN')
        files[role]['pin'] = {k:row[k] for k in ('bytes','sha256')}
    plan = dict(files=files,common_count=COMMON_COUNT,H_statistics=href['statistics'],
        minimum_pre_detected=tref['expected_minimum_pre_detected'])
    sources = []
    for name,pin in list(PINS)+list(PURE)+[('e130_common_audit',None)]:
        path = Path(__file__) if pin is None else repo/'src/data'/(name+'.py')
        source = path.read_bytes()
        require(pin is None or sha(source) == pin,'PINNED_AUDITOR_SOURCE_CHANGED')
        ast.parse(source.decode('utf-8'),feature_version=(3,6))
        sources.append(dict(name=name,sha256=sha(source),body=base64.b64encode(source).decode('ascii')))
    package = json.dumps(dict(sources=sources,plan=plan),separators=(',',':'))
    payload = ('import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads('+repr(package)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<frozen-"+row["name"]+">","exec"),m.__dict__)\n'
        ' m.__source_sha256__=row["sha256"]\n'
        'result=sys.modules["src.data.e130_common_audit"].collect(p["plan"],bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    require(len(payload) <= 1048576,'AUDIT_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={row['name']:row['sha256'] for row in sources},authorization_sha256=AUTH_SHA,
        e128_response_sha256=E128_SHA,execution_review_sha256=execution_proof['review_sha256'],
        execution_source_sha256=execution_proof['source_sha256'],original_clock_sha256=execution_proof['clock_sha256'],
        local_deadline_sha256=execution_proof['local_deadline_sha256'],audit_plan_sha256=sha(canonical(plan)),e88_sha256=E88_SHA,
        audit_plan=plan)


def _validate_metrics(metrics,receipts,expected_plan):
    from src.data import prospective_fault_translation_e129 as faults
    from src.data import prospective_report_dialect_e126 as reports
    fields = {'common_count','namespace_keyset_verified','H_v2_source_parser_passed','H_e129_source_parser_passed',
        'F_e129_source_parser_passed','H_class_counts','F_class_counts','unknown_classes',
        'H_basic_full_keyset_verified','F_basic_full_keyset_verified','H_basic_explicit_detected','F_basic_explicit_detected',
        'H_explicit_detected','F_explicit_detected','H_F_explicit_intersection','H_F_explicit_union',
        'd95_integer_threshold','explicit_union_meets_d95_math','F_statistics','F_pre_statistics',
        'H_statistics_from_frozen_reference','H_statistics_source','H_reported_DS_DI','F_reported_DS_DI',
        'native_explicit_top_class_counts','statistics_minus_native_explicit_top_class_delta',
        'expanded_statistics_delta_sum','F_EQ_rows','H_native_explicit_top_class_counts',
        'H_statistics_minus_native_explicit_top_class_delta','H_expanded_statistics_delta_sum','H_EQ_rows',
        'necessary_conditions','eq_adjacency_detection_inferred','aggregate_counts_replace_explicit_union_contract',
        'coverage_semantics_proven','frozen_contract_d95_pass','training_release','translated_explicit_minimum_pre_detected'}
    require(type(metrics) is dict and set(metrics) == fields and type(metrics['common_count']) is int and
        metrics['common_count'] == COMMON_COUNT,'EXACT_METRICS_FIELDS')
    for key in ('namespace_keyset_verified','H_v2_source_parser_passed','H_e129_source_parser_passed',
                'F_e129_source_parser_passed','H_basic_full_keyset_verified','F_basic_full_keyset_verified'):
        require(metrics[key] is True,'COMPLETE_NAMESPACE_PARSER_GATES')
    for key in ('eq_adjacency_detection_inferred','aggregate_counts_replace_explicit_union_contract',
                'coverage_semantics_proven','frozen_contract_d95_pass','training_release'):
        require(metrics[key] is False,'NO_COVERAGE_CERTIFICATE_OR_CONTRACT_CHANGE')
    require(metrics['unknown_classes'] == [] and
        metrics['H_statistics_source'] == 'FROZEN_REFERENCE_METADATA_NOT_REREAD_H_STATISTICS','EXACT_AUDIT_OBSERVATION_SCOPE')
    h,f,u,i = (metrics[key] for key in ('H_explicit_detected','F_explicit_detected','H_F_explicit_union','H_F_explicit_intersection'))
    require(all(type(n) is int and 0 <= n <= COMMON_COUNT for n in (h,f,u,i)) and
        max(h,f) <= u <= min(COMMON_COUNT,h+f) and i == h+f-u and
        type(metrics['d95_integer_threshold']) is int and metrics['d95_integer_threshold'] == (95*COMMON_COUNT+99)//100 and
        metrics['explicit_union_meets_d95_math'] is (100*u >= 95*COMMON_COUNT),'EXPLICIT_SET_COUNT_IDENTITIES')
    for key in ('H_basic_explicit_detected','F_basic_explicit_detected','translated_explicit_minimum_pre_detected'):
        require(type(metrics[key]) is int and 0 <= metrics[key] <= COMMON_COUNT,'EXPLICIT_COUNT_BOUND')
    native_top = {}
    for mode,detected_count in (('H',h),('F',f)):
        counts = metrics[mode+'_class_counts']
        require(type(counts) is dict and 1 <= len(counts) <= 64 and all(type(label) is str and
            len(label) <= 128 and faults.valid_class(label) and type(n) is int and n > 0 for label,n in counts.items()) and
            sum(counts.values()) == COMMON_COUNT,'COMPLETE_FROZEN_NATIVE_CLASS_COUNTS')
        require(sum(n for label,n in counts.items() if faults.detected(label)) == detected_count,
                'NATIVE_DETECTED_CLASS_COUNT_MATCH')
        native_top[mode] = Counter()
        for label,n in counts.items():
            if label != 'EQ':
                native_top[mode]['DI' if label != 'DS' and faults.detected(label) else label.split('.',1)[0]] += n
    stat_fields = {'schema','status','bytes','sha256','generated_patterns','classes','detected_common_faults',
        'detected_definition','observation_scope','complete_stage_acceptance_verified','actual_atpg_runtime_ns',
        'd95_verified','execution_ready','training_release'}
    for key,patterns_required in (('H_statistics_from_frozen_reference',True),('F_statistics',True),('F_pre_statistics',False)):
        value = metrics[key]
        require(type(value) is dict and set(value) == stat_fields and value['schema'] == reports.SCHEMA and
            value['status'] == 'PARSED_COMPLETE_SUPPLIED_BYTES_NOT_AUTHENTICATED' and
            type(value['bytes']) is int and 0 < value['bytes'] <= MAX_METADATA and type(value['sha256']) is str and
            re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None,'EXACT_PARSED_STATISTICS_FIELDS')
        require((type(value['generated_patterns']) is int and 0 <= value['generated_patterns'] <= reports.MAX_COUNT) or
            (not patterns_required and value['generated_patterns'] is None),'PARSED_PATTERN_COUNT')
        classes = value['classes']
        require(type(classes) is dict and {'FU','DS','DI'} <= set(classes) <= set(reports.LABELS) and
            all(type(n) is int and 0 <= n <= COMMON_COUNT for n in classes.values()) and
            classes['FU'] == COMMON_COUNT and sum(n for label,n in classes.items() if label != 'FU') == COMMON_COUNT and
            type(value['detected_common_faults']) is int and value['detected_common_faults'] == classes['DS']+classes['DI'],
            'STATISTICS_PARTITION_AND_DS_DI')
        require(value['detected_definition'] == 'DS_PLUS_DI_ONLY_PT_EXCLUDED' and
            value['observation_scope'] == 'STATISTICS_PARSER_ONLY' and value['actual_atpg_runtime_ns'] is None and
            all(value[k] is False for k in ('complete_stage_acceptance_verified','d95_verified','execution_ready','training_release')),
            'STATISTICS_NOT_STAGE_OR_RUNTIME_CERTIFICATE')
        if key in ('F_statistics','F_pre_statistics'):
            receipt = receipts[key]
            require((value['bytes'],value['sha256']) == (receipt['bytes'],receipt['sha256']),'STATISTICS_PHYSICAL_RECEIPT_SHA')
    if expected_plan is not None:
        require(metrics['H_statistics_from_frozen_reference'] == expected_plan['H_statistics'] and
            metrics['translated_explicit_minimum_pre_detected'] == expected_plan['minimum_pre_detected'],
            'EXACT_FROZEN_H_REFERENCE_AND_TRANSLATION_MINIMUM')
    delta_by_mode = {}
    for mode,key in (('H','H_statistics_from_frozen_reference'),('F','F_statistics')):
        classes = metrics[key]['classes']
        delta = {label:classes.get(label,0)-native_top[mode].get(label,0)
            for label in sorted(set(classes)|set(native_top[mode])) if label != 'FU'}
        delta_by_mode[mode] = delta
        prefix = 'H_' if mode == 'H' else ''
        require(metrics[prefix+'native_explicit_top_class_counts'] == dict(native_top[mode]) and
            metrics[prefix+'statistics_minus_native_explicit_top_class_delta'] == delta and
            type(metrics[prefix+'expanded_statistics_delta_sum']) is int and
            metrics[prefix+'expanded_statistics_delta_sum'] == sum(delta.values()) and
            type(metrics[mode+'_EQ_rows']) is int and metrics[mode+'_EQ_rows'] == metrics[mode+'_class_counts'].get('EQ',0) and
            type(metrics[mode+'_reported_DS_DI']) is int and metrics[mode+'_reported_DS_DI'] == metrics[key]['detected_common_faults'],
            'EXACT_RECOMPUTED_NATIVE_STATISTICS_RECONCILIATION')
    needed = dict(expanded_class_deltas_nonnegative=all(n >= 0 for n in delta_by_mode['F'].values()),
        expanded_delta_sum_equals_EQ_rows=sum(delta_by_mode['F'].values()) == metrics['F_EQ_rows'],
        H_frozen_metadata_expanded_delta_sum_equals_EQ_rows=sum(delta_by_mode['H'].values()) == metrics['H_EQ_rows'],
        pre_reported_DS_DI_at_least_translated_explicit_minimum=metrics['F_pre_statistics']['detected_common_faults'] >= metrics['translated_explicit_minimum_pre_detected'])
    require(type(metrics['necessary_conditions']) is dict and set(metrics['necessary_conditions']) == set(needed) and
        all(metrics['necessary_conditions'][key] is value for key,value in needed.items()),'EXACT_RECOMPUTED_NECESSARY_CONDITIONS')


def validate_response(raw,expected_plan=None):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,'AUDIT_RESPONSE_BOUND')
    value = _json(raw)
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('hostname') == 'bupt-vncs2' and
        type(value.get('uid')) is int and value['uid'] == 1047 and value.get('boot_id') == BOOT and
        value.get('original_start_monotonic') == START and value.get('original_deadline_monotonic') == END and
        value.get('clock_must_not_be_reset') is True,'AUDIT_IDENTITY_CLOCK')
    for field in ('training_release','execution_ready','coverage_semantics_proven','frozen_contract_d95_pass',
                  'sampling_is_hard_memory_guarantee'):
        require(value.get(field) is False,'NO_COVERAGE_CERTIFICATE_OR_RELEASE')
    for field in ('explicit_filesystem_writes','child_launches','environment_reads','atpg_launches',
                  'additional_historical_reports','training_runs'):
        require(type(value.get(field)) is int and value[field] == 0,'OWNED_READ_ONLY_AUDIT')
    start,end = value.get('remote_start_monotonic'),value.get('remote_end_monotonic')
    require(all(type(t) in (int,float) and math.isfinite(t) for t in (start,end)) and
        START <= start <= end < END and end-start < 30,'AUDIT_INTERVAL')
    rows = value.get('files')
    require(type(rows) is list and len(rows) <= 9,'AUDIT_FILE_COUNT')
    total = 0
    for index,row in enumerate(rows):
        role = ORDER[index]
        fields = {'path','bytes','sha256','whole_file_hashed','matched_expected_pin','expected_sha256'}
        if role == 'F_faults_report':
            fields |= {'prefix_bytes','prefix_base64','excerpt_is_not_complete_report'}
        require(type(row) is dict and set(row) == fields and row['path'] == PATHS[role] and
            type(row['bytes']) is int and 0 < row['bytes'] <= (MAX_METADATA if role in ('manifest','F_statistics','F_pre_statistics') else MAX_FILE) and
            type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None and
            row['whole_file_hashed'] is True,'EXACT_FIXED_AUDIT_RECEIPT')
        expected = role not in ('F_pre_statistics','F_faults_report')
        require(row['matched_expected_pin'] is expected and
            (row['expected_sha256'] == row['sha256'] if expected else row['expected_sha256'] is None),'EXACT_PIN_RECEIPT')
        if expected_plan is not None and expected:
            pin = expected_plan['files'][role]['pin']
            require((row['bytes'],row['sha256']) == (pin['bytes'],pin['sha256']),'ACTUAL_AUDIT_PLAN_PIN')
        if role == 'F_faults_report':
            prefix = base64.b64decode(row['prefix_base64'],validate=True)
            require(type(row['prefix_bytes']) is int and row['prefix_bytes'] == len(prefix) == min(32768,row['bytes']) and
                row['excerpt_is_not_complete_report'] is (row['bytes'] > 32768),'BOUNDED_REPORT_EXCERPT')
        total += row['bytes']
    require(type(value.get('body_bytes_hashed')) is int and total <= value['body_bytes_hashed'] <= MAX_TOTAL and
        type(value.get('sampled_peak_rss_swap_bytes')) is int and 0 <= value['sampled_peak_rss_swap_bytes'] <= 536870912,
        'AUDIT_RESOURCE_RECEIPTS')
    require(type(value.get('capture_complete')) is bool,'AUDIT_CAPTURE_STATUS')
    if value['capture_complete']:
        require(len(rows) == 9 and value.get('error') is None and total == value['body_bytes_hashed'],
                'COMPLETE_AUDIT_RECEIPTS')
        _validate_metrics(value.get('metrics'),{role:row for role,row in zip(ORDER,rows)},expected_plan)
    else:
        require(type(value.get('error')) is dict,'AUDIT_FIRST_FAILURE_REQUIRED')
    return value


def execute(review_path,reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    from scripts import read_pt_label_failure_e128 as proof
    proof._local_remaining()
    plan = prepare()
    review = _json(Path(review_path).read_bytes())
    expected = {key:plan[key] for key in REVIEW_KEYS}
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and
        reviewed_payload_sha == plan['payload_sha256'],'FRESH_EXACT_INDEPENDENT_REVIEW_REQUIRED')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING/'v6_e130_common_universe_audit_20261027_r1'
    phase.mkdir(exist_ok=False)
    control.write_new(phase/'start.json',control.encode(dict(expected,host_fingerprint=fingerprint,
        sessions_max=1,automatic_retries=0,owned_file_count=9,additional_historical_reports=0,
        total_read_max=MAX_TOTAL,response_max=MAX_RESPONSE,collector_seconds=30,original_deadline_monotonic=END,
        clock_must_not_be_reset=True,audit_of_existing_inputs_not_acquisition_authority=True)))
    try:
        helper.TIMEOUT = min(40,max(1,int(proof._local_remaining())))
        observed = helper.transport(helper.command('A'),plan['payload'],MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(phase/'transport.json',control.encode(dict(error_type=type(exc).__name__,status='AUDIT_ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    control.write_new(phase/'stdout.json',observed['stdout'])
    control.write_new(phase/'stderr.log',observed['stderr'])
    receipt = {k:v for k,v in observed.items() if k not in ('stdout','stderr')}
    for key in ('stdout','stderr'):
        receipt[key+'_bytes'],receipt[key+'_sha256'] = len(observed[key]),sha(observed[key])
    control.write_new(phase/'transport.json',control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in
        ('timeout','overflow','write_failed','threads_incomplete')),'TRANSPORT_FAILED_NO_RETRY')
    result = validate_response(observed['stdout'],plan['audit_plan'])
    control.write_new(phase/'validated.json',control.encode(dict(capture_complete=result['capture_complete'],
        coverage_semantics_proven=False,frozen_contract_d95_pass=False,training_release=False)))
    require(result['capture_complete'],'AUDIT_STOPPED_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(phase),capture_complete=True,training_release=False,frozen_contract_d95_pass=False)


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({k:v for k,v in prepare().items() if k != 'payload'},sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        print(json.dumps(execute(args[1],args[2]),sort_keys=True))
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
