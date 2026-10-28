"""One isolated external-pattern replay worker; provisional, execution denied.

REVIEWED_SPEC_SHA256 must be frozen after independent document/source review.
No network, retry, ATPG generation or old output writes. Tessent receives an
explicit environment; legacy Python selfchecks are not environment-closure proof.
The existing process observer/cleanup and sampled resource monitor are reused
in private function namespaces; historical module globals remain untouched.
"""
import copy
import base64
import math
import datetime
import os
import platform
import time
import types

from . import prospective_acceptance_materializer_v1 as io
from . import prospective_generation_storage_e118 as storage
from . import prospective_generation_process_e113 as process
from . import prospective_generation_supervision_e109 as launch_base
from . import prospective_fault_translation_e129 as faults
from . import eq_group_coverage_e133_r2 as evidence
from . import direct_tessent_acceptance_e104 as direct

SCHEMA = 'physical-f-replay-execution-e135-v1'
ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_r1'
AUTH_SHA256 = '03f0da9fec34c21433737fe51ee79e69aea7d2e8c7df94e333a78ca9be3d69b3'
REVIEWED_SPEC_SHA256 = None  # Not a caller-controlled bool or claimed manual PASS.
INITIAL_CLOCK_SHA256 = None
COMMANDS_VERIFIED = False
BASE_TCL_SHA256 = evidence.TCL_SHA
DI_SET_SHA256 = 'bbbf25513062cb7b6a0eccb23e9dc017529b84ff0080368701829d0fbab8bd74'
F_BASIC_SHA256 = evidence.PINS['F_basic'][1]
PROCESS_SOURCE_SHA256 = '6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6'
SELFTEST_ORIGIN_SHA256 = '360dd42f9c0a950858dad085d9c0a3ebda551991cd9ab525ea71fa97216abe10'
IDENTITY_FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')
SELFTEST_CASES = ('success', 'timeout', 'setsid_child')
require, sha, canonical = io.require, io.sha, io.canonical
_USED = False


def package_clock(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 4096 and INITIAL_CLOCK_SHA256 is not None and
            sha(raw) == INITIAL_CLOCK_SHA256, 'PINNED_FIRST_CALL_CLOCK_REQUIRED')
    value = evidence._json(raw)
    require(set(value) == {'schema','authorization_sha256','proposal_sha256','reader_payload_sha256',
            'initial_response_sha256','start_file_sha256','boot_id','remote_start_monotonic',
            'remote_deadline_monotonic','remote_utc_sample','remote_clock_sample_monotonic',
            'local_utc_start','local_utc_deadline','local_monotonic_start','local_monotonic_deadline',
            'local_clock_domain'} and value['schema'] == 'physical-f-replay-package-clock-e135-v1' and
            value['authorization_sha256'] == AUTH_SHA256, 'INITIAL_CLOCK_SCHEMA')
    for key in ('remote_start_monotonic','remote_deadline_monotonic','remote_clock_sample_monotonic',
                'local_monotonic_start','local_monotonic_deadline'):
        require(type(value[key]) in (float,int) and math.isfinite(value[key]) and value[key] > 0, 'INITIAL_CLOCK_NUMBER')
    for key in ('initial_response_sha256','start_file_sha256','reader_payload_sha256','proposal_sha256'):
        require(type(value[key]) is str and faults.SHA_RE.fullmatch(value[key]) is not None, 'INITIAL_CLOCK_HASH')
    require(process._boot_id() == value['boot_id'], 'INHERITED_BOOT')
    utc = lambda key: datetime.datetime.strptime(value[key],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    require(value['remote_deadline_monotonic'] == value['remote_start_monotonic']+3600 and
            value['local_monotonic_deadline'] == value['local_monotonic_start']+3600 and
            utc('local_utc_deadline')-utc('local_utc_start') == 3600, 'ORIGINAL_CLOCK_DURATION')
    remote_utc_end = utc('remote_utc_sample')+value['remote_deadline_monotonic']-value['remote_clock_sample_monotonic']
    return dict(value, monotonic_end=value['remote_deadline_monotonic'],
                utc_end=min(remote_utc_end,utc('local_utc_deadline')))


def _clone_namespace(module, updates):
    """Reuse identical function bytecode, not a mutation of imported globals."""
    namespace = dict(vars(module))
    namespace.update(updates)
    for name, value in vars(module).items():
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
            namespace[name] = types.FunctionType(value.__code__, namespace, name,
                value.__defaults__, value.__closure__)
    return namespace


def _stream_io(tick):
    class ReadOS(object):
        def __getattr__(self, name):
            return getattr(os,name)

        def read(self, fd, size):
            tick()
            return os.read(fd,size)
    return _clone_namespace(io, dict(os=ReadOS(), MAX_TREE=2147483648,
                                    MAX_ENTRIES=4000, MAX_DEPTH=32))


def _storage(end):
    namespace = _clone_namespace(storage, dict(ROOT=ROOT, SIDECAR=ROOT+'.initial_intent.json', END=end))
    methods = {name: types.FunctionType(value.__code__, namespace, name, value.__defaults__, value.__closure__)
               for name, value in vars(storage.DirectoryMonitor).items() if isinstance(value, types.FunctionType)}
    return namespace['persist_initial_intent'], type('E135DirectoryMonitor', (object,), methods)()


def _observer(launch, end, domain, budget, on_spawn, scratch):
    def validate(value):
        require(set(value) == launch_base.LAUNCH_KEYS and value['schema'] == launch_base.SCHEMA,
                'REPLAY_LAUNCH_KEYS')
        require(all(value[key] is False for key in ('environment_profile_authenticated',
                'execution_authorized', 'execution_ready')), 'NO_SYNTHETIC_AUTHORITY')
        require(value['argv'] == [launch_base.recipe.identities.LAUNCHER, '-shell', '-license_wait', '5',
                '-log', ROOT+'/tool.log', '-dofile', ROOT+'/code/replay.tcl'] and
                value['cwd'] == ROOT+'/work', 'FIXED_REPLAY_ARGV_CWD')
        launch_base._environment(value['env'], value['cwd'])
        require(sha(canonical(value['env'])) == value['environment_sha256'] and
                sha(canonical({k:v for k,v in value.items() if k != 'launch_spec_sha256'})) ==
                value['launch_spec_sha256'], 'REPLAY_LAUNCH_CHANGED')
    namespace = dict(vars(process), _validate_launch=validate)
    observer = types.FunctionType(process.observe_tessent.__code__, namespace,
                                  'observe_tessent', process.observe_tessent.__defaults__)
    return observer(launch, end, domain, budget, on_spawn, scratch)


# Exact function/class copy from frozen E127 worker; its controller/context
# imports are intentionally not brought into this isolated worker.
def run_selftests(ctx, domain):
    cases = (
        ('success', 'print("DIRECT_SYNTHETIC_OK")', 15),
        ('timeout', 'import time;time.sleep(5)', 10.5),
        ('setsid_child', 'import os,time\np=os.fork()\nif p==0:\n os.setsid();print("DIRECT_SETSID_READY %d"%os.getpid(),flush=True);time.sleep(30)\nelse:\n time.sleep(30)', 13))
    receipts = []
    for name, code, seconds in cases:
        ctx['sample']()
        end = min(ctx['end'], time.monotonic()+seconds)
        require(time.monotonic() < end-10, 'SELFTEST_CLEANUP_RESERVE')
        ctx['persist'](name+'_intent.json', canonical(dict(case=name, deadline=end,
            cleanup_reserve_seconds=10, actual_tessent_launch=False))+b'\n')
        try:
            observed = direct.base.supervise(['/usr/bin/python3', '-I', '-S', '-B', '-c', code],
                ctx['root']+'/journal', end, domain, [65536], scratch=SimpleMonitor(ctx['sample']),
                ready_check=direct.base._setsid_readiness if name == 'setsid_child' else None)
        except BaseException as exc:
            ctx['persist'](name+'_observation.json', canonical(dict(error_type=type(exc).__name__,
                status='SUPERVISION_RAISED_NO_RETRY'))+b'\n')
            raise
        raw = observed.pop('output')
        ctx['persist'](name+'_observation.json', canonical(dict(observed,
            output_bytes=len(raw), output_sha256=sha(raw),
            output_name=name+'_output.log', output_publication_ack=False))+b'\n')
        ctx['persist'](name+'_output.log', raw)
        passed = (observed.get('cleaned') is True and observed.get('launch_attempted') is True and
                  ((observed.get('returncode') == 0 and observed.get('failure') is None and
                    raw.strip() == b'DIRECT_SYNTHETIC_OK') if name == 'success' else
                   observed.get('failure') == 'CASE_TIMEOUT') and
                  (name != 'setsid_child' or observed.get('readiness') is not None))
        require(passed, 'ACTUAL_SELFTEST_FAILED')
        receipt = dict(case=name, passed=True, cleaned=True, authenticated_claim=True,
                       actual_linux_process=True, readiness=observed.get('readiness'), actual_tessent_launch=False)
        ctx['persist'](name+'_receipt.json', canonical(receipt)+b'\n')
        receipts.append(receipt)
        ctx['sample']()
    return receipts


class SimpleMonitor(object):
    def __init__(self, sample):
        self.sample = sample


def _tcl_string(value):
    require(type(value) is str and not any(c in value for c in '\x00\r\n'), 'TCL_STRING')
    return '"'+value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('[', '\\[').replace(']', '\\]')+'"'


def baseline_expectations(basic, mapping):
    require(sha(basic) == F_BASIC_SHA256 and sha(mapping) == evidence.PINS['mapping'][1], 'BASELINE_INPUT_PINS')
    lookup, universe = faults.mapping_lookup(mapping, 71216, 1, 'F', 'H')
    faults.parse_target_basic(basic, 71216, set(lookup))
    expected, detected = [], set()
    for line in faults._lines(basic, 'BASIC_ENCODING'):
        if not line.strip():
            continue
        stuck, label, path = faults.BASIC_RE.fullmatch(line.rstrip('\n')).groups()
        path = path.strip()
        if path.startswith('"'):
            path = path[1:-1]
        require(label != 'DS', 'BASELINE_DS_FORBIDDEN')
        if faults.detected(label):
            detected.add(lookup[(stuck,path)])
        expected.append((stuck,path,label if faults.detected(label) else ''))
    digest = sha(canonical([list(key) for key in sorted(detected, key=lambda key:(key[1],key[0]))]))
    require(len(detected) == 3713 and digest == DI_SET_SHA256 and len(universe) == 71216, 'EXACT_BASELINE_DI_SET')
    return EXPECTED_INIT.encode('ascii')


EXPECTED_INIT = r'''
set expected_keys [dict create]
set expected_di [dict create]
set basic_file [open /temp/jiangchuanc/multimode_ate_physical_f_replay_e135_r1/inputs/F.basic r]
while {[gets $basic_file line] >= 0} {
  if {![regexp {^\s*([01])\s+(\S+)\s+(.+?)\s*$} $line all stuck cls path]} {error "BASIC_ROW"}
  set path [string trim $path]
  if {[string index $path 0] eq "\""} {
    if {[string index $path end] ne "\""} {error "BASIC_QUOTES"}
    set path [string range $path 1 end-1]
  }
  if {$path eq "" || [string first "\"" $path] >= 0} {error "BASIC_PATH"}
  set key [list $stuck $path]
  if {[dict exists $expected_keys $key]} {error "BASIC_DUPLICATE"}
  dict set expected_keys $key 1
  if {[regexp {^(DI(_[1-9][0-9]?)?|DI\.(CLK|SCAN|SEN|SR))$} $cls]} {
    dict set expected_di $key $cls
  } elseif {[lsearch -exact {FU PT UU TI AU UC UO AU.PC AU.TC AU.SEQ EQ RE} $cls] < 0} {
    error "BASIC_CLASS_OR_DS"
  }
}
close $basic_file
if {[dict size $expected_keys] != 71216 || [dict size $expected_di] != 3713} {error "BASIC_COUNTS"}
'''


GATE = r'''
proc baseline_gate {native report stage} {
  global expected_keys expected_di native_header native_footer
  set seen [dict create]
  set observed_di [dict create]
  set native_classes [dict create]
  set f [open $native r]
  set header_index 0
  set footer_index 0
  set in_footer 0
  while {[gets $f line] >= 0} {
    if {[string length $line] > 4096} {error "NATIVE_LINE_BOUND"}
    if {$header_index < [llength $native_header]} {
      if {$line ne [lindex $native_header $header_index]} {error "NATIVE_HEADER"}
      incr header_index
      continue
    }
    if {$in_footer || $line eq [lindex $native_footer 0]} {
      set in_footer 1
      if {$footer_index >= [llength $native_footer] || $line ne [lindex $native_footer $footer_index]} {error "NATIVE_FOOTER"}
      incr footer_index
      continue
    }
    if {[regexp {^\s*([01])\s*,\s*([A-Z0-9_.]+)\s*,\s*"([^"\r\n]+)";\s*$} $line all stuck cls path]} {
      set key [list $stuck $path]
      if {![dict exists $expected_keys $key] || [dict exists $seen $key]} {error "BASELINE_KEYSET"}
      dict set seen $key 1
      dict set native_classes $key $cls
      if {$cls eq "DS"} {error "BASELINE_DS"}
      if {[string match "DI*" $cls]} {
        if {![dict exists $expected_di $key] || [dict get $expected_di $key] ne $cls} {error "BASELINE_DI"}
        dict set observed_di $key $cls
      } elseif {[lsearch -exact {FU PT UU TI AU UC UO AU.PC AU.TC AU.SEQ EQ RE} $cls] < 0} {
        error "BASELINE_UNKNOWN_CLASS"
      }
    } else {error "NATIVE_ROW"}
  }
  close $f
  if {$header_index != [llength $native_header] || $footer_index != [llength $native_footer] || [dict size $seen] != 71216 || [dict size $observed_di] != 3713} {error "BASELINE_INCOMPLETE"}
  # Only report_faults order defines groups, never native/MTFI adjacency.
  set f [open $report r]
  set report_seen [dict create]
  set expanded_di [dict create]
  set report_phase 0
  set representative_class ""
  while {[gets $f line] >= 0} {
    if {[string length $line] > 4096} {error "REPORT_LINE_BOUND"}
    if {$report_phase == 0} {
      if {[string trim $line] eq ""} {continue}
      if {![regexp {^\s*type\s+code\s+pin_pathname\s*$} $line]} {error "REPORT_HEADER"}
      set report_phase 1
      continue
    }
    if {$report_phase == 1} {
      if {![regexp {^\s*-+\s+-+\s+-+\s*$} $line]} {error "REPORT_SEPARATOR"}
      set report_phase 2
      continue
    }
    if {![regexp {^\s*([01])\s+([A-Z0-9_.]+)\s+(.+?)\s*$} $line all stuck cls path]} {error "REPORT_ROW"}
    set path [string trim $path]
    if {[string index $path 0] eq "\""} {
      if {[string index $path end] ne "\""} {error "REPORT_QUOTES"}
      set path [string range $path 1 end-1]
    }
    if {$path eq "" || [string first "\"" $path] >= 0} {error "REPORT_PATH"}
    set key [list $stuck $path]
    if {![dict exists $native_classes $key] || [dict exists $report_seen $key] || [dict get $native_classes $key] ne $cls} {error "REPORT_NATIVE_KEY_CLASS"}
    dict set report_seen $key 1
    if {$cls eq "EQ"} {
      if {$representative_class eq ""} {error "REPORT_ORPHAN_EQ"}
    } else {
      set representative_class $cls
    }
    if {[string match "DI*" $representative_class]} {
      if {![dict exists $expected_di $key]} {error "REPORT_EXPANDED_DI_OUTSIDE_BASELINE"}
      dict set expanded_di $key 1
    }
  }
  close $f
  if {$report_phase != 2 || [dict size $report_seen] != 71216 || [dict size $expanded_di] != 3713} {error "REPORT_BASELINE_INCOMPLETE"}
  puts "E135_BASELINE_GATE=$stage"
}
'''


def _snapshot(stage):
    prefix = ROOT+'/snapshots/'+stage
    return ('report_statistics -detailed_analysis > '+prefix+'.statistics.rpt\n'
        'report_faults > '+prefix+'.faults.rpt\n'
        'write_faults '+prefix+'.faults.mtfi -replace -format Mtfi\n')


def build_recipe(incremental, expectation_bytes, commands=None):
    """Candidate bytes only. Unreviewed options never authorize worker()."""
    require(sha(incremental) == BASE_TCL_SHA256, 'PINNED_F4_TCL')
    source = incremental.decode('ascii')
    start = source.index('set_context patterns -scan ')
    stop = source.index('read_faults $common_source -show_warnings\n')
    setup = source[start:stop+len('read_faults $common_source -show_warnings\n')]
    require('create_patterns' not in setup and '$status' not in setup and 'add_processors' not in setup, 'FRESH_F4_SETUP')
    # Variables use only new-root copies, never old status/native patterns.
    header = ('set root '+ROOT+'\nset circuit aes_core\nset top aes_cipher_top\nset mode F\n'
        'set run_id e135_external_F\nset tool_id re135\nset out '+ROOT+'/snapshots\n'
        'set lib '+ROOT+'/inputs/cells.lib\nset common_source '+ROOT+'/inputs/F.basic\n')
    # Same F4 setup with isolated TSDB, no inherited pattern set is accepted.
    setup = setup.replace('set tsdb_input [file normalize $::env(TSDB_INPUT_DIR)]', 'set tsdb_input '+ROOT+'/tsdb')
    commands = commands or ('read_patterns '+ROOT+'/inputs/tester.stil', 'simulate_patterns -source external')
    require(type(commands) in (tuple,list) and len(commands) == 2 and all(type(c) is str and '\n' not in c for c in commands), 'TWO_REPLAY_COMMANDS')
    envelope = ''.join('set '+name+' [list '+' '.join(_tcl_string(line.rstrip('\n')) for line in lines)+']\n'
                       for name,lines in (('native_header',faults.HEADER),('native_footer',faults.FOOTER)))
    body = header+setup+'source '+ROOT+'/code/expected_baseline.tcl\n'+envelope+GATE
    body += _snapshot('baseline')+'baseline_gate '+ROOT+'/snapshots/baseline.faults.mtfi '+ROOT+'/snapshots/baseline.faults.rpt baseline\n'
    body += commands[0]+'\n'+_snapshot('imported')+'baseline_gate '+ROOT+'/snapshots/imported.faults.mtfi '+ROOT+'/snapshots/imported.faults.rpt imported\n'
    body += commands[1]+'\n'+_snapshot('simulated')+'report_patterns > '+ROOT+'/snapshots/simulated.patterns.rpt\n'
    body += 'puts "E135_REPLAY_FINISHED"\nexit\n'
    raw = body.encode('ascii')
    require(not any(token in raw for token in (b'create_patterns', b'add_processors', b'read_faults $status', b'write_patterns')), 'FORBIDDEN_GENERATION_OR_MERGE')
    return dict(body=raw, sha256=sha(raw), base_tcl_sha256=BASE_TCL_SHA256,
                command_verified=COMMANDS_VERIFIED, baseline_expectations_sha256=sha(expectation_bytes))


class Files(object):
    """Exclusive anchored namespace, retained on every failure, no resume."""
    def __init__(self, tick):
        self.tick, self.owned = tick, {}

    def directory(self, path, create=False):
        require(path == ROOT or path.startswith(ROOT+'/'), 'NEW_ROOT_ONLY')
        if path != ROOT and ROOT in self.owned:
            root = io._directory(ROOT)
            try:
                require((os.fstat(root).st_dev,os.fstat(root).st_ino) == self.owned[ROOT], 'OWNED_ROOT_REPLACED')
            finally:
                os.close(root)
        if create:
            parent,name = path.rsplit('/',1)
            fd = io._directory(parent)
            try:
                child = io._mkdir(fd,name)
                os.close(child)
            finally:
                os.close(fd)
        fd = io._directory(path)
        identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        require(path not in self.owned or self.owned[path] == identity, 'OWNED_DIRECTORY_REPLACED')
        self.owned[path] = identity
        return fd

    def publish(self, name, raw, check=True):
        require('/' not in name and len(raw) <= 16777216, 'JOURNAL_PUBLICATION_BOUND')
        if check:
            self.tick()
        fd = self.directory(ROOT+'/journal')
        try:
            io._publish(fd,name,raw)
        finally:
            os.close(fd)
        return dict(path=ROOT+'/journal/'+name, bytes=len(raw), sha256=sha(raw))

    def copy(self, source, target, size, digest, expected_identity):
        self.tick()
        parent,name = source.rsplit('/',1)
        src = io._directory(parent)
        destination,leaf = target.rsplit('/',1)
        dst = self.directory(destination)
        out = None
        try:
            named = os.stat(name,dir_fd=src,follow_symlinks=False)
            require({key:getattr(named,key) for key in IDENTITY_FIELDS} == expected_identity and
                    named.st_uid == 1047 and named.st_nlink == 1, 'COPY_INITIAL_IDENTITY_CHANGED')
            out = os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dst)
            _,actual,hashed = _stream_io(self.tick)['_read_at'](src,name,[0],out,expected_bytes=size,max_bytes=67108864)
            require(actual == size and hashed == digest, 'COPY_SOURCE_PIN')
            fresh = io._directory(parent)
            try:
                require(io._identity(os.fstat(fresh)) == io._identity(os.fstat(src)), 'COPY_SOURCE_PARENT_REPLACED')
            finally:
                os.close(fresh)
            os.fsync(out)
            os.fsync(dst)
        finally:
            if out is not None:
                os.close(out)
            os.close(src)
            os.close(dst)
        self.tick()
        parent = self.directory(destination)
        sink = os.open('/dev/null',os.O_WRONLY)
        try:
            require(_stream_io(self.tick)['_read_at'](parent,leaf,[0],sink,expected_bytes=size,max_bytes=67108864)[2] == digest, 'COPY_READBACK_PIN')
        finally:
            os.close(parent)
            os.close(sink)
        os.close(self.directory(destination))
        return dict(path=target,bytes=size,sha256=digest)


def _tree_copy(files, source, pin):
    # Caps are private to the clone. No historical global LIMIT is patched.
    namespace = _stream_io(files.tick)
    original_read = namespace['_read_at']
    def read(*args, **kwargs):
        files.tick()
        return original_read(*args, **kwargs)
    namespace['_read_at'] = read
    def initial_identities():
        require(type(pin['rows']) is list and 0 < len(pin['rows']) <= 4001, 'INITIAL_TREE_ROWS')
        for row in pin['rows']:
            files.tick()
            relative = row['relative']
            require(type(relative) is str and (relative == '' or
                    all(part not in ('.','..','') for part in relative.split('/'))), 'INITIAL_TREE_PATH')
            path = source+('/'+relative if relative else '')
            parent,name = path.rsplit('/',1)
            fd = io._directory(parent)
            try:
                named = os.stat(name,dir_fd=fd,follow_symlinks=False)
                require({key:getattr(named,key) for key in IDENTITY_FIELDS} == row['identity'] and
                        named.st_uid == 1047, 'INITIAL_TREE_IDENTITY_CHANGED')
            finally:
                os.close(fd)
    initial_identities()
    target = files.directory(ROOT+'/tsdb', True)
    try:
        digest = namespace['_tree'](source,target,pin['bytes'],pin['files'],pin['directories'])
        require(digest == pin['sha256'], 'CLONED_TREE_SHA')
    finally:
        os.close(target)
    target = files.directory(ROOT+'/tsdb')
    os.close(target)
    initial_identities()
    require(namespace['_tree'](ROOT+'/tsdb',None,pin['bytes'],pin['files'],pin['directories']) == digest, 'CLONED_TREE_READBACK')
    target = files.directory(ROOT+'/tsdb')
    os.close(target)
    return dict(path=ROOT+'/tsdb',sha256=digest,bytes=pin['bytes'])


def worker(spec):
    """Real closed-loop entry; disabled until exact runtime spec is reviewed.

    spec carries authority bytes, inherited boot/start/UTC clock, complete
    executable/engine/env closure, exact source pins, and frozen recipe bytes.
    No readback or capture connection is opened by this function.
    """
    global _USED
    require(not _USED, 'ONE_WORKER_NO_RETRY')
    _USED = True
    require(COMMANDS_VERIFIED and REVIEWED_SPEC_SHA256 is not None and
            sha(canonical(spec)) == REVIEWED_SPEC_SHA256, 'FINAL_MANUAL_AND_RUNTIME_REVIEW_REQUIRED')
    require(getattr(process,'__source_sha256__',None) == PROCESS_SOURCE_SHA256, 'PINNED_OBSERVER_SOURCE_REQUIRED')
    require(sha(base64.b64decode(spec['authority_base64'],validate=True)) == AUTH_SHA256, 'NEW_AUTHORITY_PIN')
    require(platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux'), 'FIXED_HOST')
    clock = package_clock(base64.b64decode(spec['package_clock_base64'],validate=True))
    started,end = clock['remote_start_monotonic'],clock['monotonic_end']
    connection_end = min(end,time.monotonic()+2400)
    require(started <= time.monotonic() < end-10 and time.time() < clock['utc_end'], 'INHERITED_PACKAGE_DEADLINE')
    domain = direct.Descendants()
    persist_initial, monitor = _storage(connection_end)
    persist_initial(canonical(dict(schema=SCHEMA,spec_sha256=REVIEWED_SPEC_SHA256,launch_debit=0)))
    active = [False]
    def tick():
        require(time.monotonic() < connection_end-10 and time.time() < clock['utc_end'], 'PACKAGE_TIMEOUT')
        domain.sample()
        require(domain.peak <= 536870912, 'SAMPLED_MEMORY_STOP')
        if active[0]:
            receipt = monitor.sample()
            require(receipt['sampled_named_bytes'] <= 8589934592, 'STORAGE_BYTES_THRESHOLD')
    files = Files(tick)
    tick()
    os.close(files.directory(ROOT,True))
    for name in ('journal','code','work','inputs','snapshots'):
        os.close(files.directory(ROOT+'/'+name,True))
    active[0] = True
    tick()
    # Stable metadata from the first read is reverified here, not trusted as
    # still-current; all source paths were frozen in the reviewed spec.
    require(len(spec['input_files']) == 3 and {item['role'] for item in spec['input_files']} ==
            {'library','basic','pattern'}, 'EXACT_THREE_INPUT_FILES')
    targets = dict(library='cells.lib',basic='F.basic',pattern='tester.stil')
    for item in spec['input_files']:
        require(item['role'] in ('library','basic','pattern') and item['target'] in
                (ROOT+'/inputs/cells.lib', ROOT+'/inputs/F.basic', ROOT+'/inputs/tester.stil') and
                item['target'] == ROOT+'/inputs/'+targets[item['role']], 'FIXED_INPUT_TARGET')
        files.copy(item['path'], item['target'], item['bytes'], item['sha256'],item['identity'])
    _tree_copy(files,spec['tsdb']['path'],spec['tsdb'])
    for name in ('expected_baseline.tcl','replay.tcl'):
        fd = files.directory(ROOT+'/code')
        try:
            io._publish(fd,name,base64.b64decode(spec['code_base64'][name],validate=True))
        finally:
            os.close(fd)
    # Reuse the already-run E127 Python-only process cases, never execute its
    # controller or old authorization entry.
    def persist_selfcheck(name,raw):
        return files.publish(name,raw,check=not name.endswith(('_observation.json','_output.log')))
    ctx = dict(root=ROOT,end=connection_end,sample=tick,persist=persist_selfcheck)
    receipts = run_selftests(ctx,domain)
    require(len(receipts) == 3 and tuple(r['case'] for r in receipts) == SELFTEST_CASES and
            all(r['passed'] is True and r['cleaned'] is True and r['authenticated_claim'] is True for r in receipts), 'THREE_ACTUAL_SELFCHECKS_REQUIRED')
    # The full executable/environment closure verifier is frozen with the
    # initial identity packet; no wrapper-only identity claim is accepted.
    require(type(spec['execution_closure']) is list and len(spec['execution_closure']) >= 2 and
            len({item['path'] for item in spec['execution_closure']}) == len(spec['execution_closure']), 'FULL_EXECUTION_CLOSURE_REQUIRED')
    for item in spec['execution_closure']:
        parent,name = item['path'].rsplit('/',1)
        fd = io._directory(parent)
        sink = os.open('/dev/null',os.O_WRONLY)
        try:
            require(_stream_io(tick)['_read_at'](fd,name,[0],sink,expected_bytes=item['bytes'],max_bytes=134217728)[2] == item['sha256'], 'FRESH_EXECUTION_CLOSURE')
        finally:
            os.close(sink)
            os.close(fd)
        tick()
    launch = copy.deepcopy(spec['launch'])
    files.publish('launch_intent.json',canonical(dict(launch_debit=1,automatic_retries=0,
        launch_spec_sha256=launch['launch_spec_sha256'],spec_sha256=REVIEWED_SPEC_SHA256)))
    def on_spawn(identity):
        files.publish('spawn_identity.json',canonical(identity))
        return True
    session_end = min(connection_end,time.monotonic()+1800,
                      time.monotonic()+max(0,clock['utc_end']-time.time()))
    try:
        observed = _observer(launch,session_end,domain,[16777216],on_spawn,SimpleMonitor(tick))
    except BaseException as exc:
        files.publish('observation_exception.json',canonical(dict(error_type=type(exc).__name__,
            launch_debit=1,status='OBSERVER_RAISED_NO_RETRY_NO_OBSERVATION_FABRICATED')),check=False)
        raise
    raw = observed['output']
    metadata = {key:value for key,value in observed.items() if key != 'output'}
    metadata.update(output_bytes=len(raw),output_sha256=sha(raw),output_name='stdout.log')
    files.publish('observation.json',canonical(metadata),check=False)
    files.publish('stdout.log',raw,check=False)
    files.publish('stdout_ack.json',canonical(dict(bytes=len(raw),sha256=sha(raw))),check=False)
    tick()
    require(observed['failure'] is None and observed['cleaned'] is True and observed['returncode'] == 0,
            'REPLAY_OBSERVATION_REJECTED')
    # Scientific qualification requires separately exported full snapshots.
    return dict(schema=SCHEMA,status='OBSERVED_PENDING_ARTIFACT_AUDIT',launch_debit=1,
        selfchecks=3,actual_atpg_runtime_ns=None,physical_HF_D95_verified=False,
        execution_ready=False,training_release=False)
