"""Pure fixed-source conditional selector, NOT an engine/runtime authenticator.

No filesystem/environment/process access. Source bodies are supplied as bytes;
only their hashes and short branch assertions are retained in this module.
Metadata is an unauthenticated caller claim. PRESENT/absence must be obtained
and authenticated elsewhere before this classification can inform execution.
Only the constrained Linux/x86_64 tessent_shell invocation is modeled.
build_plan returns SENSITIVE_RAM_ONLY data including the supplied initial LD
path. Never serialize/publish that private plan. Use redact_plan for exports.
"""
import copy
import re
import stat

from .physical_replay_source_reader_e135 import canonical, require, sha, FIELDS

ROOT = '/cad/mentor/tessent2021_2'
RUN_ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'
FUNCTIONS_SHA = '00dd479b93c31ddee02231887f417e4636dd7abbe765965eba1779da1df5181f'
SHELL_SHA = '75933bcaa3831bf3635bb305d3e721f011ba9abf4c226045aa6d1d1863e4ca6d'
FUNCTIONS_BYTES, SHELL_BYTES = 12306, 49725
LAUNCHER = ROOT+'/bin/tessent'
ENGINE = {w:ROOT+'/lnx-x86/bin'+w+'/tessent_shell.exe' for w in ('64','32')}
MGLS = {w:ROOT+'/lnx-x86/bin'+w+'/mgls/lib/mgls_asynch' for w in ('64','32')}
TCL = {w:ROOT+'/lnx-x86/lib'+w+'/tcl8.6' for w in ('64','32','')}
CANDIDATES = tuple(ENGINE[w] for w in ('64','32'))+tuple(MGLS[w] for w in ('64','32'))+tuple(TCL[w] for w in ('64','32',''))
SCHEMA = 'physical-engine-source-plan-e137-v1'
PINNED_DEPENDENCY_SHA256 = '6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818'
PLAN_KEYS = frozenset(('schema','source_sha256','platform','whoami','environment_sha256',
    'argv_sha256','requested_width','initial_ld_library_path','candidate_paths',
    'actual_platform_observed','execution_ready','data_handling','plan_sha256'))
ENV_KEYS = frozenset(('PATH','LD_LIBRARY_PATH','LM_LICENSE_FILE','MGLS_LICENSE_FILE',
    'HOME','TMPDIR','LANG','LC_ALL','TESSENT_PATH','TESSENT_HOME','MGC_HOME','MGC_ROOT',
    'CIRCUIT_ROOT','CIRCUIT','TOP_MODULE','CELL_LIBRARY','COMMON_FAULT_DIR','MODE',
    'RUN_ID','TSDB_INPUT_DIR','PHASE','PATTERN_LIMIT','TEST_COVERAGE_LIMIT','STATUS_FILE',
    'STATUS_TRANSLATION_MANIFEST'))

# Short exact assertions supplement, never replace, complete immutable hashes.
FUNCTION_BRANCHES = (
    (b'TESSENT_PLATFORM=lnx-x86',1), (b'trywidth=$DEFW',1),
    (b'if [[ -e "$p/$target" ]] ; then',1),
    (b'if find_tessent_binary mgls/lib/mgls_asynch ; then',1),
    (b'lib${TESSENT_WIDTH}/tcl8.6',1),
    (b'if search_tessent_path $TESSENT_PLATFORM/${bin_dir}32/$exec_name ; then',1),
    (b'if search_tessent_path $TESSENT_PLATFORM/${bin_dir}64/$exec_name ; then',2),
)
SHELL_BRANCHES = (
    (b'\ntcl_setup\n',1),
    (b'find_tessent_binary $name.exe "${_tessent_wide_word}"',1),
    (b'eval preview_args "$MGC_DFT_EXTRA_ARG"',1),
    (b'eval handle_args "$MGC_DFT_EXTRA_ARG"',1),
    (b'\n    launch_application\n',1),
)


def _absolute(value):
    return (type(value) is str and 0 < len(value) <= 4096 and value.startswith('/') and
        all(p not in ('','.','..') for p in value.split('/')[1:]) and
        not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == '\\' for c in value))


def _sources(functions_bytes,shell_bytes):
    require(type(functions_bytes) is bytes and type(shell_bytes) is bytes and
        len(functions_bytes) == FUNCTIONS_BYTES and len(shell_bytes) == SHELL_BYTES and
        sha(functions_bytes) == FUNCTIONS_SHA and sha(shell_bytes) == SHELL_SHA,'EXACT_HELPER_SOURCE_BYTES')
    require(all(functions_bytes.count(s) == n for s,n in FUNCTION_BRANCHES) and
        all(shell_bytes.count(s) == n for s,n in SHELL_BRANCHES),'EXPECTED_HELPER_SOURCE_BRANCHES')
    require(shell_bytes.index(b'\ntcl_setup\n') < shell_bytes.index(SHELL_BRANCHES[1][0]) <
        shell_bytes.index(b'\n    launch_application\n'),'TCL_BEFORE_ENGINE_BEFORE_LAUNCH')


def _environment(environment):
    require(type(environment) is dict and set(environment) <= ENV_KEYS and 'PATH' in environment,
        'EXPLICIT_SUPPORTED_ENVIRONMENT_ONLY')
    require(all(type(k) is str and type(v) is str and 0 < len(v) <= 4096 and
        not any(ord(c) < 32 or ord(c) == 127 for c in v) for k,v in environment.items()) and
        len(canonical(environment)) <= 32768,'BOUNDED_ENVIRONMENT_STRINGS')
    require(environment.get('TESSENT_PATH',ROOT) == ROOT and
        environment.get('TESSENT_HOME',ROOT) == ROOT,'SINGLE_INSTALLATION_ROOT_ONLY')
    for key in ('MGC_HOME','MGC_ROOT'):
        require(key not in environment or environment[key] == ROOT,'SUPPORTED_MGC_ROOT_ONLY')
    for key in ('PATH','LD_LIBRARY_PATH'):
        if key in environment:
            require(all(_absolute(p) for p in environment[key].split(':')),'ABSOLUTE_NONEMPTY_SEARCH_COMPONENTS')
    for key in ('LANG','LC_ALL'):
        require(key not in environment or environment[key] == 'C','FIXED_C_LOCALE')
    # LD is needed internally for exact substring semantics; the private plan
    # contains it. Public receipts must pass through the explicit redactor.
    # Licensing and PATH values are not copied even into the private plan.
    return environment.get('LD_LIBRARY_PATH','')


def _argv(argv):
    require(type(argv) is list and 1 <= len(argv) <= 16 and argv[0] == LAUNCHER and
        all(type(v) is str and 0 < len(v) <= 4096 and
            not any(ord(c) < 32 or ord(c) == 127 for c in v) for v in argv),'FIXED_LAUNCHER_ARGV')
    seen,width,i = set(),'',1
    while i < len(argv):
        arg = argv[i]
        require(arg not in seen,'DUPLICATE_OR_CONFLICTING_OPTION')
        seen.add(arg)
        if arg in ('-64','-32'):
            require(not width,'DUPLICATE_OR_CONFLICTING_WIDTH')
            width = arg[1:]
        elif arg in ('-shell','-ignore_startup_file','-replace'):
            pass
        elif arg in ('-license_wait','-log','-dofile'):
            i += 1
            require(i < len(argv),'MISSING_OPTION_VALUE')
            value = argv[i]
            if arg == '-license_wait':
                require(value == '5','FIXED_LICENSE_WAIT')
            else:
                expected = RUN_ROOT+('/tool.log' if arg == '-log' else '/code/replay.tcl')
                require(value == expected,'FIXED_REPLAY_PATH_OPTION')
        else:
            raise ValueError('UNSUPPORTED_OR_DYNAMIC_ARGUMENT')
        i += 1
    require('-shell' in seen,'EXPLICIT_TESSENT_SHELL_REQUIRED')
    return width


def build_plan(functions_bytes,shell_bytes,environment,argv,system='Linux',machine='x86_64',whoami='tessent_shell'):
    """Return SENSITIVE_RAM_ONLY private plan; use redact_plan before export.

    The initial LD value is necessary for the helper's substring decision.
    This private object is neither a public receipt nor permission to execute.
    """
    _sources(functions_bytes,shell_bytes)
    require(type(system) is str and type(machine) is str and type(whoami) is str and
        system == 'Linux' and machine == 'x86_64' and whoami == 'tessent_shell','FIXED_PLATFORM_AND_TOOL')
    ld = _environment(environment)
    width = _argv(argv)
    plan = dict(schema=SCHEMA,source_sha256=dict(functions=FUNCTIONS_SHA,shell=SHELL_SHA),
        platform=dict(system=system,machine=machine,default_width='64'),whoami=whoami,
        environment_sha256=sha(canonical(environment)),argv_sha256=sha(canonical(argv)),
        requested_width=width,initial_ld_library_path=ld,candidate_paths=list(CANDIDATES),
        actual_platform_observed=False,execution_ready=False,data_handling='SENSITIVE_RAM_ONLY')
    return dict(plan,plan_sha256=sha(canonical(plan)))


def _validate_plan(plan):
    require(type(plan) is dict and set(plan) == PLAN_KEYS and plan['schema'] == SCHEMA and
        plan['source_sha256'] == dict(functions=FUNCTIONS_SHA,shell=SHELL_SHA) and
        plan['platform'] == dict(system='Linux',machine='x86_64',default_width='64') and
        plan['whoami'] == 'tessent_shell' and plan['candidate_paths'] == list(CANDIDATES) and
        plan['actual_platform_observed'] is False and plan['execution_ready'] is False and
        plan['data_handling'] == 'SENSITIVE_RAM_ONLY' and
        plan['requested_width'] in ('','32','64') and
        all(type(plan[k]) is str and re.fullmatch('[0-9a-f]{64}',plan[k]) for k in
            ('environment_sha256','argv_sha256','plan_sha256')) and
        type(plan['initial_ld_library_path']) is str and len(plan['initial_ld_library_path']) <= 4096 and
        (not plan['initial_ld_library_path'] or all(_absolute(p) for p in plan['initial_ld_library_path'].split(':'))) and
        plan['plan_sha256'] == sha(canonical({k:v for k,v in plan.items() if k != 'plan_sha256'})),
        'EXACT_SOURCE_DERIVED_PLAN')


def redact_plan(plan):
    """Export fixed public fields bound to this exact validated private plan.

    Raw LD, PATH and license strings cannot enter this allowlisted projection.
    The public result deliberately cannot be passed to classify as a plan.
    Hash binding is not authentication, source consent or execution authority.
    """
    _validate_plan(plan)
    public = {key:copy.deepcopy(plan[key]) for key in (
        'source_sha256','platform','whoami','environment_sha256','argv_sha256',
        'requested_width','candidate_paths','plan_sha256','actual_platform_observed','execution_ready')}
    public.update(schema='physical-engine-source-public-plan-e137-v1',
        data_handling='PUBLIC_REDACTED',contains_environment_values=False,
        initial_ld_library_path_sha256=sha(plan['initial_ld_library_path'].encode('utf-8')),
        private_plan_authenticated=False)
    return dict(public,redaction_sha256=sha(canonical(public)))


def _metadata(metadata):
    require(type(metadata) is dict and set(metadata) <= set(CANDIDATES),'FINITE_METADATA_PATHS_ONLY')
    result = {p:dict(state='UNOBSERVED') for p in CANDIDATES}
    for path,row in metadata.items():
        require(type(row) is dict and row.get('state') in ('UNOBSERVED','MISSING','PRESENT'),
            'CANDIDATE_METADATA_STATE')
        if row['state'] != 'PRESENT':
            require(set(row) == {'state'},'ABSENCE_OR_UNKNOWN_NOT_IDENTITY')
        else:
            info = row.get('identity')
            require(set(row) == {'state','identity'} and type(info) is dict and set(info) == set(FIELDS) and
                all(type(n) is int and 0 <= n < 2**64 for n in info.values()),'CANDIDATE_IDENTITY_SHAPE')
        result[path] = copy.deepcopy(row)
    return result


def classify(plan,metadata):
    """Simulate existence lookups from supplied claims; never authenticate them.

    A source-first PRESENT but unsafe object BLOCKS. It must not be turned into
    absence to manufacture a different fallback selection. UNOBSERVED stops a
    branch instead of treating missing observations as actual absent files.
    """
    _validate_plan(plan)
    rows = _metadata(metadata)
    trace,selected,ld = [],{},plan['initial_ld_library_path']
    class Stop(Exception):
        def __init__(self,status,code):
            self.status,self.code = status,code
    def exists(path,purpose):
        row = rows[path]
        trace.append(dict(path=path,purpose=purpose,state=row['state']))
        if row['state'] == 'UNOBSERVED':
            raise Stop('UNOBSERVED','LOOKUP_NOT_OBSERVED')
        return row['state'] == 'PRESENT'
    def safe(path,directory=False,executable=False):
        info = rows[path]['identity']
        valid_type = stat.S_ISDIR(info['st_mode']) if directory else stat.S_ISREG(info['st_mode'])
        if not (valid_type and info['st_uid'] == 0 and info['st_nlink'] >= 1 and
                not info['st_mode'] & 0o022 and (directory or info['st_size'] > 0) and
                (not executable or info['st_mode'] & 0o111)):
            raise Stop('BLOCKED','SOURCE_SELECTED_OBJECT_UNSAFE')
    def prepend_library(width):
        nonlocal ld
        lib = ROOT+'/lnx-x86/lib'+width
        # The actual helper checks a substring, not path-component equality.
        if not ld:
            ld = lib
        elif lib not in ld:
            ld = lib+':'+ld
    def binary(table,desired,purpose,optional=False):
        first = desired or '64'
        second = '32' if first == '64' else '64'
        for width in (first,second):
            path = table[width]
            if exists(path,purpose):
                safe(path,executable=purpose == 'engine')
                selected[purpose] = dict(path=path,width=width)
                # Width32 success probes width64 for a warning, not selection.
                if width == '32' and width == first:
                    exists(table['64'],purpose+'_width32_warning_probe')
                prepend_library(width)
                return width
        if not optional:
            raise Stop('BLOCKED','NO_ENGINE_CANDIDATE_EXISTS')
        return ''
    status,code = 'CONDITIONALLY_SELECTED','SUPPLIED_METADATA_BRANCHES_COMPLETE'
    try:
        license_width = binary(MGLS,'','mgls',optional=True)
        selected['mgls_home'] = (selected['mgls']['path'][:-len('lib/mgls_asynch')]
            if 'mgls' in selected else None)
        selected['tcl_search_width'] = license_width
        path = TCL[license_width]
        if not exists(path,'tcl_before_engine'):
            raise Stop('BLOCKED','TCL_DIRECTORY_MISSING_BEFORE_ENGINE_SEARCH')
        safe(path,directory=True)
        selected['tcl_library'] = path
        binary(ENGINE,plan['requested_width'],'engine')
    except Stop as exc:
        status,code = exc.status,exc.code
    result = dict(schema='physical-engine-source-classification-e137-v1',status=status,code=code,
        plan_sha256=plan['plan_sha256'],metadata_sha256=sha(canonical(metadata)),
        source_sha256=copy.deepcopy(plan['source_sha256']),selected=selected,lookup_trace=trace,
        pre_ldd_library_path_sha256=sha(ld.encode('utf-8')),
        source_tcl_search_precedes_engine_selection=True,
        launcher_inserts_cwd_into_PATH=True,validate_executable_may_replace_library_path=True,
        metadata_is_unauthenticated_caller_claim=True,candidate_existence_authenticated=False,
        selected_engine_identity_authenticated=False,actual_engine_selected_observed=False,
        complete_dynamic_library_closure_verified=False,execution_authorized=False,
        execution_ready=False,training_release=False)
    return dict(result,classification_sha256=sha(canonical(result)))
