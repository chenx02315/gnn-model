"""Two-call documentation-only probe; no executable, experiment, or environment access.

Protocol review is prior approval of fixed reader code, not approval of a future
selection. The parent records an exact post-metadata selection review separately.
"""
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import stat
import sys
import time

from src.data import documentation_scandir_compat_e132 as compatibility

HELPER_SHA = 'fb944116ac17da709bda9f6d4a5aa4b0aa4699f3b48c0829bca9ece362f99d11'
ORIGIN_PROBE_SHA = 'bcbc66b54c171ca1cb3b955b189aa85f91c1e77c4b44e61a5539d976d66a168e'

INSTALL_ROOT = '/cad/mentor/tessent2021_2'
INSTALL_PARENT = '/cad/mentor'
DOC_ROOTS = ('doc','docs','help','share/doc','share/help')
EXTENSIONS = ('.pdf','.html','.htm','.txt')
SENSITIVE = ('license','credential','secret','password','key','token','auth','user_data','design_data')
AUTH = 'contracts/coverage_semantics_documentation_authorization_e132_20261027.json'
AUTH_SHA = 'a093e056d09c91796ae4cebd0403288a49618ee6afc6a5eef6de6ad762159f8d'
PROPOSAL = 'contracts/coverage_semantics_documentation_repair_proposal_e132_v1.json'
PROPOSAL_SHA = 'a5f6a7ec838f9373dd23e3c1b35e8902b1a8fc3825865989ddb3cff5860036b2'
SCHEMA = 'tessent-documentation-probe-e132-v1'
META_CAP, EXPORT_CAP, BODY_CAP = 65536,48*1048576,32*1048576
MAX_ENTRIES, MAX_DEPTH = 200,2
PHASE_NAME = 'v6_e132_documentation_probe_20261027_r1'
PROTOCOL_KEYS = ('source_sha256','controller_sha256','authorization_sha256','proposal_sha256','protocol_sha256')


def require(ok,code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def decode(raw):
    def pairs(items):
        value = {}
        for k,v in items:
            require(k not in value,'DUPLICATE_JSON_KEY')
            value[k] = v
        return value
    return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def identity(info):
    return {k:getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')}


def allowed(relative,directory=False):
    if (type(relative) is not str or not 0 < len(relative) <= 512 or relative.startswith('/') or
            '\\' in relative or any(ord(c) < 32 or ord(c) == 127 for c in relative)):
        return False
    parts = relative.split('/')
    if any(p in ('','.','..') or any(word in p.lower() for word in SENSITIVE) for p in parts):
        return False
    roots = [root for root in DOC_ROOTS if relative == root or relative.startswith(root+'/')]
    if not roots:
        return False
    root = max(roots,key=len)
    rest = relative[len(root):].lstrip('/').split('/') if relative != root else []
    depth = len(rest) if directory else len(rest)-1
    return 0 <= depth <= MAX_DEPTH and (directory or (rest and posixpath.splitext(relative)[1].lower() in EXTENSIONS))


def _open_absolute_directory(path):
    require(path.startswith('/') and all(p not in ('.','..','') for p in path.split('/')[1:]),'CANONICAL_INSTALL_ROOT')
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.split('/')[1:]:
            next_fd = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_root(expected=None):
    real = os.path.realpath(INSTALL_ROOT)
    require(real.startswith(INSTALL_PARENT.rstrip('/')+'/') and real != INSTALL_PARENT,'INSTALL_ROOT_REALPATH_BOUND')
    fd = _open_absolute_directory(real)
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode),'INSTALL_ROOT_DIRECTORY')
        root = dict(logical=INSTALL_ROOT,resolved=real,identity=identity(info))
        require(expected is None or root == expected,'INSTALL_ROOT_SNAPSHOT_CHANGED')
        require(os.path.realpath(INSTALL_ROOT) == real,'INSTALL_ROOT_REALPATH_CHANGED')
        return fd,root
    except BaseException:
        os.close(fd)
        raise


def resolve_doc(root_fd,root,logical,directory=False):
    """Resolve only allowed doc-to-doc links, without stat/open outside that scope."""
    require(allowed(logical,directory),'LOGICAL_DOCUMENT_SCOPE')
    relative = logical
    for _ in range(17):
        fd = os.dup(root_fd)
        parts = relative.split('/')
        try:
            restart = None
            for index,part in enumerate(parts):
                info = os.stat(part,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(part,dir_fd=fd)
                    if target.startswith('/'):
                        require(target.startswith(root['resolved']+'/'),'SYMLINK_OUTSIDE_INSTALL_ROOT')
                        target = target[len(root['resolved'])+1:]
                    else:
                        target = posixpath.join('/'.join(parts[:index]),target)
                    restart = posixpath.normpath(posixpath.join(target,*parts[index+1:]))
                    require(allowed(restart,directory),'RESOLVED_DOCUMENT_SCOPE_OR_DEPTH')
                    break
                is_last = index == len(parts)-1
                require(stat.S_ISDIR(info.st_mode) if not is_last or directory else stat.S_ISREG(info.st_mode),
                        'NAMED_DOCUMENT_OR_DIRECTORY_TYPE_REQUIRED')
                flags = os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
                if not is_last or directory:
                    flags |= os.O_DIRECTORY
                next_fd = os.open(part,flags,dir_fd=fd)
                opened = os.fstat(next_fd)
                if identity(opened) != identity(info):
                    os.close(next_fd)
                    raise ValueError('DOCUMENT_INODE_RACE')
                os.close(fd)
                fd = next_fd
            if restart is not None:
                relative = restart
                continue
            require(allowed(relative,directory),'RESOLVED_DOCUMENT_SCOPE_OR_DEPTH')
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),'REGULAR_DOCUMENT_OR_DIRECTORY')
            result = fd
            fd = None
            return relative,result
        finally:
            if fd is not None:
                os.close(fd)
    raise ValueError('DOCUMENT_SYMLINK_DEPTH')


def candidate(root,logical,resolved,info):
    value = dict(logical_relative=logical,resolved_relative=resolved,identity=identity(info))
    value['candidate_id'] = sha(canonical(dict(root=root,metadata=value)))
    return value


def scan_metadata(root_fd,root,tick):
    # Fixed PDF directory probes precede generic help HTML, without increasing limits.
    queue = [(base+'/'+leaf,1) for base in DOC_ROOTS for leaf in ('pdf','pdfs')]+[(base,0) for base in DOC_ROOTS]
    visited,candidates,seen = set(),[],set()
    entries,dirs,rejected = 0,0,0
    truncated = depth_limited = False
    while queue and not truncated:
        logical,depth = queue.pop(0)
        if logical in visited:
            continue
        visited.add(logical)
        tick()
        try:
            resolved,fd = resolve_doc(root_fd,root,logical,True)
        except (OSError,ValueError):
            continue
        dirs += 1
        try:
            with compatibility.BoundedDocumentNames(fd,identity(os.fstat(fd)),root['resolved'],
                    logical,resolved,tick,limit=MAX_ENTRIES-entries) as stream:
                for name in stream:
                    tick()
                    if entries >= MAX_ENTRIES:
                        truncated = True
                        break
                    entries += 1
                    child = logical+'/'+name
                    try:
                        require(type(name) is str and '/' not in name and '\\' not in name,'DIRECTORY_ENTRY_NAME')
                        named = os.stat(name,dir_fd=fd,follow_symlinks=False)
                        if stat.S_ISDIR(named.st_mode):
                            if depth < MAX_DEPTH and allowed(child,True):
                                queue.append((child,depth+1))
                            else:
                                depth_limited = True
                            continue
                        if stat.S_ISLNK(named.st_mode) and allowed(child,True):
                            try:
                                _,linked = resolve_doc(root_fd,root,child,True)
                            except (OSError,ValueError):
                                linked = None
                            if linked is not None:
                                os.close(linked)
                                if depth < MAX_DEPTH:
                                    queue.append((child,depth+1))
                                else:
                                    depth_limited = True
                                continue
                        require(allowed(child),'DOCUMENT_EXTENSION_OR_NAME')
                        target,source = resolve_doc(root_fd,root,child)
                        try:
                            info = os.fstat(source)
                            require(0 < info.st_size <= BODY_CAP,'CANDIDATE_DOCUMENT_SIZE')
                            row = candidate(root,child,target,info)
                            again,check = resolve_doc(root_fd,root,child)
                            try:
                                require(again == target and identity(os.fstat(check)) == identity(info),'DOCUMENT_ALIAS_RACE')
                            finally:
                                os.close(check)
                        finally:
                            os.close(source)
                        if row['candidate_id'] not in seen:
                            if len(canonical(candidates+[row])) > META_CAP-4096:
                                truncated = True
                                break
                            candidates.append(row)
                            seen.add(row['candidate_id'])
                    except (OSError,ValueError):
                        rejected += 1
            if entries >= MAX_ENTRIES:
                truncated = True
        finally:
            os.close(fd)
    return dict(candidates=candidates,scanned_entries=entries,scanned_directories=dirs,
        rejected_entries=rejected,truncated=truncated,depth_limited=depth_limited,
        scan_complete_within_fixed_scope=not truncated and not queue,
        fixed_document_roots=list(DOC_ROOTS),no_candidates_does_not_prove_installation_document_absence=True)


def read_document(root_fd,root,row,tick):
    logical,resolved = row['logical_relative'],row['resolved_relative']
    target,fd = resolve_doc(root_fd,root,logical)
    try:
        before = os.fstat(fd)
        require(target == resolved and identity(before) == row['identity'],'SELECTED_DOCUMENT_SNAPSHOT_CHANGED')
        remaining,total,digest,parts,tail = before.st_size,0,hashlib.sha256(),[],b''
        require(0 < remaining <= BODY_CAP,'DOCUMENT_BODY_BOUND')
        while remaining:
            tick()
            raw = os.read(fd,min(65536,remaining))
            require(bool(raw),'DOCUMENT_SHORT_READ')
            remaining -= len(raw)
            total += len(raw)
            digest.update(raw)
            combined = tail+raw
            stop = len(combined)//3*3
            if stop:
                parts.append(base64.b64encode(combined[:stop]).decode('ascii'))
            tail = combined[stop:]
        if tail:
            parts.append(base64.b64encode(tail).decode('ascii'))
        require(not os.read(fd,1),'DOCUMENT_GREW')
        tick()
        require(identity(os.fstat(fd)) == row['identity'],'DOCUMENT_CHANGED')
        fresh,check = resolve_doc(root_fd,root,logical)
        try:
            require(fresh == resolved and identity(os.fstat(check)) == row['identity'],'DOCUMENT_ALIAS_CHANGED')
        finally:
            os.close(check)
        return dict(candidate_id=row['candidate_id'],bytes=total,sha256=digest.hexdigest(),
            whole_file_hashed=True,body_base64=''.join(parts))
    finally:
        os.close(fd)


def collect(mode,spec,started):
    from src.data import direct_tessent_acceptance_e104 as direct
    result = dict(schema=SCHEMA,mode=mode,capture_complete=False,error=None,hostname=platform.node(),
        uid=os.getuid() if hasattr(os,'getuid') else None,boot_id=None,remote_start_monotonic=started,
        python_version=list(sys.version_info[:3]),stage='HOST_SCOPE',
        remote_end_monotonic=None,probe_start_monotonic=started,probe_deadline_monotonic=started+300,
        root=None,scan=None,exports=[],sampled_peak_rss_swap_bytes=0,filesystem_writes=0,
        child_launches=0,environment_reads=0,tessent_launches=0,training_runs=0,
        coverage_semantics_proven=False,old_experiment_clock_changed=False,training_release=False)
    root_fd,domain = None,None
    next_sample = [0]
    deadline = started+60
    def tick():
        require(time.monotonic() < deadline,'DOCUMENT_PROBE_DEADLINE')
        if time.monotonic() >= next_sample[0]:
            require(not domain.sample() and domain.peak <= 536870912,'DOCUMENT_MEMORY_OR_CHILD_STOP')
            next_sample[0] = time.monotonic()+.25
        require(time.monotonic() < deadline,'DOCUMENT_PROBE_DEADLINE')
    try:
        require(mode in ('metadata','export') and sys.platform.startswith('linux') and
            result['hostname'] == 'bupt-vncs2' and result['uid'] == 1047,'FIXED_DOCUMENT_HOST_SCOPE')
        result['stage'] = 'AUTHORITY_CHECK'
        authority = base64.b64decode(spec['authority'],validate=True)
        require(sha(authority) == AUTH_SHA and json.loads(authority.decode('utf-8'))['user_reply'] == '\u6279\u51c6 **E132 \u65b0\u6587\u6863\u6838\u9a8c\u6574\u5305**',
                'ACTUAL_DOCUMENT_AUTHORITY')
        result['stage'] = 'BOOT_ID_CHECK'
        result['boot_id'] = direct.base._small('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',result['boot_id']) is not None,'BOOT_ID')
        metadata = None
        if mode == 'export':
            result['stage'] = 'METADATA_SNAPSHOT_CHECK'
            metadata_raw = base64.b64decode(spec['metadata'],validate=True)
            require(sha(metadata_raw) == spec['metadata_sha256'],'EXACT_METADATA_RESPONSE_SHA')
            metadata = validate_metadata(metadata_raw)
            require(metadata['boot_id'] == result['boot_id'],'PROBE_BOOT_CHANGED')
            result['probe_start_monotonic'] = metadata['probe_start_monotonic']
            result['probe_deadline_monotonic'] = metadata['probe_deadline_monotonic']
            deadline = min(deadline,result['probe_deadline_monotonic'])
        require(result['probe_start_monotonic'] <= started < result['probe_deadline_monotonic'],'TOTAL_DOCUMENT_PROBE_CLOCK')
        result['stage'] = 'RESOURCE_SETUP'
        domain = direct.Descendants()
        tick()
        result['stage'] = 'INSTALL_ROOT_CHECK'
        root_fd,root = open_root(metadata['root'] if metadata else None)
        result['root'] = root
        if mode == 'metadata':
            result['stage'] = 'DOCUMENT_DIRECTORY_SCAN'
            result['scan'] = scan_metadata(root_fd,root,tick)
        else:
            result['stage'] = 'DOCUMENT_EXPORT'
            selected = select_candidates(metadata,spec['selected_ids'])
            for row in selected:
                result['exports'].append(read_document(root_fd,root,row,tick))
        tick()
        result['stage'] = 'FINAL_INSTALL_ROOT_CHECK'
        fresh,again = open_root(root)
        os.close(fresh)
        require(again == root,'INSTALL_ROOT_RECHECK')
        result['capture_complete'] = True
        result['stage'] = 'COMPLETE'
    except BaseException as exc:
        result['error'] = dict(type=type(exc).__name__,stage=result['stage'],
            code=str(exc) if type(exc) is ValueError else 'DOCUMENT_PROBE_FAILED_AT_'+result['stage'])
    finally:
        if root_fd is not None:
            os.close(root_fd)
        result['remote_end_monotonic'] = time.monotonic()
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(result)) <= (META_CAP if mode == 'metadata' else EXPORT_CAP),'DOCUMENT_RESPONSE_BOUND')
    return result


def _validate_common(value,mode):
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('mode') == mode and
        value.get('hostname') == 'bupt-vncs2' and type(value.get('uid')) is int and value['uid'] == 1047,'DOCUMENT_RESPONSE_HOST_SCHEMA')
    require(type(value.get('python_version')) is list and len(value['python_version']) == 3 and
        all(type(n) is int and n >= 0 for n in value['python_version']),'FIXED_PYTHON_VERSION_METADATA')
    stages = {'HOST_SCOPE','AUTHORITY_CHECK','BOOT_ID_CHECK','METADATA_SNAPSHOT_CHECK','RESOURCE_SETUP',
        'INSTALL_ROOT_CHECK','DOCUMENT_DIRECTORY_SCAN','DOCUMENT_EXPORT','FINAL_INSTALL_ROOT_CHECK','COMPLETE'}
    require(value.get('stage') in stages and (value.get('capture_complete') is not True or value['stage'] == 'COMPLETE'),
            'FIXED_DOCUMENT_PROBE_STAGE')
    require(type(value.get('boot_id')) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) is not None,'DOCUMENT_BOOT')
    start,end,first,last = (value.get(k) for k in ('remote_start_monotonic','remote_end_monotonic','probe_start_monotonic','probe_deadline_monotonic'))
    require(all(type(t) in (int,float) and __import__('math').isfinite(t) and t >= 0 for t in (start,end,first,last)) and
        last == first+300 and first <= start <= end < last and end-start < 60,'DOCUMENT_CLOCK_BUDGET')
    if mode == 'metadata':
        require(first == start,'FIRST_DOCUMENT_CALL_STARTS_PROBE_CLOCK')
    for key in ('filesystem_writes','child_launches','environment_reads','tessent_launches','training_runs'):
        require(type(value.get(key)) is int and value[key] == 0,'DOCUMENT_ONLY_READ_SCOPE')
    for key in ('coverage_semantics_proven','old_experiment_clock_changed','training_release'):
        require(value.get(key) is False,'NO_EXPERIMENT_OR_COVERAGE_CHANGE')
    require(type(value.get('capture_complete')) is bool and type(value.get('sampled_peak_rss_swap_bytes')) is int and
        0 <= value['sampled_peak_rss_swap_bytes'] <= 536870912,'DOCUMENT_CAPTURE_OR_MEMORY')


def validate_metadata(raw):
    require(type(raw) is bytes and 0 < len(raw) <= META_CAP,'METADATA_RESPONSE_BOUND')
    value = decode(raw)
    _validate_common(value,'metadata')
    require(value['capture_complete'] is True and value['error'] is None,'METADATA_INCOMPLETE_NO_EXPORT')
    root = value['root']
    require(type(root) is dict and set(root) == {'logical','resolved','identity'} and root['logical'] == INSTALL_ROOT and
        type(root['resolved']) is str and root['resolved'].startswith(INSTALL_PARENT.rstrip('/')+'/') and
        type(root['identity']) is dict and set(root['identity']) == set(identity_fields()) and
        all(type(n) is int and n >= 0 for n in root['identity'].values()) and root['identity']['st_nlink'] >= 1 and
        stat.S_ISDIR(root['identity']['st_mode']),'VERIFIED_INSTALL_ROOT_METADATA')
    scan = value['scan']
    scan_fields = {'candidates','scanned_entries','scanned_directories','rejected_entries','truncated','depth_limited',
        'scan_complete_within_fixed_scope','fixed_document_roots','no_candidates_does_not_prove_installation_document_absence'}
    require(type(scan) is dict and set(scan) == scan_fields and type(scan.get('scanned_entries')) is int and 0 <= scan['scanned_entries'] <= MAX_ENTRIES and
        scan.get('fixed_document_roots') == list(DOC_ROOTS) and scan.get('no_candidates_does_not_prove_installation_document_absence') is True and
        all(type(scan.get(key)) is bool for key in ('truncated','depth_limited','scan_complete_within_fixed_scope')) and
        not (scan['truncated'] and scan['scan_complete_within_fixed_scope']) and
        (scan['scanned_entries'] < MAX_ENTRIES or scan['truncated']) and
        all(type(scan[k]) is int and 0 <= scan[k] <= 215 for k in ('scanned_directories','rejected_entries')),
        'BOUNDED_METADATA_SCAN')
    rows = scan['candidates']
    require(type(rows) is list and len(rows) <= MAX_ENTRIES,'METADATA_CANDIDATE_BOUND')
    ids = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'logical_relative','resolved_relative','identity','candidate_id'} and
            allowed(row['logical_relative']) and allowed(row['resolved_relative']),'CANDIDATE_DOC_ONLY_SCOPE')
        info = row['identity']
        require(type(info) is dict and set(info) == set(identity_fields()) and all(type(n) is int and n >= 0 for n in info.values()) and
            stat.S_ISREG(info['st_mode']) and info['st_nlink'] >= 1 and 0 < info['st_size'] <= BODY_CAP,'CANDIDATE_REGULAR_FILE_METADATA')
        expected = sha(canonical(dict(root=root,metadata={k:v for k,v in row.items() if k != 'candidate_id'})))
        require(row['candidate_id'] == expected and expected not in ids,'EXACT_CANONICAL_CANDIDATE_ID')
        ids.add(expected)
    return value


def identity_fields():
    return ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')


def select_candidates(metadata,ids):
    require(type(ids) is list and 1 <= len(ids) <= 3 and len(ids) == len(set(ids)) and all(type(x) is str for x in ids),'SELECT_AT_MOST_THREE_IDS')
    rows = {r['candidate_id']:r for r in metadata['scan']['candidates']}
    require(all(key in rows for key in ids),'EXACT_METADATA_CANDIDATE_SELECTION')
    selected = [rows[key] for key in ids]
    require(sum(r['identity']['st_size'] for r in selected) <= BODY_CAP,'SELECTED_TOTAL_BODY_BOUND')
    return selected


def _sources():
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    rows = []
    require(sha((repo/'scripts/probe_tessent_docs_e131.py').read_bytes()) == ORIGIN_PROBE_SHA,'FROZEN_E131_SOURCE_CHANGED')
    for name,pin in list(PINS)+[('documentation_scandir_compat_e132',HELPER_SHA),('e132_docs_probe',None)]:
        raw = (Path(__file__) if pin is None else repo/'src/data'/(name+'.py')).read_bytes()
        require(pin is None or sha(raw) == pin,'PINNED_READONLY_RUNTIME_SOURCE')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        rows.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    return rows


def _prepare(mode,metadata_raw=None,selected_ids=None):
    repo = Path(__file__).resolve().parents[1]
    authority = (repo/AUTH).read_bytes()
    require(sha(authority) == AUTH_SHA and sha((repo/PROPOSAL).read_bytes()) == PROPOSAL_SHA,'ACTUAL_DOCUMENT_AUTHORITY_OR_PROPOSAL_CHANGED')
    require(json.loads(authority.decode('utf-8'))['user_reply'] == '\u6279\u51c6 **E132 \u65b0\u6587\u6863\u6838\u9a8c\u6574\u5305**' and '\ufffd' not in authority.decode('utf-8'),'EXACT_AUTHORITY_UNICODE_REPLY')
    sources = _sources()
    protocol = dict(installation_root=INSTALL_ROOT,documentation_roots=list(DOC_ROOTS),max_depth=2,max_entries=200,
        metadata_cap=META_CAP,export_cap=EXPORT_CAP,body_cap=BODY_CAP,files_max=3,calls_max=2,call_seconds=60,total_seconds=300,
        source_sha256={r['name']:r['sha256'] for r in sources},selection_requires_post_metadata_root_review=True,
        protocol_review_is_not_future_selection_review=True)
    spec = dict(authority=base64.b64encode(authority).decode('ascii'))
    selection = None
    if mode == 'export':
        metadata = validate_metadata(metadata_raw)
        rows = select_candidates(metadata,selected_ids)
        selection = dict(metadata_sha256=sha(metadata_raw),selected_ids=selected_ids,selected_metadata=rows)
        spec.update(metadata=base64.b64encode(metadata_raw).decode('ascii'),metadata_sha256=sha(metadata_raw),selected_ids=selected_ids)
    package = json.dumps(dict(sources=sources,mode=mode,spec=spec),separators=(',',':'))
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
        ' exec(compile(raw,"<docs-"+row["name"]+">","exec"),m.__dict__)\n'
        'result=sys.modules["src.data.e132_docs_probe"].collect(p["mode"],p["spec"],bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    require(len(payload) <= 1048576,'DOCUMENT_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    result = dict(mode=mode,payload=payload,payload_sha256=sha(payload),source_sha256=protocol['source_sha256'],
        controller_sha256=sha(Path(__file__).read_bytes()),authorization_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,
        protocol_sha256=sha(canonical(protocol)),protocol=protocol,selection_manifest=selection,
        selection_manifest_sha256=sha(canonical(selection)) if selection else None)
    return result


def prepare_metadata():
    return _prepare('metadata')


def prepare_export(metadata_raw,selected_ids):
    return _prepare('export',metadata_raw,selected_ids)


def _protocol_review(plan,review_path,metadata=False):
    review = decode(Path(review_path).read_bytes())
    expected = {k:plan[k] for k in PROTOCOL_KEYS}
    require(review.get('status') == 'PASS' and review.get('protocol_reviewed') == expected and
        review.get('future_selection_not_yet_reviewed') is True,'INDEPENDENT_FIXED_PROTOCOL_REVIEW_REQUIRED')
    if metadata:
        require(review.get('metadata_payload_sha256') == plan['payload_sha256'],'EXACT_METADATA_PACKET_REVIEW')


def _phase():
    from scripts import acceptance_transport_e98 as control
    return control.STAGING/PHASE_NAME


def _remaining(first):
    domain = dict(pid=os.getpid(),host=platform.node(),monotonic_implementation=time.get_clock_info('monotonic').implementation)
    require(first.get('local_clock_domain') == domain,'SAME_LOCAL_PROCESS_MONOTONIC_DOMAIN_REQUIRED')
    start,last = first.get('local_monotonic_start'),first.get('local_monotonic_deadline')
    now = time.monotonic()
    require(all(type(v) in (int,float) and __import__('math').isfinite(v) for v in (start,last,now)) and
        last == start+300 and start <= now < last,'LOCAL_MONOTONIC_PROBE_DEADLINE')
    deadline = datetime.datetime.strptime(first['local_utc_deadline'],'%Y-%m-%dT%H:%M:%S.%f%z')
    remaining = min((deadline-datetime.datetime.now(datetime.timezone.utc)).total_seconds(),last-now)
    require(remaining > 1,'WHOLE_DOCUMENT_PROBE_300_SECONDS_EXPIRED')
    return remaining


def _transport(plan,directory,helper,first):
    from scripts import acceptance_transport_e98 as control
    cap = META_CAP if plan['mode'] == 'metadata' else EXPORT_CAP
    helper.TIMEOUT = min(60,max(1,int(_remaining(first))))
    try:
        observed = helper.transport(helper.command('A'),plan['payload'],cap)
    except BaseException as exc:
        control.write_new(directory/'transport.json',control.encode(dict(error_type=type(exc).__name__,status='ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    control.write_new(directory/'stdout.json',observed['stdout'])
    control.write_new(directory/'stderr.log',observed['stderr'])
    receipt = {k:v for k,v in observed.items() if k not in ('stdout','stderr')}
    for key in ('stdout','stderr'):
        receipt[key+'_bytes'],receipt[key+'_sha256'] = len(observed[key]),sha(observed[key])
    control.write_new(directory/'transport.json',control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in ('timeout','overflow','write_failed','threads_incomplete')),'DOCUMENT_TRANSPORT_FAILED_NO_RETRY')
    return observed['stdout']


def execute_metadata(review_path,reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    plan = prepare_metadata()
    _protocol_review(plan,review_path,True)
    require(reviewed_payload_sha == plan['payload_sha256'],'EXACT_REVIEWED_PAYLOAD')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = _phase()
    phase.mkdir(exist_ok=False)
    now = datetime.datetime.now(datetime.timezone.utc)
    monotonic_start = time.monotonic()
    first = dict(local_utc_start=now.isoformat(timespec='microseconds'),
        local_utc_deadline=(now+datetime.timedelta(seconds=300)).isoformat(timespec='microseconds'),
        local_monotonic_start=monotonic_start,local_monotonic_deadline=monotonic_start+300,
        local_clock_domain=dict(pid=os.getpid(),host=platform.node(),monotonic_implementation=time.get_clock_info('monotonic').implementation),
        source_sha256=plan['source_sha256'],protocol_sha256=plan['protocol_sha256'],authorization_sha256=AUTH_SHA,
        host_fingerprint=fingerprint,calls_max=2,metadata_attempt_consumed=True,automatic_retries=0,
        old_experiment_clock_changed=False)
    control.write_new(phase/'start.json',control.encode(first))
    directory = phase/'metadata'
    directory.mkdir(exist_ok=False)
    control.write_new(directory/'intent.json',control.encode(dict(payload_sha256=plan['payload_sha256'],call_index=1,attempt_consumed=True)))
    raw = _transport(plan,directory,helper,first)
    _remaining(first)
    value = validate_metadata(raw)
    control.write_new(directory/'validated.json',control.encode(dict(metadata_sha256=sha(raw),candidate_count=len(value['scan']['candidates']))))
    return dict(phase=str(phase),metadata_sha256=sha(raw),candidate_count=len(value['scan']['candidates']),
        remaining_seconds=_remaining(first),truncated=value['scan']['truncated'])


def execute_export(metadata_raw,selection_review_path,protocol_review_path,reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    phase = _phase()
    first = decode((phase/'start.json').read_bytes())
    _remaining(first)
    saved = (phase/'metadata/stdout.json').read_bytes()
    validated = decode((phase/'metadata/validated.json').read_bytes())
    require(metadata_raw == saved and sha(saved) == validated['metadata_sha256'],'ACTUAL_FIRST_METADATA_RESPONSE_REQUIRED')
    selection_review = decode(Path(selection_review_path).read_bytes())
    ids = selection_review.get('selected_ids')
    plan = prepare_export(metadata_raw,ids)
    _protocol_review(plan,protocol_review_path)
    require(first['protocol_sha256'] == plan['protocol_sha256'] and first['source_sha256'] == plan['source_sha256'] and
        first['authorization_sha256'] == AUTH_SHA,'PROTOCOL_CHANGED_AFTER_FIRST_CALL')
    require(selection_review.get('status') == 'PASS' and selection_review.get('reviewer_role') == 'PARENT_EXACT_POST_METADATA_SELECTION' and
        selection_review.get('selection_reviewed') == plan['selection_manifest'] and
        selection_review.get('export_payload_sha256') == plan['payload_sha256'] == reviewed_payload_sha and
        selection_review.get('selection_manifest_sha256') == plan['selection_manifest_sha256'], 'EXACT_ROOT_SELECTION_REVIEW_REQUIRED')
    helper = control.load_transport()
    require(helper.verify_cached_host('A') == first['host_fingerprint'],'SAME_CACHED_A_KEY_REQUIRED')
    directory = phase/'export'
    directory.mkdir(exist_ok=False)
    control.write_new(directory/'intent.json',control.encode(dict(call_index=2,attempt_consumed=True,
        metadata_sha256=sha(metadata_raw),selected_ids=ids,selection_manifest_sha256=plan['selection_manifest_sha256'],
        payload_sha256=plan['payload_sha256'],no_future_selection_review_claim=True)))
    raw = _transport(plan,directory,helper,first)
    value = decode(raw)
    _remaining(first)
    _validate_common(value,'export')
    metadata = validate_metadata(metadata_raw)
    require(value['capture_complete'] is True and value['error'] is None and value['root'] == metadata['root'] and
        value['boot_id'] == metadata['boot_id'] and value['probe_start_monotonic'] == metadata['probe_start_monotonic'] and
        [row.get('candidate_id') for row in value['exports']] == ids,'EXACT_SELECTED_EXPORT_COMPLETION')
    selected = select_candidates(metadata,ids)
    # Verify ALL complete files before writing any decoded artifact or permitting analysis.
    decoded = []
    for row,candidate_row in zip(value['exports'],selected):
        require(set(row) == {'candidate_id','bytes','sha256','whole_file_hashed','body_base64'} and
            type(row['bytes']) is int and row['bytes'] == candidate_row['identity']['st_size'] and row['whole_file_hashed'] is True,
            'COMPLETE_SELECTED_EXPORT_BYTES')
        body = base64.b64decode(row['body_base64'],validate=True)
        require(len(body) == row['bytes'] and sha(body) == row['sha256'],'FULL_EXPORTED_DOCUMENT_SHA')
        decoded.append(body)
    require(sum(len(body) for body in decoded) <= BODY_CAP,'EXPORTED_TOTAL_BODY_BOUND')
    _remaining(first)
    records = []
    for row,candidate_row,body in zip(value['exports'],selected,decoded):
        extension = posixpath.splitext(candidate_row['resolved_relative'])[1].lower()
        filename = row['candidate_id']+extension
        control.write_new(directory/filename,body)
        records.append(dict(candidate_id=row['candidate_id'],file=filename,bytes=len(body),sha256=sha(body),
            logical_relative=candidate_row['logical_relative'],resolved_relative=candidate_row['resolved_relative']))
    _remaining(first)
    control.write_new(directory/'validated.json',control.encode(dict(documents=records,all_whole_file_hashes_verified=True,
        version_semantics_not_yet_interpreted=True,coverage_semantics_proven=False)))
    return dict(phase=str(directory),documents=records,coverage_semantics_proven=False)
