"""Local-testable source-read CORE ONLY; no transport, launch or current grant."""
import base64
import hashlib
import json
import os
import re
import stat

AUTH_SHA = None  # No E135 grant exists. A future approved freeze must pin it.
PROPOSAL_SHA = '0a9300f556d4b48cbebb7c83f4bac1ffa9c6875198e4a9b3ed2df21d67609767'
SCHEMA = 'physical-replay-source-receipt-e135-v1'
MAX_RESPONSE = 48*1048576
MAX_METADATA = 65536
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')
FILES = (
    dict(role='pattern',path='/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/tester.stil',uid=1047,cap=64*1048576,export=False),
    dict(role='reference',path='/cad/mentor/tessent2021_2/doc/pdfdocs/tshell_ref.pdf',uid=0,cap=32*1048576,export=True),
)


def require(ok,code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def decode(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            require(key not in result,'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def check_authority(authority,proposal):
    require(type(AUTH_SHA) is str and re.fullmatch('[0-9a-f]{64}',AUTH_SHA) is not None,'NO_FROZEN_E135_AUTHORITY')
    require(type(authority) is bytes and type(proposal) is bytes and
        sha(authority) == AUTH_SHA and sha(proposal) == PROPOSAL_SHA,'EXACT_AUTHORITY_AND_PROPOSAL_SHA')
    auth,plan = decode(authority),decode(proposal)
    require(auth.get('schema') == 'physical-f-pattern-replay-authorization-e135-v1' and
        plan.get('schema') == 'physical-f-pattern-replay-proposal-e135-v1' and
        auth.get('approval_source') == 'explicit_user_reply' and
        auth.get('user_reply') == '\u6279\u51c6 E135 \u6574\u5305' and
        auth.get('user_authorization_received') is True and auth.get('proposal_sha256') == PROPOSAL_SHA and
        type(auth.get('approved_scope')) is dict and auth['approved_scope'] == plan.get('scope_if_granted'),
        'EXACT_NEW_WHOLE_PACKAGE_AUTHORITY')
    scope = auth['approved_scope']
    require(scope.get('candidate_pattern_path') == FILES[0]['path'] and
        scope.get('reference_pdf_candidate') == FILES[1]['path'] and
        scope.get('source_pattern_bytes_max') == FILES[0]['cap'] and
        scope.get('reference_pdf_bytes_max') == FILES[1]['cap'] and
        scope.get('initial_readback_response_bytes_max') == MAX_RESPONSE and
        scope.get('source_pattern_export_to_desktop') is False and
        scope.get('automatic_retries') == 0,'EXACT_SOURCE_READ_SCOPE')


def identity(info):
    return {key:getattr(info,key) for key in FIELDS}


def read_file(record,tick):
    """Read one exact source. tick must enforce the caller's deadline/resources."""
    from src.data import prospective_acceptance_materializer_v1 as anchored
    require(type(record) is dict and record in FILES,'EXACT_SOURCE_RECORD')
    require(callable(tick),'INJECTED_RESOURCE_GUARD_REQUIRED')
    tick()
    parent,name = record['path'].rsplit('/',1)
    parent_fd,fd = anchored._directory(parent),None
    try:
        parent_identity = identity(os.fstat(parent_fd))
        named = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == record['uid'],
            'PREOPEN_REGULAR_SINGLE_LINK_OWNER')
        require(type(named.st_size) is int and 0 < named.st_size <= record['cap'],'PREOPEN_SIZE_CAP')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        require(identity(os.fstat(fd)) == identity(named),'OPEN_IDENTITY_CHANGED')
        remaining,digest,parts,tail = named.st_size,hashlib.sha256(),[],b''
        while remaining:
            tick()
            count = min(65536,remaining)
            raw = os.read(fd,count)
            require(type(raw) is bytes and 0 < len(raw) <= count,'SHORT_OR_INVALID_READ')
            remaining -= len(raw)
            digest.update(raw)
            if record['export']:
                combined = tail+raw
                stop = len(combined)//3*3
                if stop:
                    parts.append(base64.b64encode(combined[:stop]).decode('ascii'))
                tail = combined[stop:]
        if tail:
            parts.append(base64.b64encode(tail).decode('ascii'))
        tick()
        require(not os.read(fd,1),'SOURCE_GREW')
        current = os.fstat(fd)
        final = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        require(identity(named) == identity(current) == identity(final),'SOURCE_IDENTITY_CHANGED')
        require(identity(os.fstat(parent_fd)) == parent_identity,'HELD_PARENT_CHANGED')
        fresh = anchored._directory(parent)
        try:
            require(identity(os.fstat(fresh)) == parent_identity,'PARENT_ANCHOR_CHANGED')
        finally:
            os.close(fresh)
        tick()
        result = dict(role=record['role'],path=record['path'],bytes=named.st_size,
            sha256=digest.hexdigest(),identity=identity(current),whole_file_hashed=True)
        if record['export']:
            result['body_base64'] = ''.join(parts)
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def collect(authority,proposal,tick):
    """Denied before IO until an actual authority is pinned in a future freeze."""
    check_authority(authority,proposal)
    rows = [read_file(record,tick) for record in FILES]
    value = dict(schema=SCHEMA,files=rows,source_provenance_authenticated=False,
        semantics_verified=False,execution_ready=False)
    raw = canonical(value)
    validate_receipt(raw)
    tick()
    return value


def validate_receipt(raw):
    """Validate receipt consistency, not truth of unobserved hash-only STIL bytes."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,'RESPONSE_CAP')
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema','files','source_provenance_authenticated','semantics_verified','execution_ready'} and
        value['schema'] == SCHEMA and all(value[k] is False for k in
        ('source_provenance_authenticated','semantics_verified','execution_ready')),'CORE_ONLY_RECEIPT')
    require(type(value['files']) is list and len(value['files']) == 2,'EXACT_TWO_SOURCE_RECEIPTS')
    metadata = dict(value,files=[{k:v for k,v in row.items() if k != 'body_base64'} for row in value['files']])
    require(len(canonical(metadata)) <= MAX_METADATA,'METADATA_CAP')
    for record,row in zip(FILES,value['files']):
        fields = {'role','path','bytes','sha256','identity','whole_file_hashed'}
        if record['export']:
            fields.add('body_base64')
        require(type(row) is dict and set(row) == fields and row['role'] == record['role'] and
            row['path'] == record['path'] and type(row['bytes']) is int and 0 < row['bytes'] <= record['cap'] and
            type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None and
            row['whole_file_hashed'] is True,'EXACT_SOURCE_RECEIPT')
        info = row['identity']
        require(type(info) is dict and set(info) == set(FIELDS) and
            all(type(n) is int and n >= 0 for n in info.values()) and stat.S_ISREG(info['st_mode']) and
            info['st_uid'] == record['uid'] and info['st_nlink'] == 1 and info['st_size'] == row['bytes'],
            'SOURCE_IDENTITY_METADATA')
        if record['export']:
            body64 = row['body_base64']
            require(type(body64) is str and len(body64) == 4*((row['bytes']+2)//3),'FULL_REFERENCE_BASE64_SIZE')
            body = base64.b64decode(body64,validate=True)
            require(len(body) == row['bytes'] and sha(body) == row['sha256'] and
                base64.b64encode(body).decode('ascii') == body64,'FULL_REFERENCE_SHA')
    return value
