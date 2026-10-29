"""Exact two installation helpers; no search, process or environment access."""
import base64
import hashlib
import os
import stat
from .physical_replay_source_reader_e135 import require,sha,canonical,decode,identity,FIELDS
from . import prospective_acceptance_materializer_v1 as anchored

AUTH_SHA = 'af9efa1b960e06f60f35258b4a42a236644f617fe02fc9e806ae305a2c92755d'
PROPOSAL_SHA = '48ee68232e37b39844221166e567118ee4e0f5c68da7d9abbc086bbf072c7f2b'
PATHS = ('/cad/mentor/tessent2021_2/lib/scripts/tessent_functions',
    '/cad/mentor/tessent2021_2/lib/scripts/tessent_shell')
MAX_FILE,MAX_TOTAL,MAX_RESPONSE = 2097152,4194304,6291456
SCHEMA = 'engine-source-discovery-e137-v1'


def check_authority(raw,proposal):
    require(sha(raw) == AUTH_SHA and sha(proposal) == PROPOSAL_SHA,'EXACT_SUPPLEMENT_AUTHORITY')
    a,p = decode(raw),decode(proposal)
    require(a.get('schema') == 'physical-engine-source-discovery-authorization-e137-v1' and
        a.get('approval_source') == 'explicit_user_reply' and a.get('user_authorization_received') is True and
        a.get('user_reply') == '\u5141\u8bb8\u8865\u5145\u8bfb\u53d6' and a.get('proposal_sha256') == PROPOSAL_SHA and
        a.get('candidate_paths') == p.get('candidate_paths') == list(PATHS) and
        canonical(a.get('approved_scope')) == canonical(p.get('scope_if_granted')),'EXACT_TWO_HELPERS_SCOPE')


def read_file(path,tick,total):
    require(path in PATHS,'FIXED_HELPER_ONLY')
    tick()
    parent,name = path.rsplit('/',1)
    held,fd = anchored._directory(parent),None
    try:
        parent_id = identity(os.fstat(held))
        info = os.stat(name,dir_fd=held,follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0,'PREOPEN_UID0_REGULAR_SINGLE_LINK')
        require(0 < info.st_size <= MAX_FILE and total[0]+info.st_size <= MAX_TOTAL,'HELPER_BYTE_CAP')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=held)
        require(identity(os.fstat(fd)) == identity(info),'OPEN_CHANGED')
        chunks,left,digest = [],info.st_size,hashlib.sha256()
        while left:
            tick()
            raw = os.read(fd,min(left,65536))
            require(type(raw) is bytes and 0 < len(raw) <= min(left,65536),'SHORT_HELPER')
            chunks.append(raw)
            digest.update(raw)
            left -= len(raw)
            total[0] += len(raw)
        tick()
        require(not os.read(fd,1),'HELPER_GREW')
        require(identity(os.fstat(fd)) == identity(info) == identity(os.stat(name,dir_fd=held,follow_symlinks=False)), 'HELPER_CHANGED')
        require(identity(os.fstat(held)) == parent_id,'HELD_PARENT_CHANGED')
        fresh = anchored._directory(parent)
        try:
            require(identity(os.fstat(fresh)) == parent_id,'PARENT_REPLACED')
        finally:
            os.close(fresh)
        tick()
        return dict(path=path,bytes=info.st_size,sha256=digest.hexdigest(),identity=identity(info),
            whole_file_hashed=True,body_base64=base64.b64encode(b''.join(chunks)).decode('ascii'))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(held)


def validate(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,'RESPONSE_CAP')
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema','files','simulation_budget_changed'} and
        value['schema'] == SCHEMA and value['simulation_budget_changed'] is False and
        type(value['files']) is list and len(value['files']) == 2,'TWO_HELPERS_RECEIPT')
    bodies,total = [],0
    for path,row in zip(PATHS,value['files']):
        require(type(row) is dict and set(row) == {'path','bytes','sha256','identity','whole_file_hashed','body_base64'} and
            row['path'] == path and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE and row['whole_file_hashed'] is True,
            'EXACT_HELPER_RECEIPT')
        info = row['identity']
        require(type(info) is dict and set(info) == set(FIELDS) and all(type(n) is int and n >= 0 for n in info.values()) and
            stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_uid'] == 0 and info['st_size'] == row['bytes'],
            'HELPER_IDENTITY')
        body = base64.b64decode(row['body_base64'],validate=True)
        total += len(body)
        require(len(body) == row['bytes'] and sha(body) == row['sha256'] and total <= MAX_TOTAL,'FULL_HELPER_SHA')
        bodies.append(body)
    return value,bodies
