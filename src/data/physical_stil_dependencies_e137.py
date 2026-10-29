"""Bounded dependency-only STIL 1.0 subset; not a STIL importer or authority.

Grammar basis: IEEE 1450 WG dot0/bnf.pdf and 1450_clarifications.pdf.
Only self-contained STIL 1.0 files and exact absolute quoted Include names
are supported. IfNeed, extension blocks, user keywords/functions, relative
search, and ambiguous escapes fail closed. Legal unsupported STIL can fail.
Names, backslashes and physical paths are never decoded or normalized.
The caller must authenticate the allowlist/tree, source closure and resource
guard. __source_sha256__ is a bootstrap binding, not human consent/OS proof.
"""
import copy
import hashlib
import os
import re
import stat

from . import prospective_acceptance_materializer_v1 as anchored
from .physical_replay_source_reader_e135 import canonical, identity, require, sha
from .physical_replay_source_inventory_e135 import safe_name

ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'
PATTERN = ROOT+'/inputs/tester.stil'
FIXED = (
    dict(path=PATTERN,bytes=443378,sha256='333d9f9bd359cf9066501a41e748b2182f5c787ffd46e112c7b5c5c2c6c5eae2'),
    dict(path=ROOT+'/inputs/cells.lib',bytes=248814,sha256='34a3ca7df9262548eaf05ff544e2da080a541ab60467ef23193f6543ac5e5217'),
    dict(path=ROOT+'/inputs/F.basic',bytes=2245666,sha256='70b549870374c4b31f342d5a6fbd10db5d5d8f5eb3844c3eb8d28d45767fb566'),
)
TREE_FILES, TREE_BYTES = 19, 3759776
# Future bootstrap must verify these complete source bytes, not trust this map.
PINNED_DEPENDENCIES = {
    'src.data.prospective_acceptance_materializer_v1': 'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'src.data.physical_replay_source_reader_e135': '6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818',
    'src.data.physical_replay_source_inventory_e135': '9467ee407dec9fd9bccad3ffdc517a508789c38b404fe9ac7d9d499fbd1be48d',
}
MAX_FILE, MAX_PARSE_BYTES = 64*1048576, 64*1048576
MAX_DEPTH, MAX_EDGES, MAX_TOKEN, MAX_TOKENS = 8, 128, 16384, 4000000
TOP = frozenset(('Header','Signals','SignalGroups','Timing','Spec','Selector',
    'ScanStructures','PatternExec','PatternBurst','Procedures','MacroDefs','Pattern'))
UNSUPPORTED = frozenset(x.lower() for x in ('FileReference','Environment','UserKeywords',
    'UserFunctions','Extension','Design','Pragma','Import','Exec','System','IfNeed'))


def _allowlist(pattern_path, allowed):
    require(pattern_path == PATTERN and type(allowed) is list and
        len(allowed) == len(FIXED)+TREE_FILES,'E137_EXACT_CLONED_ALLOWLIST')
    rows = copy.deepcopy(allowed)
    require(all(type(r) is dict and set(r) == {'path','bytes','sha256'} and
        type(r['path']) is str and type(r['bytes']) is int and 0 <= r['bytes'] <= MAX_FILE and
        type(r['sha256']) is str and re.fullmatch('[0-9a-f]{64}',r['sha256']) for r in rows),
        'E137_ALLOWLIST_SHAPE')
    require(rows == sorted(rows,key=lambda r:r['path']) and
        len(set(r['path'] for r in rows)) == len(rows),'E137_ALLOWLIST_ORDER_UNIQUE')
    by_path = {r['path']:r for r in rows}
    require(all(by_path.get(r['path']) == r for r in FIXED),'E137_FIXED_INPUT_PINS')
    tree = [r for r in rows if r['path'] not in {x['path'] for x in FIXED}]
    require(len(tree) == TREE_FILES and sum(r['bytes'] for r in tree) == TREE_BYTES,
        'E137_TREE_FILE_COUNT_BYTES')
    for row in tree:
        require(row['path'].startswith(ROOT+'/tsdb/'),'E137_ALLOWLIST_PATH_SCOPE')
        parts = row['path'][len(ROOT+'/tsdb/'):].split('/')
        require(len(parts) <= 32 and all(safe_name(p) for p in parts),'E137_ALLOWLIST_PATH_SCOPE')
    return rows,by_path


def _parent_check(parent, held, before):
    require(identity(os.fstat(held)) == before,'E137_HELD_PARENT_CHANGED')
    fresh = anchored._directory(parent)
    try:
        require(identity(os.fstat(fresh)) == before and identity(os.fstat(held)) == before,
            'E137_PARENT_REPLACED')
    finally:
        os.close(fresh)


def _chunks(path, allowed, tick, snapshots):
    # Membership precedes even a stat/open of the requested leaf.
    require(path in allowed,'E137_DEPENDENCY_OUTSIDE_ALLOWLIST')
    row = allowed[path]
    tick()
    parent,name = path.rsplit('/',1)
    pfd,fd = anchored._directory(parent),None
    try:
        before_parent = identity(os.fstat(pfd))
        require(stat.S_ISDIR(before_parent['st_mode']) and before_parent['st_uid'] == 1047,
            'E137_PARENT_OWNER_DIRECTORY')
        named = os.stat(name,dir_fd=pfd,follow_symlinks=False)
        before = identity(named)
        require(stat.S_ISREG(named.st_mode) and named.st_uid == 1047 and named.st_nlink == 1,
            'E137_PREOPEN_REGULAR_OWNER_SINGLE_LINK')
        require(named.st_size == row['bytes'],'E137_PINNED_SIZE')
        require(path not in snapshots or snapshots[path] == (before,before_parent),
            'E137_COHORT_IDENTITY_CHANGED')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=pfd)
        require(identity(os.fstat(fd)) == before,'E137_OPEN_IDENTITY_CHANGED')
        digest,remaining = hashlib.sha256(),row['bytes']
        while remaining:
            tick()
            count = min(65536,remaining)
            raw = os.read(fd,count)
            require(type(raw) is bytes and 0 < len(raw) <= count,'E137_SHORT_READ')
            remaining -= len(raw)
            digest.update(raw)
            yield raw
        tick()
        require(os.read(fd,1) == b'','E137_FILE_GREW')
        require(digest.hexdigest() == row['sha256'],'E137_FILE_SHA_MISMATCH')
        require(before == identity(os.fstat(fd)) == identity(os.stat(name,dir_fd=pfd,follow_symlinks=False)),
            'E137_FILE_CHANGED')
        _parent_check(parent,pfd,before_parent)
        snapshots[path] = (before,before_parent)
        tick()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(pfd)


class _Lexer(object):
    """Streaming ASCII dependency lexer, not a complete STIL semantic parser."""
    def __init__(self, chunks, tick):
        self.chunks,self.tick = iter(chunks),tick
        self.buffer,self.offset,self.done,self.count,self.chars = '',0,False,0,0

    def peek(self,n=1):
        while len(self.buffer)-self.offset < n and not self.done:
            self.buffer = self.buffer[self.offset:]
            self.offset = 0
            raw = next(self.chunks,None)
            if raw is None:
                self.done = True
            else:
                require(all(c in (9,10,13) or 32 <= c <= 126 for c in raw),'E137_STIL_ASCII_ONLY')
                self.buffer += raw.decode('ascii')
        return self.buffer[self.offset:self.offset+n]

    def take(self):
        char = self.peek()
        self.offset += len(char)
        self.chars += len(char)
        if self.chars % 4096 == 0:
            self.tick()
        return char

    def quoted(self,quote):
        self.take()
        value = []
        while True:
            char = self.take()
            require(char != '','E137_UNCLOSED_QUOTE')
            if char == quote:
                return ''.join(value)
            require(char not in '\r\n','E137_MULTILINE_QUOTE_UNSUPPORTED')
            # Base STIL names permit literal backslashes; never C-unescape them.
            # Extensions escaping a delimiter/backslash are not supported.
            if char == '\\':
                require(self.peek() not in ('\\','"',"'",'\r','\n',''),
                    'E137_AMBIGUOUS_ESCAPE_UNSUPPORTED')
            value.append(char)
            require(len(value) <= MAX_TOKEN,'E137_TOKEN_CAP')

    def annotation(self):
        self.tick()
        # Called after Ann token; whitespace/comments are allowed before {*.
        token = self.next()
        require(token == ('punct','{') and self.take() == '*','E137_ANN_OPEN')
        while self.peek(2) != '*}':
            require(self.take() != '','E137_UNCLOSED_ANN')
        self.take(); self.take()

    def next(self):
        while True:
            char = self.peek()
            if not char:
                return ('eof','')
            if char.isspace():
                self.take(); continue
            if self.peek(2) == '//':
                while self.peek() not in ('','\r','\n'):
                    self.take()
                continue
            if self.peek(2) == '/*':
                self.take(); self.take()
                while self.peek(2) != '*/':
                    require(self.peek() != '' and self.peek(2) != '/*','E137_BAD_BLOCK_COMMENT')
                    self.take()
                self.take(); self.take(); continue
            break
        self.count += 1
        require(self.count <= MAX_TOKENS,'E137_TOKEN_COUNT_CAP')
        if char in ('"',"'"):
            return ('string' if char == '"' else 'expression',self.quoted(char))
        if char.isalpha() or char == '_':
            value = []
            while self.peek() and (self.peek().isalnum() or self.peek() == '_'):
                value.append(self.take())
                require(len(value) <= MAX_TOKEN,'E137_TOKEN_CAP')
            return ('word',''.join(value))
        if char.isdigit():
            value = []
            while self.peek() and (self.peek().isdigit() or self.peek() == '.'):
                value.append(self.take())
                require(len(value) <= MAX_TOKEN,'E137_TOKEN_CAP')
            return ('number',''.join(value))
        if char == '\\':
            self.take()
            require(self.take() in ('w','h','d','r'),'E137_UNSUPPORTED_BARE_ESCAPE')
            return ('wave_escape','')
        return ('punct',self.take())


def _includes(chunks,tick):
    lex = _Lexer(chunks,tick)
    require([lex.next(),lex.next(),lex.next()] == [('word','STIL'),('number','1.0'),('punct',';')],
        'E137_SELF_CONTAINED_STIL_1_0_REQUIRED')
    depth,header,refs = 0,None,[]
    while True:
        kind,value = lex.next()
        if kind == 'eof':
            require(depth == 0 and header is None,'E137_UNBALANCED_STIL')
            return refs
        if kind == 'word':
            require(value.lower() not in UNSUPPORTED,'E137_DEPENDENCY_EXTENSION_UNSUPPORTED')
            if value.lower() in ('include','ann'):
                require(value in ('Include','Ann') and header is None,'E137_AMBIGUOUS_DEPENDENCY_KEYWORD')
                if value == 'Ann':
                    lex.annotation()
                    continue
                target = lex.next()
                require(target[0] == 'string' and lex.next() == ('punct',';'),
                    'E137_LITERAL_INCLUDE_ONLY')
                path = target[1]
                require(path.startswith(ROOT+'/') and '\\' not in path and
                    not any(c in path for c in ('$','*','?','\t','\r','\n')),
                    'E137_ABSOLUTE_INCLUDE_ONLY')
                refs.append(path)
                require(len(refs) <= MAX_EDGES,'E137_INCLUDE_EDGE_CAP')
                continue
        if depth == 0:
            if header is None:
                if (kind,value) == ('punct',';'):
                    continue
                require(kind == 'word' and value in TOP,'E137_TOP_LEVEL_SUBSET')
                header = 0
                continue
            header += 1
            require(header <= 8,'E137_BLOCK_HEADER_CAP')
            if (kind,value) == ('punct','{'):
                depth,header = 1,None
            else:
                require(kind in ('word','string','number'),'E137_BLOCK_HEADER_SUBSET')
        elif kind == 'punct':
            if value == '{':
                depth += 1
                require(depth <= 128,'E137_BRACE_DEPTH_CAP')
            elif value == '}':
                depth -= 1


def verify(pattern_path, allowed, tick):
    """Validate exact cloned files and reachable supported literal dependencies.

    tick must enforce the caller's existing clock/process/memory/scratch limits.
    No authority, runtime identity or historical-source certificate is issued.
    """
    source_sha = getattr(verify,'__source_sha256__',None)
    require(type(source_sha) is str and re.fullmatch('[0-9a-f]{64}',source_sha) and callable(tick),
        'E137_FROZEN_VALIDATOR_AND_RESOURCE_GUARD_REQUIRED')
    rows,by_path = _allowlist(pattern_path,allowed)
    snapshots = {}
    for row in rows:
        for _ in _chunks(row['path'],by_path,tick,snapshots):
            pass
    parsed,active,edges,budget = set(),set(),[],[0]
    def visit(path,depth):
        require(path in by_path,'E137_DEPENDENCY_OUTSIDE_ALLOWLIST')
        require(path not in active,'E137_INCLUDE_CYCLE')
        require(depth <= MAX_DEPTH,'E137_INCLUDE_DEPTH_CAP')
        if path in parsed:
            return
        budget[0] += by_path[path]['bytes']
        require(budget[0] <= MAX_PARSE_BYTES,'E137_PARSE_BYTE_CAP')
        active.add(path)
        stream = _chunks(path,by_path,tick,snapshots)
        try:
            refs = _includes(stream,tick)
        finally:
            stream.close()
        for target in refs:
            edges.append((path,target))
            require(len(edges) <= MAX_EDGES,'E137_INCLUDE_EDGE_CAP')
            visit(target,depth+1)
        active.remove(path)
        parsed.add(path)
    visit(pattern_path,0)
    # Reanchor the whole hash cohort after dependency traversal, without export.
    for path in sorted(snapshots):
        tick()
        parent,name = path.rsplit('/',1)
        fd = anchored._directory(parent)
        try:
            before,pi = snapshots[path]
            require(identity(os.fstat(fd)) == pi and
                identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) == before,
                'E137_FINAL_COHORT_CHANGED')
            _parent_check(parent,fd,pi)
        finally:
            os.close(fd)
    receipt = dict(schema='physical-stil-dependencies-e137-v1',status='PASS',
        validator_source_sha256=source_sha,pattern_sha256=by_path[pattern_path]['sha256'],
        exact_allowlist_sha256=sha(canonical(rows)),files_verified=len(rows),
        parsed_files=sorted(parsed),include_edges=[list(e) for e in edges],
        supported_grammar='self-contained-STIL-1.0-absolute-literal-Include-no-IfNeed',
        dependency_closure_verified_within_supported_grammar=True,
        legal_unsupported_input_may_fail_closed=True,full_STIL_semantics_verified=False,
        tool_import_verified=False,historical_source_identity_verified=False,
        runtime_authority_verified=False,resource_enforcement_claimed=False,
        execution_ready=False,training_release=False)
    require(len(canonical(receipt)) <= 65536,'E137_RECEIPT_CAP')
    tick()
    return receipt
