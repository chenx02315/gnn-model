"""Bounded hash-only inventory of the single E135 source tree and dependencies."""
import hashlib
import os
import stat

from .physical_replay_source_reader_e135 import require,sha,canonical,identity
from . import prospective_acceptance_materializer_v1 as anchored

BASE = '/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core'
TREE = BASE+'/runs/e116-aes_core/tsdb/aes_core:HF:h1:F'
MAX_ENTRIES,MAX_DEPTH,MAX_BYTES,MAX_METADATA = 4000,32,2147483648,1048576
INPUTS = (
    dict(role='library',path=BASE+'/inputs/aes_core/cells.lib',bytes=248814,sha256='34a3ca7df9262548eaf05ff544e2da080a541ab60467ef23193f6543ac5e5217'),
    dict(role='F_basic',path=BASE+'/03_fault_universe/common_frozen/F_common_initial_faults.basic',bytes=2245666,sha256='70b549870374c4b31f342d5a6fbd10db5d5d8f5eb3844c3eb8d28d45767fb566'),
)
ORIGINAL_TREE_SHA = 'ac602e864f6e5746622e0faf26e68a4a317f90e15eb0f2bc5350013216402259'


def safe_name(name):
    return (type(name) is str and 0 < len(name) <= 255 and name not in ('.','..') and
        '/' not in name and '\\' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name) and
        name.lower() not in ('.ssh','ssh','token','tokens','private_key','id_rsa','log','logs') and
        not name.lower().startswith('logs_') and not name.lower().endswith(('.log','.ckpt','.pt','.pth')) and
        not any(word in name.lower() for word in ('blind','checkpoint','secret','credential','outcome')))


def file_at(parent,name,tick,budget):
    tick()
    named = os.stat(name,dir_fd=parent,follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 1047,
        'INVENTORY_PREOPEN_REGULAR_SINGLE_LINK_OWNER')
    require(0 <= named.st_size <= MAX_BYTES-budget[0],'INVENTORY_BYTE_CAP')
    fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        require(identity(os.fstat(fd)) == identity(named),'INVENTORY_OPEN_CHANGED')
        remaining,digest = named.st_size,hashlib.sha256()
        while remaining:
            tick()
            count = min(65536,remaining)
            raw = os.read(fd,count)
            require(type(raw) is bytes and 0 < len(raw) <= count,'INVENTORY_SHORT_READ')
            digest.update(raw)
            remaining -= len(raw)
            budget[0] += len(raw)
        tick()
        require(not os.read(fd,1),'INVENTORY_GREW')
        require(identity(named) == identity(os.fstat(fd)) ==
            identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'INVENTORY_FILE_CHANGED')
        tick()
        return dict(bytes=named.st_size,sha256=digest.hexdigest(),identity=identity(named),whole_file_hashed=True)
    finally:
        os.close(fd)


def read_input(pin,tick):
    require(pin in INPUTS,'EXACT_FIXED_INPUT')
    parent,name = pin['path'].rsplit('/',1)
    fd = anchored._directory(parent)
    try:
        before = identity(os.fstat(fd))
        named = os.stat(name,dir_fd=fd,follow_symlinks=False)
        require(named.st_size == pin['bytes'],'FIXED_INPUT_SIZE')
        result = file_at(fd,name,tick,[0])
        require(result['sha256'] == pin['sha256'],'FIXED_INPUT_SHA')
        require(identity(os.fstat(fd)) == before,'INPUT_PARENT_CHANGED')
        fresh = anchored._directory(parent)
        try:
            require(identity(os.fstat(fresh)) == before,'INPUT_ANCHOR_CHANGED')
        finally:
            os.close(fresh)
        return dict(result,role=pin['role'],path=pin['path'])
    finally:
        os.close(fd)


def inventory(tick):
    """No generic tree/path API. Exactly TREE; no symlinks, exports or writes."""
    rows,budget,entries = [],[0],[0]
    def visit(fd,relative,depth):
        tick()
        require(depth <= MAX_DEPTH,'TREE_DEPTH_CAP')
        before = identity(os.fstat(fd))
        require(stat.S_ISDIR(before['st_mode']) and before['st_uid'] == 1047 and before['st_nlink'] >= 1,
            'OWNED_TREE_DIRECTORY')
        rows.append(dict(relative=relative,kind='directory',bytes=0,sha256=None,identity=before))
        alias = '/proc/self/fd/%d'%fd
        target = TREE+('/'+relative if relative else '')
        def check():
            tick()
            require(identity(os.fstat(fd)) == before and os.readlink(alias) == target and
                identity(os.stat(alias,follow_symlinks=True)) == before,'TREE_FD_ALIAS_CHANGED')
        check()
        names = []
        with os.scandir(alias) as stream:
            iterator = iter(stream)
            while True:
                check()
                # Conservatively fail at the bound; never request entry 4001.
                require(entries[0] < MAX_ENTRIES,'TREE_ENTRY_CAP')
                try:
                    name = next(iterator).name
                except StopIteration:
                    break
                require(safe_name(name) and name not in names,'TREE_ENTRY_NAME')
                entries[0] += 1
                names.append(name)
        check()
        for name in sorted(names):
            tick()
            rel = relative+'/'+name if relative else name
            require(depth+1 <= MAX_DEPTH,'TREE_DEPTH_CAP')
            named = os.stat(name,dir_fd=fd,follow_symlinks=False)
            require(named.st_uid == 1047,'TREE_ENTRY_OWNER')
            if stat.S_ISDIR(named.st_mode):
                child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(named),'TREE_DIRECTORY_OPEN_CHANGED')
                    visit(child,rel,depth+1)
                    require(identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) == identity(named),
                        'TREE_DIRECTORY_NAMED_CHANGED')
                finally:
                    os.close(child)
            else:
                rows.append(dict(file_at(fd,name,tick,budget),relative=rel,kind='file'))
            require(len(canonical(rows)) <= MAX_METADATA,'TREE_METADATA_CAP')
        check()
    root = anchored._directory(TREE)
    try:
        before = identity(os.fstat(root))
        visit(root,'',0)
        fresh = anchored._directory(TREE)
        try:
            require(identity(os.fstat(fresh)) == before,'TREE_ROOT_REPLACED')
        finally:
            os.close(fresh)
    finally:
        os.close(root)
    digest = sha(canonical([[r['relative'],r['kind'],r['bytes'],r['sha256']] for r in rows]))
    result = dict(path=TREE,entries=entries[0],bytes=budget[0],rows=rows,sha256=digest,
        sha256_scope='E85_SORTED_CHILD_DEPTH_FIRST_TREE',complete=True,
        original_tree_sha256=ORIGINAL_TREE_SHA,original_tree_matches=(digest == ORIGINAL_TREE_SHA))
    require(len(canonical(result)) <= MAX_METADATA,'TREE_METADATA_CAP')
    tick()
    return result
