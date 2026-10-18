"""Bounded local name-only metadata/backup discovery. No file content reads."""
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path(r'C:\Users\86155\Desktop\new lab')
ROOT_NAMES = ('.artifact_staging', '.codex_build', '.staging', '01_配置与清单',
              '03_脚本工具', '04_同步收件箱', '05_B端数据交接', '99_临时文件',
              '99_A_B_中转', '99_A_B_涓浆', 'multimode_atpg_search_thesis_20260901',
              'runtime_training_staging_20260928', 'tmp')
DENIED_ROOT = BASE/'runtime_training_staging_20260928'/'formal_candidate_space_v2_r1'
SKIP_NAMES = {'.git','node_modules','venv','.venv','site-packages','__pycache__',
              'checkpoints','checkpoint','netlists','measurements','native_universes',
              'denominator_raw','phase4_r6_raw','runtime_training_package_v2_r1',
              'runtime_v2_outcome_split_r1','runtime_v2_results_20261004'}
MAX_DIRS, MAX_ENTRIES, MAX_DEPTH, MAX_MATCHES = 2500, 50000, 7, 256
SKIP_NAMES_FOLDED = frozenset(name.casefold() for name in SKIP_NAMES)


def skip_name(name):
    lower=name.casefold()
    return lower in SKIP_NAMES_FOLDED or 'blind' in lower or 'validation' in lower or lower in {'graphs','runs','results','raw'}


def match_kind(name):
    if name in ('receipt_v2.json','source_provenance_v2.tsv'):
        return 'named_metadata'
    lower = name.lower()
    if any(w in lower for w in ('candidate','provenance','runtime_v2_inputs','runtime_training')) and lower.endswith(('.tar.gz','.tgz','.zip','.tar')):
        return 'named_archive_candidate'
    return None


def discover(roots, denied_root):
    result = dict(status='PASS_BOUNDED_LOCAL_NAME_DISCOVERY',directories=0,entries=0,
                  matches=[],unavailable=[],depth_limited=[],excluded_directories=0,
                  file_contents_opened=False,archive_headers_read=False,ACL_changed=False,training_release=False)
    seen = set()
    todo = [(Path(root),0) for root in reversed(roots)]
    while todo:
        directory, depth = todo.pop()
        if directory == denied_root or skip_name(directory.name):
            result['excluded_directories'] += 1
            continue
        key = str(directory)
        if key in seen: raise ValueError('DUPLICATE_DIRECTORY')
        seen.add(key)
        if result['directories'] >= MAX_DIRS: raise ValueError('DIRECTORY_BOUND')
        try:
            directory_info = os.lstat(directory)
            if not stat.S_ISDIR(directory_info.st_mode) or getattr(directory_info,'st_file_attributes',0) & 0x400:
                result['unavailable'].append(dict(path=key,code='NOT_PLAIN_DIRECTORY'))
                continue
            with os.scandir(directory) as entries:
                result['directories'] += 1
                for entry in entries:
                    result['entries'] += 1
                    if result['entries'] > MAX_ENTRIES: raise ValueError('ENTRY_BOUND')
                    path = directory/entry.name
                    if path == denied_root or skip_name(entry.name):
                        result['excluded_directories'] += 1
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if getattr(info,'st_file_attributes',0) & 0x400 or stat.S_ISLNK(info.st_mode): continue
                        if stat.S_ISDIR(info.st_mode):
                            if depth < MAX_DEPTH: todo.append((path,depth+1))
                            else: result['depth_limited'].append(str(path))
                        elif stat.S_ISREG(info.st_mode):
                            kind = match_kind(entry.name)
                            if kind:
                                if len(result['matches']) >= MAX_MATCHES: raise ValueError('MATCH_BOUND')
                                result['matches'].append(dict(path=str(path),kind=kind,bytes=info.st_size))
                    except OSError as exc:
                        result['unavailable'].append(dict(path=str(path),code=type(exc).__name__))
        except OSError as exc:
            result['unavailable'].append(dict(path=key,code=type(exc).__name__))
    result['matches'].sort(key=lambda row:row['path'])
    result['unavailable'].sort(key=lambda row:row['path'])
    result['depth_limited'].sort()
    return result


def main():
    if len(sys.argv) != 1: raise ValueError('FIXED_SCOPE_ONLY')
    roots = [BASE/name for name in ROOT_NAMES]
    result = discover(roots,DENIED_ROOT)
    result['scope'] = [str(p) for p in roots]
    raw = json.dumps(result,ensure_ascii=True,sort_keys=True)
    if len(raw.encode('ascii')) > 131072: raise ValueError('OUTPUT_BOUND')
    print(raw)


if __name__ == '__main__': main()
