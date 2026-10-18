"""Compare authenticated TRAIN source hashes with E38 metadata; no data reads."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys

# Isolated Python (-I -S -B) excludes the script directory from module lookup.
# Load only the fixed sibling helper by absolute __file__ path; never alter sys.path.
_HELPER_PATH = Path(__file__).resolve().with_name('project_ranking_v6_e54_source_binding.py')
_HELPER_SPEC = importlib.util.spec_from_file_location('_ranking_v6_e55_e54_stable', _HELPER_PATH)
if _HELPER_SPEC is None or _HELPER_SPEC.loader is None:
    raise ImportError('FIXED_STABLE_READER_UNAVAILABLE')
_HELPER_MODULE = importlib.util.module_from_spec(_HELPER_SPEC)
_HELPER_SPEC.loader.exec_module(_HELPER_MODULE)
stable_read = _HELPER_MODULE.stable_read

ROOT = Path(__file__).resolve().parents[1]
PROJECTION = ROOT.parent/'runtime_training_staging_20260928/v6_e54_source_binding_20261018_r1/projection.json'
INVENTORY = ROOT/'data/manifests/ranking_v6_e38_projection_summary_20261016_r1.json'
PROJECTION_SHA = '8aca374b13a89035706a72006258e9373ba67f0f31eda5376215eb51d007ba9e'
INVENTORY_SHA = '80b152fa1a81232e4d778cd0abac88e077d8de1b0d6a33ca83ac305db9a8823d'
TRAIN = frozenset(('aes_core','s13207','s15850','s35932','s38417','spi'))
STAGES = frozenset(('hf_coarse','hmf_coarse','hf_refine','hmf_refine'))
HEX = re.compile('[0-9a-f]{64}\\Z')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def join_sources(rows, files):
    require(type(rows) is list and len(rows) == 24, 'FORMAL_24')
    require(type(files) is list and len(files) == 32, 'INVENTORY_32')
    seen, paths = set(), set()
    for row in rows:
        require(type(row) is dict and set(row) == {'circuit','stage','source_sha256',
            'normalized_sha256','row_count','source_basename','logical_ordinal','physical_line'}, 'FORMAL_SCHEMA')
        key = (row['circuit'],row['stage'])
        require(row['circuit'] in TRAIN and row['stage'] in STAGES and key not in seen, 'FORMAL_GRID')
        seen.add(key)
        require(sha(row['source_sha256']) and sha(row['normalized_sha256']), 'FORMAL_SHA')
        require(type(row['row_count']) is int and row['row_count'] >= 0, 'FORMAL_COUNT')
        require(type(row['logical_ordinal']) is int and row['logical_ordinal'] >= 1
            and type(row['physical_line']) is int and row['physical_line'] == row['logical_ordinal']+1, 'ORDINAL')
        require(type(row['source_basename']) is str and 0 < len(row['source_basename']) <= 128
            and '/' not in row['source_basename'] and '\\' not in row['source_basename'], 'BASENAME')
    require(seen == {(c,s) for c in TRAIN for s in STAGES}, 'FORMAL_GRID')
    for item in files:
        require(type(item) is dict and {'circuit','stage_alias','sha256','path','coverage_root','row_count'} <= set(item), 'INVENTORY_SCHEMA')
        require(item['circuit'] in TRAIN and item['stage_alias'] in STAGES and sha(item['sha256']), 'INVENTORY_KEY')
        require(type(item['row_count']) is int and item['row_count'] >= 0, 'INVENTORY_COUNT')
        require(type(item['path']) is str and type(item['coverage_root']) is str
            and item['path'].startswith(item['coverage_root']+'/')
            and item['path'] not in paths and '..' not in PurePosixPath(item['path']).parts, 'INVENTORY_PATH')
        paths.add(item['path'])
    output, references = [], [0]*len(files)
    classes = {'ZERO_ORIGINAL_SHA_MATCH':0, 'ONE_ORIGINAL_SHA_MATCH':0, 'MULTIPLE_IDENTICAL_BYTES_LOCATIONS':0}
    for row in rows:
        matches = []
        for index, item in enumerate(files):
            if (row['circuit'],row['stage'],row['source_sha256']) != (item['circuit'],item['stage_alias'],item['sha256']):
                continue
            require(row['row_count'] == item['row_count'], 'MATCHED_HASH_ROW_COUNT_CONTRADICTION')
            references[index] += 1
            matches.append({'inventory_ordinal':index+1,'coverage_root':item['coverage_root'],
                'path':item['path'],'source_sha256':item['sha256'],'row_count':item['row_count'],
                'basename_equal':PurePosixPath(item['path']).name == row['source_basename']})
        kind = 'ZERO_ORIGINAL_SHA_MATCH' if not matches else 'ONE_ORIGINAL_SHA_MATCH' if len(matches)==1 else 'MULTIPLE_IDENTICAL_BYTES_LOCATIONS'
        classes[kind] += 1
        output.append({'formal':dict(row),'classification':kind,'matches':matches})
    return {'status':'PASS_ORIGINAL_SHA_COMPARISON_ONLY','formal_source_count':24,'inventory_file_count':32,
        'class_counts':classes,'rows':output,'inventory_references':[
            {'inventory_ordinal':i+1,'path':item['path'],'formal_references':references[i]}
            for i,item in enumerate(files)],'unused_inventory_count':references.count(0),
        'all_formal_bytes_found':classes['ZERO_ORIGINAL_SHA_MATCH']==0,
        'all_physical_locations_unique':classes['ONE_ORIGINAL_SHA_MATCH']==24,
        'normalized_sha_used_for_matching':False,'source_files_opened':False,
        'physical_locations_or_invocations_merged':False,'historical_freeze_certified':False,
        'full_search_cost_certified':False,'training_release':False}


def unique_object(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def pinned_json(path, expected):
    require(sha(expected), 'INPUT_PIN_NOT_FROZEN')
    raw = stable_read(path, 65536)
    require(hashlib.sha256(raw).hexdigest() == expected, 'INPUT_SHA')
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique_object)


def main():
    try:
        require(len(sys.argv)==1, 'FIXED_INPUTS_ONLY')
        projected = pinned_json(PROJECTION, PROJECTION_SHA)
        require(projected['status']=='PASS_BOUND_TRAIN_PROVENANCE_METADATA'
            and projected['training_release'] is False, 'E54_STATUS')
        inventory = pinned_json(INVENTORY, INVENTORY_SHA)
        result = join_sources(projected['provenance']['rows'],inventory['files'])
        result['input_sha256'] = {'e54':PROJECTION_SHA,'e38_summary':INVENTORY_SHA}
        raw = json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        require(len(raw.encode('ascii'))+1 <= 65536, 'OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_ORIGINAL_SHA_COMPARISON","code":"PINNED_METADATA_REJECTED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
