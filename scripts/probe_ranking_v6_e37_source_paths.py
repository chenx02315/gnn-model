"""Fixed six-TRAIN evidence-path stat only. No file contents or task writes.

Roots are reconstructed from pinned runtime path metadata and prior bindings,
not authenticated formal-builder inputs. Both Phase2 coverage versions stay.
CLI is Linux-only and intended for reviewed stdin execution without deployment.
"""
import json
import os
import stat
import sys

MAX_OUTPUT = 65536
ROOTS = (
    ('aes_core', '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/aes_core/10_coverage95_phase4_v2'),
    ('s13207', '/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s13207/10_coverage95_v3_merge_reclassify'),
    ('s15850', '/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s15850/10_coverage95_v3_merge_reclassify'),
    ('s35932', '/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v1'),
    ('s35932', '/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v2_merge_reclassify'),
    ('s38417', '/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v1'),
    ('s38417', '/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v2_merge_reclassify'),
    ('spi', '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/spi/10_coverage95_phase4_v2'),
)
LAYOUT = (
    ('hf_coarse', '02_hf_coarse/measurements.tsv'),
    ('hmf_coarse', '03_hmf_coarse/measurements.tsv'),
    ('hf_refine', '04_integer_refine/hf_measurements.tsv'),
    ('hmf_refine', '04_integer_refine/hmf_measurements.tsv'),
)
SPECS = tuple((c, root, alias, root+'/'+suffix)
              for c, root in ROOTS for alias, suffix in LAYOUT)


def _parents(path):
    parts = path.split('/')[1:-1]
    return ['/'+'/'.join(parts[:i]) for i in range(1, len(parts)+1)]


def probe(lstat_fn=os.lstat):
    results = []
    cache = {}
    for circuit, root, alias, path in SPECS:
        row = dict(circuit=circuit, coverage_root=root, stage_alias=alias, path=path)
        try:
            for parent in _parents(path):
                if parent not in cache:
                    cache[parent] = lstat_fn(parent)
                if not stat.S_ISDIR(cache[parent].st_mode):
                    raise ValueError('UNSAFE_ANCESTOR')
            info = lstat_fn(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('NOT_REGULAR_SINGLE_LINK')
            if not (0 < info.st_size <= 8*1024*1024):
                raise ValueError('SOURCE_SIZE_BOUND')
            row.update(status='PRESENT_ORDINARY_SIZE_BOUNDED', size_bytes=info.st_size)
        except FileNotFoundError:
            row['status'] = 'MISSING'
        except PermissionError:
            row['status'] = 'DENIED'
        except ValueError as exc:
            row['status'] = str(exc)
        except OSError:
            row['status'] = 'OS_ERROR'
        results.append(row)
    present = sum(r['status']=='PRESENT_ORDINARY_SIZE_BOUNDED' for r in results)
    return dict(status='PASS_PATH_STAT_ONLY' if present==32 else 'PARTIAL_PATH_STAT_ONLY',
        roots=8, files=32, present_ordinary_size_bounded=present, results=results,
        source_file_contents_opened=False, quality_values_accessed=False,
        source_rows_projected=False, remote_task_files_written=False,
        source_hashes_verified=False, formal_builder_roots_certified=False,
        complete_roster_certified=False, training_release=False)


def main():
    if len(sys.argv)!=1 or sys.platform!='linux':
        raise SystemExit('LINUX_FIXED_STDIN_ONLY')
    import resource
    cap=1024*1024*1024
    soft, hard=resource.getrlimit(resource.RLIMIT_AS)
    bounded=min(cap, hard) if hard!=resource.RLIM_INFINITY else cap
    if soft!=resource.RLIM_INFINITY:
        bounded=min(bounded, soft)
    resource.setrlimit(resource.RLIMIT_AS,(bounded,hard))
    cpu_soft,cpu_hard=resource.getrlimit(resource.RLIMIT_CPU)
    cpu_bound=min([20]+[n for n in (cpu_soft,cpu_hard) if n!=resource.RLIM_INFINITY])
    resource.setrlimit(resource.RLIMIT_CPU,(cpu_bound,cpu_hard))
    result=probe()
    result['resource']=dict(address_space_limit_bytes=bounded,cpu_limit_s=cpu_bound,workers=1)
    raw=json.dumps(result,sort_keys=True,separators=(',',':')).encode('ascii')
    if len(raw)>MAX_OUTPUT:
        raise SystemExit('OUTPUT_BOUND')
    print(raw.decode('ascii'))


if __name__=='__main__':
    main()
