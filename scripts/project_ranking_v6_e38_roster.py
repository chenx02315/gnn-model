"""Fixed TRAIN config projection, never a candidate-quality parser.

Only header names and candidate/h_patterns/m_patterns are decoded. All other
field contents are structurally scanned without capture, decoding or semantic
evaluation. The raw input buffer is retained only for scanning/file hashing.
Selected strings use legacy val.strip() whitespace trimming, retaining leading
zeros; they are not exact raw field bytes. The whole-file SHA binds raw bytes.
Coverage versions remain separate; this is not the E36 24-file inventory or
an attestation that a historical source set preceded outcomes.
"""
from __future__ import print_function
import hashlib
import json
import os
import re
import stat
import sys

MAX_FILE_BYTES=8*1024*1024
MAX_TOTAL_BYTES=40*1024*1024
MAX_FIELD_BYTES=64*1024
MAX_RECORD_BYTES=256*1024
MAX_ROWS=100000
MAX_OUTPUT_BYTES=1024*1024
ALLOWED_HEADERS=frozenset(('candidate','h_patterns','m_patterns','f_patterns','h_cycles','m_cycles',
    'f_cycles','total_cycles','detected_faults','f_minus_one_patterns','f_minus_one_detected',
    'h_result','m_result','f_result','h_fault_sha256','m_fault_sha256','f_fault_sha256','result_status'))
ROOTS=(
    ('aes_core','/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/aes_core/10_coverage95_phase4_v2'),
    ('s13207','/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s13207/10_coverage95_v3_merge_reclassify'),
    ('s15850','/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s15850/10_coverage95_v3_merge_reclassify'),
    ('s35932','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v1'),
    ('s35932','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v2_merge_reclassify'),
    ('s38417','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v1'),
    ('s38417','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v2_merge_reclassify'),
    ('spi','/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/spi/10_coverage95_phase4_v2'))
LAYOUT=(('hf_coarse','HF','02_hf_coarse/measurements.tsv'),
        ('hmf_coarse','HMF','03_hmf_coarse/measurements.tsv'),
        ('hf_refine','HF','04_integer_refine/hf_measurements.tsv'),
        ('hmf_refine','HMF','04_integer_refine/hmf_measurements.tsv'))
SPECS=tuple((circuit,root,alias,scheme,root+'/'+suffix)
            for circuit,root in ROOTS for alias,scheme,suffix in LAYOUT)
_DECIMAL=re.compile(r'[0-9]{1,10}\Z')


class ProjectionError(ValueError):
    pass


def _require(ok,code):
    if not ok: raise ProjectionError(code)


def _project(raw,scheme):
    _require(type(raw) is bytes and 0<len(raw)<=MAX_FILE_BYTES,'FILE_BYTE_BOUND')
    _require(type(scheme) is str and scheme in ('HF','HMF'),'SCHEME')
    header=None
    selected=set()
    rows=[]
    header_sha=None
    # State 0=start, 1=unquoted, 2=quoted, 3=after closing quote.
    state=0
    column=0
    values=[]
    buffer=bytearray()
    field_bytes=record_bytes=0
    record_start=0
    record_data=False
    i=0

    def capture():
        return header is None or column in selected

    def finish_field():
        return bytes(buffer) if capture() else None

    def finish_record(end):
        nonlocal header,selected,header_sha
        _require(record_data,'BLANK_RECORD')
        if header is None:
            try: names=[value.decode('ascii') for value in values]
            except UnicodeError: raise ProjectionError('HEADER_ASCII')
            _require(names and len(names)==len(set(names)) and all(name in ALLOWED_HEADERS for name in names),
                     'UNKNOWN_OR_DUPLICATE_HEADER')
            _require('h_patterns' in names and (scheme=='HF' or 'm_patterns' in names),'REQUIRED_HEADER')
            header=names
            selected={index for index,name in enumerate(names) if name in ('candidate','h_patterns','m_patterns')}
            header_sha=hashlib.sha256(raw[record_start:end]).hexdigest()
        else:
            _require(len(values)==len(header),'RECORD_WIDTH')
            _require(len(rows)<MAX_ROWS,'ROW_BOUND')
            decoded={}
            for index in selected:
                try: decoded[header[index]]=values[index].decode('ascii').strip()
                except UnicodeError: raise ProjectionError('SELECTED_METADATA_ASCII')
            source_row=len(rows)+2
            candidate=decoded.get('candidate','').strip()
            origin='explicit_candidate' if candidate else 'one_based_data_row'
            if not candidate: candidate=str(source_row-1)
            h=decoded['h_patterns']
            m=decoded.get('m_patterns','')
            _require(_DECIMAL.match(candidate) is not None and _DECIMAL.match(h) is not None,'SELECTED_DECIMAL')
            if scheme=='HMF': _require(_DECIMAL.match(m) is not None,'SELECTED_DECIMAL')
            else: _require(m=='' or (_DECIMAL.match(m) is not None and int(m)==0),'HF_M_METADATA')
            rows.append([source_row,candidate,h,m,origin])

    while i<len(raw):
        value=raw[i]
        # CRLF is one record delimiter only outside quotes; quoted bytes are
        # scanned unchanged (unselected values never enter a field buffer).
        endline=state!=2 and value in (10,13)
        consumed=2 if endline and value==13 else 1
        if endline and value==13:
            _require(i+1<len(raw) and raw[i+1]==10,'BARE_CR')
        record_bytes+=consumed
        _require(record_bytes<=MAX_RECORD_BYTES,'RECORD_BYTE_BOUND')
        if endline:
            values.append(finish_field())
            finish_record(i+consumed)
            i+=consumed
            record_start=i
            state=column=field_bytes=record_bytes=0
            values=[]
            buffer=bytearray()
            record_data=False
            continue
        record_data=True
        if state!=2 and value==9:
            values.append(finish_field())
            column+=1
            if header is not None: _require(column<len(header),'RECORD_WIDTH')
            state=field_bytes=0
            buffer=bytearray()
            i+=1
            continue
        field_bytes+=1
        _require(field_bytes<=MAX_FIELD_BYTES,'FIELD_BYTE_BOUND')
        if state==0:
            if value==34: state=2
            else:
                state=1
                if capture(): buffer.append(value)
        elif state==1:
            _require(value!=34,'QUOTE_IN_UNQUOTED_FIELD')
            if capture(): buffer.append(value)
        elif state==2:
            if value==34: state=3
            elif capture(): buffer.append(value)
        else:
            _require(value==34,'AFTER_QUOTE_CHARACTER')
            if capture(): buffer.append(34)
            state=2
        i+=1
    _require(state!=2,'UNTERMINATED_QUOTE')
    if record_data:
        values.append(finish_field())
        finish_record(len(raw))
    _require(header is not None,'MISSING_HEADER')
    return rows,header_sha


def project_bytes(raw,scheme):
    """Return compact logical-row config projection; no aliases/IDs are invented."""
    return _project(raw,scheme)[0]


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,
            getattr(info,'st_mtime_ns',info.st_mtime),getattr(info,'st_ctime_ns',info.st_ctime))


def _regular(info):
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'ORDINARY_SINGLE_LINK_FILE')


def _read(path,remaining):
    _require(os.name=='posix' and hasattr(os,'O_NOFOLLOW') and hasattr(os,'O_DIRECTORY'),'POSIX_DESCRIPTOR_REQUIRED')
    _require(type(path) is str and path.startswith('/') and not path.startswith('//')
             and '\\' not in path and '\x00' not in path,'ABSOLUTE_PATH')
    parts=path.split('/')[1:]
    _require(all(part not in ('','.','..') for part in parts),'PATH_COMPONENT')
    parent=descriptor=None
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        parent=os.open('/',flags)
        for part in parts[:-1]:
            child=os.open(part,flags,dir_fd=parent)
            try: _require(stat.S_ISDIR(os.fstat(child).st_mode),'ORDINARY_ANCESTOR')
            except Exception:
                os.close(child)
                raise
            os.close(parent)
            parent=child
        before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        _regular(before)
        cap=min(MAX_FILE_BYTES,remaining)
        _require(0<before.st_size<=cap,'FILE_OR_TOTAL_BYTE_BOUND')
        descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NONBLOCK',0),dir_fd=parent)
        opened=os.fstat(descriptor)
        _regular(opened)
        _require(_identity(opened)==_identity(before),'OPEN_IDENTITY')
        chunks=[]
        count=0
        digest=hashlib.sha256()
        while count<=cap:
            chunk=os.read(descriptor,min(65536,cap+1-count))
            if not chunk: break
            chunks.append(chunk)
            digest.update(chunk)
            count+=len(chunk)
        after=os.fstat(descriptor)
        last=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        _regular(after)
        _regular(last)
        _require(_identity(before)==_identity(opened)==_identity(after)==_identity(last)
                 and count==opened.st_size and count<=cap,'READ_IDENTITY_OR_SIZE')
        return b''.join(chunks),digest.hexdigest()
    except ProjectionError: raise
    except (OSError,ValueError,TypeError,NotImplementedError): raise ProjectionError('SOURCE_READ_FAILED')
    finally:
        if descriptor is not None: os.close(descriptor)
        if parent is not None: os.close(parent)


def main():
    active_file_index=-1
    try:
        _require(len(sys.argv)==1 and sys.platform=='linux','LINUX_FIXED_STDIN_ONLY')
        import resource
        imposed={}
        for kind,cap in ((resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,20)):
            soft,hard=resource.getrlimit(kind)
            bound=min([cap]+[value for value in (soft,hard) if value!=resource.RLIM_INFINITY])
            resource.setrlimit(kind,(bound,hard))
            imposed['address_space_limit_bytes' if kind==resource.RLIMIT_AS else 'cpu_limit_s']=bound
        imposed['workers']=1
        files=[]
        total_bytes=total_rows=0
        for active_file_index,spec in enumerate(SPECS):
            circuit,root,alias,scheme,path=spec
            raw,digest=_read(path,MAX_TOTAL_BYTES-total_bytes)
            total_bytes+=len(raw)
            rows,header_sha=_project(raw,scheme)
            total_rows+=len(rows)
            _require(total_bytes<=MAX_TOTAL_BYTES and total_rows<=MAX_ROWS,'TOTAL_RESOURCE_BOUND')
            files.append(dict(circuit=circuit,coverage_root=root,stage_alias=alias,path=path,
                sha256=digest,byte_count=len(raw),header_sha256=header_sha,rows=rows))
            del raw
        result=dict(status='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY',files=files,file_count=32,
            coverage_root_count=8,total_bytes=total_bytes,total_rows=total_rows,
            nonselected_values_decoded=False,nonselected_values_captured=False,quality_evaluated=False,
            PASS_or_eligibility_filter_applied=False,coverage_versions_merged=False,
            pre_outcome_certified=False,formal_builder_roots_certified=False,training_release=False,
            source_identity_scope='circuit+coverage_root+stage_alias+candidate_raw',
            E36_inventory_emitted=False,physical_files_written=False,
            source_file_bytes_read_for_sha_and_structure=True,raw_source_tables_persisted=False,
            resource=imposed)
        encoded=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        _require(len(encoded.encode('ascii'))<=MAX_OUTPUT_BYTES,'OUTPUT_BOUND')
        print(encoded)
        return 0
    except ProjectionError as exc:
        print(json.dumps(dict(status='FAIL_CLOSED',code=str(exc),file_index=active_file_index),sort_keys=True))
        return 2
    except Exception:
        print(json.dumps(dict(status='FAIL_CLOSED',code='PROJECTION_FAILURE',file_index=active_file_index),sort_keys=True))
        return 2


if __name__=='__main__': sys.exit(main())
