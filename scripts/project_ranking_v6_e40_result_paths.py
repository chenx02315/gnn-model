"""Frozen E38 fork: eight selected config/result-PATH declarations only.

Whole raw files transiently enter memory for structure and SHA checks. Only
header names and config/path fields on pinned logical target rows are captured
or decoded. Every other field/row is scanned structurally, never decoded or
evaluated as quality/PASS/eligibility. Result paths are not followed, resolved,
rebased or treated as ownership evidence. E38 remains unchanged.
"""
from __future__ import print_function
import hashlib
import json
import os
import re
import stat
import sys

MAX_FILE_BYTES=64*1024
MAX_TOTAL_BYTES=256*1024
MAX_FIELD_BYTES=64*1024
MAX_RECORD_BYTES=256*1024
MAX_ROWS=1000
MAX_OUTPUT_BYTES=64*1024
ALLOWED_HEADERS=frozenset(('candidate','h_patterns','m_patterns','f_patterns','h_cycles','m_cycles',
    'f_cycles','total_cycles','detected_faults','f_minus_one_patterns','f_minus_one_detected',
    'h_result','m_result','f_result','h_fault_sha256','m_fault_sha256','f_fault_sha256','result_status'))
_BASE='/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/'
_HEADERS=('dbc4f8eefabe7018732e30060f4ceed036c820a1198234f7ea68553a2a8ca433',
          '7d6cf1046fb485cea83248529b46645a748d615440252232ddbf41c62772266e')
_PINS=(
 ('s35932','10_coverage95_v1','5eb75438764668eb991d88dead2cadea4a3932b9bf166773721ca22bbccccc05',1376,4,0,
  [[2,'1','9','','one_based_data_row']]),
 ('s35932','10_coverage95_v2_merge_reclassify','96f387de0b7312e71a459075f61da9e05c813d3252beeebc1dde73ec209465ec',6928,15,1,
  [[2,'1','9','0','explicit_candidate']]),
 ('s38417','10_coverage95_v1','451f78b65ec024c9d5cf4dad814a3580954a29d40dd1648a00d92b3ee6c25c6a',3937,12,0,
  [[9,'8','101','','one_based_data_row'],[11,'10','100','','one_based_data_row'],[12,'11','102','','one_based_data_row']]),
 ('s38417','10_coverage95_v2_merge_reclassify','70588e39da9d34533376eacea306e54dd48155becced2bbee9e31f1b0e7c2467',20678,42,1,
  [[9,'8','101','0','explicit_candidate'],[11,'10','100','0','explicit_candidate'],[12,'11','102','0','explicit_candidate']]))
SPECS=tuple(dict(circuit=circuit,coverage_root=_BASE+circuit+'/'+version,stage_alias='hf_refine',
    path=_BASE+circuit+'/'+version+'/04_integer_refine/hf_measurements.tsv',sha256=digest,
    byte_count=size,header_sha256=_HEADERS[header],expected_rows=count,targets=targets)
    for circuit,version,digest,size,count,header,targets in _PINS)
_DECIMAL=re.compile(r'[0-9]{1,10}\Z')


class ProjectionError(ValueError):
    pass


def _require(ok,code):
    if not ok: raise ProjectionError(code)


def _path_metadata(value):
    _require(len(value)<=4096,'RESULT_PATH_BOUND')
    try: text=value.decode('ascii')
    except UnicodeError: raise ProjectionError('RESULT_PATH_ASCII')
    _require(all(32<=ord(char)<127 for char in text),'RESULT_PATH_CONTROL')
    text=text.strip()
    _require('\\' not in text and all(part not in ('.','..') for part in text.split('/')),
             'RESULT_PATH_TRAVERSAL_OR_BACKSLASH')
    _require(re.match(r'[A-Za-z]:/',text) is None,'RESULT_PATH_WINDOWS_DRIVE')
    return text


def _project(raw,spec):
    _require(type(raw) is bytes and 0<len(raw)<=MAX_FILE_BYTES,'FILE_BYTE_BOUND')
    _require(len(raw)==spec['byte_count'] and hashlib.sha256(raw).hexdigest()==spec['sha256'],'FROZEN_FILE_BYTES_SHA')
    targets={target[0]:target for target in spec['targets']}
    _require(len(targets)==len(spec['targets']) and targets,'TARGET_ROW_DECLARATION')
    _require(list(targets)==sorted(targets),'TARGET_ROW_ORDER')
    header=None
    selected=set()
    rows=[]
    logical_rows=0
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
        return header is None or (logical_rows+2 in targets and column in selected)

    def finish_field():
        return bytes(buffer) if capture() else None

    def finish_record(end):
        nonlocal header,selected,header_sha,logical_rows
        _require(record_data,'BLANK_RECORD')
        if header is None:
            try: names=[value.decode('ascii') for value in values]
            except UnicodeError: raise ProjectionError('HEADER_ASCII')
            _require(names and len(names)==len(set(names)) and all(name in ALLOWED_HEADERS for name in names),
                     'UNKNOWN_OR_DUPLICATE_HEADER')
            _require(all(name in names for name in ('h_patterns','h_result','f_result')),'REQUIRED_HEADER')
            header=names
            selected={index for index,name in enumerate(names) if name in ('candidate','h_patterns','m_patterns','h_result','f_result')}
            header_sha=hashlib.sha256(raw[record_start:end]).hexdigest()
            _require(header_sha==spec['header_sha256'],'FROZEN_HEADER_SHA')
        else:
            _require(len(values)==len(header),'RECORD_WIDTH')
            _require(logical_rows<MAX_ROWS,'ROW_BOUND')
            source_row=logical_rows+2
            logical_rows+=1
            if source_row not in targets: return
            decoded={}
            for index in selected:
                name=header[index]
                if name in ('h_result','f_result'):
                    decoded[name]=_path_metadata(values[index])
                    continue
                try: decoded[name]=values[index].decode('ascii').strip()
                except UnicodeError: raise ProjectionError('SELECTED_METADATA_ASCII')
            candidate=decoded.get('candidate','').strip()
            origin='explicit_candidate' if candidate else 'one_based_data_row'
            if not candidate: candidate=str(source_row-1)
            h=decoded['h_patterns']
            m=decoded.get('m_patterns','')
            _require(_DECIMAL.match(candidate) is not None and _DECIMAL.match(h) is not None,'SELECTED_DECIMAL')
            _require(m=='' or (_DECIMAL.match(m) is not None and int(m)==0),'HF_M_METADATA')
            _require([source_row,candidate,h,m,origin]==targets[source_row],'FROZEN_TARGET_CONFIG')
            rows.append(dict(source_row=source_row,candidate=candidate,h_patterns=h,m_patterns=m,
                             candidate_origin=origin,h_result=decoded['h_result'],f_result=decoded['f_result']))

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
    _require(logical_rows==spec['expected_rows'] and len(rows)==len(targets),'FROZEN_ROW_COUNTS')
    return rows,header_sha,logical_rows


def project_bytes(raw,spec):
    """Return one frozen-file projection; pure tests may supply synthetic pins."""
    rows,header,count=_project(raw,spec)
    return dict(circuit=spec['circuit'],coverage_root=spec['coverage_root'],stage_alias=spec['stage_alias'],
                path=spec['path'],sha256=spec['sha256'],byte_count=len(raw),header_sha256=header,row_count=count,rows=rows)


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


def validate_response(result):
    """Validate parsed JSON only; wrapper separately rejects duplicate keys."""
    try:
        false_flags={'quality_evaluated','result_files_opened','source_origin_assigned','training_release','physical_files_written'}
        top={'status','files','file_count','total_bytes','total_rows','target_rows',
             'source_file_bytes_read_for_sha_and_structure','resource'}|false_flags
        if type(result) is not dict or set(result)!=top: return False
        if result['status']!='PASS_TARGET_RESULT_PATH_METADATA_ONLY': return False
        if any(result[key] is not False for key in false_flags): return False
        if result['source_file_bytes_read_for_sha_and_structure'] is not True: return False
        for key,value in (('file_count',4),('total_bytes',32919),('total_rows',73),('target_rows',8)):
            if type(result[key]) is not int or result[key]!=value: return False
        files=result['files']
        if type(files) is not list or len(files)!=4: return False
        fields={'circuit','coverage_root','stage_alias','path','sha256','byte_count','header_sha256','row_count','rows'}
        row_fields={'source_row','candidate','h_patterns','m_patterns','candidate_origin','h_result','f_result'}
        for item,spec in zip(files,SPECS):
            if type(item) is not dict or set(item)!=fields: return False
            for key in ('circuit','coverage_root','stage_alias','path','sha256','header_sha256'):
                if type(item[key]) is not str or item[key]!=spec[key]: return False
            if type(item['byte_count']) is not int or item['byte_count']!=spec['byte_count']: return False
            if type(item['row_count']) is not int or item['row_count']!=spec['expected_rows']: return False
            if type(item['rows']) is not list or len(item['rows'])!=len(spec['targets']): return False
            for row,target in zip(item['rows'],spec['targets']):
                if type(row) is not dict or set(row)!=row_fields: return False
                if type(row['source_row']) is not int: return False
                if any(type(row[key]) is not str for key in row_fields-{'source_row'}): return False
                if [row['source_row'],row['candidate'],row['h_patterns'],row['m_patterns'],row['candidate_origin']]!=target:
                    return False
                for key in ('h_result','f_result'):
                    if len(row[key])>4096 or _path_metadata(row[key].encode('ascii'))!=row[key]: return False
        resource=result['resource']
        return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
            and type(resource['address_space_limit_bytes']) is int and 0<resource['address_space_limit_bytes']<=1024**3
            and type(resource['cpu_limit_s']) is int and 0<resource['cpu_limit_s']<=20
            and type(resource['workers']) is int and resource['workers']==1)
    except (ProjectionError,TypeError,ValueError,UnicodeError,RecursionError): return False


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
            raw,digest=_read(spec['path'],MAX_TOTAL_BYTES-total_bytes)
            total_bytes+=len(raw)
            _require(digest==spec['sha256'],'FROZEN_FILE_BYTES_SHA')
            projected=project_bytes(raw,spec)
            total_rows+=projected['row_count']
            _require(total_bytes<=MAX_TOTAL_BYTES and total_rows<=MAX_ROWS,'TOTAL_RESOURCE_BOUND')
            files.append(projected)
            del raw
        _require(total_bytes==32919 and total_rows==73 and sum(len(item['rows']) for item in files)==8,'FROZEN_TOTAL_COUNTS')
        result=dict(status='PASS_TARGET_RESULT_PATH_METADATA_ONLY',files=files,file_count=4,
            total_bytes=total_bytes,total_rows=total_rows,target_rows=8,
            quality_evaluated=False,result_files_opened=False,source_origin_assigned=False,
            training_release=False,physical_files_written=False,
            source_file_bytes_read_for_sha_and_structure=True,resource=imposed)
        _require(validate_response(result),'OUTPUT_SCHEMA')
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
