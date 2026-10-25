"""Pure classification helpers, not a new execution or warning-acceptance policy.

Socket support is metadata-only for an owned, single-link PVM runtime endpoint
inside the already anchored case scratch. Never open/connect/follow that leaf.
Warning inventory does not approve any diagnostic or assert D95 correctness.
"""
import hashlib
import re
import stat


def classify_leaf(info,name,uid,hostname):
    if stat.S_ISREG(info.st_mode) and info.st_nlink==1:
        return 'REGULAR_SINGLE_LINK'
    pattern=r'pvmtmp\.%d\.([1-9][0-9]{0,9})\.%s\.[0-9]{1,4}'%(uid,re.escape(hostname))
    match=re.fullmatch(pattern,name) if type(name) is str and len(name)<=255 else None
    if (stat.S_ISSOCK(info.st_mode) and info.st_nlink==1 and info.st_uid==uid
            and info.st_size==0 and match is not None and int(match.group(1))<2**31):
        return 'OWNED_PVM_UNIX_SOCKET_METADATA_ONLY'
    raise ValueError('SCRATCH_UNREVIEWED_LEAF_TYPE_OR_IDENTITY')


def warning_inventory(log):
    if type(log) is not bytes or len(log)>16777216:
        raise ValueError('BOUNDED_TOOL_LOG_REQUIRED')
    rules=(
        ('LIBRARY_ATTRIBUTE_MODELS_UNMATCHED',rb'read_verilog must be used to read in modules \(or read_cell_library to read in models\)'),
        ('FN1',rb'Rule FN1 violation occurs ([0-9]{1,9}) times'),
        ('FN4',rb'Rule FN4 violation occurs ([0-9]{1,9}) times'),
        ('D7_STABLE_HIGH_CLOCK_PORTS',rb'([0-9]{1,9}) edge-triggered clock ports set to stable high\. \(D7\)'),
        ('EDT_INITIALIZATION_OVERHEAD_PERCENT',rb'EDT initialization cycles increase each pattern size by ([0-9]{1,3})%\.'))
    rows=[];fault_import_seen=False;imports=0
    for line_number,line in enumerate(log.splitlines(),1):
        if re.match(rb'^\s*//\s*command:\s*read_faults\b',line):
            fault_import_seen=True;imports+=1
        if not re.search(rb'(?<![a-z0-9_])warning(?![a-z0-9_])',line,re.I):
            continue
        if len(rows)>=128:raise ValueError('WARNING_INVENTORY_BOUND')
        category='UNKNOWN';count=None
        for key,pattern in rules:
            match=re.search(pattern,line,re.I)
            if match is not None:
                category=key
                if match.groups():count=int(match.group(1))
                break
        rows.append(dict(line_number=line_number,category=category,reported_number=count,
            phase='FAULT_IMPORT_OR_LATER' if fault_import_seen else 'STARTUP_BEFORE_FAULT_IMPORT',
            message_sha256=hashlib.sha256(line).hexdigest(),reviewed_for_acceptance=False))
    return dict(warnings=rows,top_level_fault_import_commands_seen=imports,
        warning_acceptance_policy_changed=False,d95_verified=False)
