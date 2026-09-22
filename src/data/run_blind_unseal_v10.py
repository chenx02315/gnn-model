#!/usr/bin/env python3
"""Sealed v10 BLIND runtime auditor; stdlib-only, operational one-shot control."""
from __future__ import print_function
import csv, hashlib, json, os, re, subprocess, sys, tempfile

LAYOUTS = (("01_single_boundaries", "measurements.tsv", "single"), ("02_hf_coarse", "measurements.tsv", "hf"),
           ("03_hmf_coarse", "measurements.tsv", "hmf"), ("04_integer_refine", "hf_measurements.tsv", "hf"),
           ("04_integer_refine", "hmf_measurements.tsv", "hmf"), ("05_repeatability", "measurements.tsv", "repeatability"))
FORMAL_STAGES = set(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
SHA = re.compile(r"^[0-9a-f]{64}$")
# The runner has two intentionally disjoint read domains.  This list is the
# *only* pre-CONSUMED domain: immutable bundle-control evidence.  Do not turn
# this into a prefix check; a measurement table or a driver log must never
# become readable merely because it lives below the bundle root.
CONTROL_ARTIFACTS = frozenset((
    "contracts/blind_runtime_unseal_v10.json",
    "contracts/blind_runtime_unseal_job_v10_template.json",
    "contracts/blind_runtime_unseal_job_v10.json",
    "contracts/blind_runtime_unseal_registration_v10.json",
    "contracts/blind_unseal_independent_review_v10.json",
    "contracts/blind_runtime_unseal_protocol_v7.json",
    "contracts/data_split_v1.json",
    "data/manifests/blind_gate_snapshot_v1.json",
    "data/manifests/blind_input_inventory_freeze_v1.json",
    "data/manifests/lsf_probe_v8_20260910.json",
    "src/data/build_blind_unseal_lifecycle_v10.py",
    "src/data/run_blind_unseal_v10.py",
    "src/data/validate_blind_unseal_registration_v10.py",
    "src/data/validate_blind_unseal_scheduler_audit_v10.py",
))
MARKERS = {"run_id": re.compile(r"^MAPPED_COMMON_ATPG_RUN_ID=(.+)$", re.M), "mode": re.compile(r"^MAPPED_COMMON_ATPG_MODE=(.+)$", re.M), "atpg_status": re.compile(r"^MAPPED_COMMON_ATPG_STATUS=(.+)$", re.M), "user_s": re.compile(r"^\s*User time \(seconds\):\s*(\S+)", re.M), "system_s": re.compile(r"^\s*System time \(seconds\):\s*(\S+)", re.M), "elapsed": re.compile(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M), "exit_status": re.compile(r"^\s*Exit status:\s*(\S+)", re.M)}
TIMEOUT = re.compile(r"(?:^|\n)(?:TIMEOUT|TIMED_OUT|KILLED_FOR_TIMEOUT)(?:\b|=)", re.I)
EXPECTED_BUNDLE_ROOT = "/temp/jiangchuanc/blind_runtime_unseal_v10_bundle"
EXPECTED_EXTERNAL_CONTROL_MANIFEST = "/temp/jiangchuanc/blind_runtime_unseal_v10_control_manifest.json"
EXPECTED_COMMAND_ARGV = ["python3", EXPECTED_BUNDLE_ROOT + "/src/data/run_blind_unseal_v10.py", "--bundle-root", EXPECTED_BUNDLE_ROOT]
CONTROL_MANIFEST_PATHS = frozenset((
    "contracts/blind_runtime_unseal_protocol_v7.json",
    "contracts/data_split_v1.json",
    "data/manifests/blind_gate_snapshot_v1.json",
    "data/manifests/blind_input_inventory_freeze_v1.json",
    "data/manifests/lsf_probe_v8_20260910.json",
    "src/data/build_blind_unseal_lifecycle_v10.py",
    "src/data/run_blind_unseal_v10.py",
    "src/data/validate_blind_unseal_registration_v10.py",
    "src/data/validate_blind_unseal_scheduler_audit_v10.py",
))
# This is deliberately an in-memory object, rather than a serialisable
# string.  The CONSUMED file is durable audit evidence, but it is not a
# capability: a caller which merely writes a look-alike JSON file must not be
# able to invoke source readers through an imported module.  This protects the
# supported Python API against accidental/import bypasses; it is not presented
# as an OS security boundary against the same user reading source files.
_ACTIVE_SOURCE_CAPABILITY = None

class Refusal(Exception): pass

def value(row, key): return (row.get(key) or "").strip()
def basename(path):
    name = os.path.basename((path or "").replace("\\", "/").rstrip("/"))
    for suffix in (".driver.log", ".log", ".tsv", ".csv"):
        if name.endswith(suffix): return name[:-len(suffix)]
    return name
def source_state(row): return value(row, "result_status") or value(row, "status")
def source_rows(kind, row):
    if kind == "single": return [(value(row, "mode"), value(row, "result_directory") or value(row, "result"))]
    if kind == "repeatability":
        modes = {"FullScan-F4": ("F",), "ComScan-H64": ("H",), "H64-F4": ("H", "F"), "H64-M16-F4": ("H", "M", "F")}.get(value(row, "scheme"), ())
        return [(mode, "") for mode in modes]
    return [(mode, value(row, mode.lower() + "_result")) for mode in (("H", "F") if kind == "hf" else ("H", "M", "F"))]
def is_not_run(row, mode, marker):
    state = source_state(row)
    if "TARGET_BEFORE_F" in state or "INFEASIBLE_AT_D95" in state: return mode == "F"
    return not marker and ("NOT_RUN" in state or "PRUNED_OR_UNREACHED" in state)
def table_paths(root, guard=None):
    """Enumerate BLIND measurement tables only after the CONSUMED guard."""
    _require_source_guard(guard)
    for directory, filename, kind in LAYOUTS:
        path=os.path.join(root,directory,filename)
        if os.path.isfile(path): yield directory, filename, kind, path

def sha_file(path):
    """Retired generic reader: it must not bypass the sealed read domains."""
    raise Refusal("CONTROL_READER_REQUIRED")

def read_json(path):
    """Retired generic reader: it must not bypass the sealed read domains."""
    raise Refusal("CONTROL_READER_REQUIRED")

def _control_relative(relative):
    if not isinstance(relative,str) or not relative or os.path.isabs(relative):
        raise Refusal("CONTROL_PATH_INVALID")
    normalized=relative.replace("\\","/")
    if normalized.startswith("/") or any(part in ("", ".", "..") for part in normalized.split("/")):
        raise Refusal("CONTROL_PATH_INVALID")
    if normalized not in CONTROL_ARTIFACTS: raise Refusal("CONTROL_PATH_NOT_WHITELISTED")
    return normalized

def _control_path(root, relative):
    relative=_control_relative(relative); bundle=os.path.realpath(root)
    if not os.path.isdir(bundle) or os.path.islink(bundle): raise Refusal("CONTROL_ROOT_INVALID")
    candidate=os.path.join(bundle,*relative.split("/")); current=bundle
    for component in relative.split("/"):
        current=os.path.join(current,component)
        # lstat is deliberately before any open/hash; a symlink may otherwise
        # point a nominal control filename at a Phase2/3/4 source tree.
        if os.path.islink(current): raise Refusal("CONTROL_PATH_SYMLINK")
    if not os.path.isfile(candidate): raise Refusal("CONTROL_PATH_MISSING")
    resolved=os.path.realpath(candidate)
    if os.path.commonpath((bundle,resolved)) != bundle: raise Refusal("CONTROL_PATH_ESCAPE")
    return candidate

def control_sha_file(root, relative):
    path=_control_path(root,relative); h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def control_read_bytes(root, relative):
    with open(_control_path(root,relative),"rb") as f: return f.read()

def control_read_json(root, relative):
    with open(_control_path(root,relative),encoding="utf-8") as f: return json.load(f)

def _source_sha_file(path, guard):
    """Hash a Phase2/3/4 source file after verifying the exact guard."""
    _require_source_guard(guard)
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()
def sha_lines(lines): return hashlib.sha256("".join(x+"\n" for x in sorted(set(lines))).encode("utf-8")).hexdigest()
def wall(text):
    try:
        x=text.split(":")
        return "%.3f" % ((float(x[0])*60+float(x[1])) if len(x)==2 else (float(x[0])*3600+float(x[1])*60+float(x[2]))) if len(x) in (2,3) else ""
    except ValueError: return ""
def _require_source_guard(guard):
    if not isinstance(guard,tuple) or len(guard)!=4: raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    path,contract_sha,tool_sha,capability=guard
    if capability is not _ACTIVE_SOURCE_CAPABILITY: raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    if not os.path.isfile(path) or os.path.islink(path): raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    try:
        with open(path,encoding="utf-8") as f: marker=json.load(f)
    except (OSError,ValueError): raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    if marker!={"schema_version":"blind-runtime-unseal-consumed-v10","status":"CONSUMED","contract_sha256":contract_sha,"tool_set_sha256":tool_sha}: raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")

def _scan_log(path,guard):
    _require_source_guard(guard)
    digest=hashlib.sha256(); found={key:"" for key in MARKERS}; timed_out=False
    with open(path,"rb") as f:
        for raw in f:
            digest.update(raw); line=raw.decode("utf-8","replace")
            for key, pattern in MARKERS.items():
                if not found[key]:
                    match=pattern.search(line)
                    if match: found[key]=match.group(1).strip()
            if not timed_out and TIMEOUT.search(line): timed_out=True
    return found,digest.hexdigest(),timed_out
def _attempt_rows(log_root, meta, guard):
    _require_source_guard(guard)
    roots=[]
    for parent, dirs, files in os.walk(log_root):
        dirs.sort(); roots.extend(os.path.join(parent,x) for x in sorted(files) if x.endswith(".driver.log"))
    rows=[]; root_real=os.path.realpath(log_root)
    for path in roots:
        found,digest,timed=_scan_log(path,guard); rel=os.path.relpath(os.path.realpath(path),root_real).replace(os.sep,"/")
        run=found["run_id"] or os.path.basename(path)[:-11]; mode=found["mode"] or (run[0] if run[:2] in ("H_","M_","F_") else "")
        row={"run_id":run,"run_id_source":"log_marker" if found["run_id"] else "filename","retry_group_id":run,"retry_order":"","retry_order_status":"UNKNOWN_ORDER","mode":mode,"stage":rel.split("/")[-2] if "/" in rel else "","source_log_path":rel,"source_log_sha256":digest,"source_artifact_sha256":digest,"phase":meta["phase"],"cohort":meta["cohort"],"environment_cohort":meta["environment_cohort"],"wall_s":wall(found["elapsed"]),"exit_status":found["exit_status"],"atpg_status":found["atpg_status"],"timeout_status":"TIMEOUT_MARKER" if timed else "unknown"}
        identity="|".join((digest,rel,run)); row["attempt_id"]="attempt_"+hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        if timed: row["parse_status"]="TIMEOUT"; row["attempt_outcome_class"]="TIMEOUT"
        elif not row["wall_s"]: row["parse_status"]="MISSING_ELAPSED"; row["attempt_outcome_class"]="UNKNOWN"
        elif not row["exit_status"]: row["parse_status"]="MISSING_EXIT"; row["attempt_outcome_class"]="UNKNOWN"
        elif row["exit_status"]!="0": row["parse_status"]="NONZERO_EXIT"; row["attempt_outcome_class"]="NONZERO_EXIT"
        elif row["atpg_status"] and row["atpg_status"]!="PASS": row["parse_status"]="ATPG_STATUS_FAIL"; row["attempt_outcome_class"]="TOOL_FAIL"
        else: row["parse_status"]="PASS" if row["atpg_status"]=="PASS" else "PASS_RUNTIME_OUTCOME_PENDING"; row["attempt_outcome_class"]="SUCCESS" if row["atpg_status"]=="PASS" else "UNKNOWN_LEGACY_STATUS"
        rows.append(row)
    if len(rows)!=len(set(x["attempt_id"] for x in rows)) or any(not x["source_log_sha256"] or not x["phase"] or not x["cohort"] or not x["environment_cohort"] for x in rows): raise ValueError("ATTEMPT_INTEGRITY")
    return rows
def _inventory(root, rels, prefix, guard):
    _require_source_guard(guard)
    lines=[]
    for rel in rels:
        path=os.path.join(root,*rel.split("/"))
        if not os.path.isfile(path) or os.path.islink(path): raise ValueError("INPUT_FILE_MISSING_OR_SYMLINK")
        lines.append(_source_sha_file(path,guard)+"  "+prefix+rel+"\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
def _log_inventory(root,guard):
    _require_source_guard(guard)
    rels=[]
    for parent,dirs,files in os.walk(root):
        dirs.sort(); rels.extend(os.path.relpath(os.path.join(parent,x),root).replace(os.sep,"/") for x in sorted(files) if x.endswith(".driver.log"))
    return _inventory(root,sorted(rels),"./",guard),len(rels)
def _audit_circuit(entry, measurement_files, guard):
    _require_source_guard(guard)
    if _inventory(entry["measurements_root"],measurement_files,"",guard)!=entry["measurement_file_set_sha256"]: raise ValueError("MEASUREMENT_SOURCE_SET_CHANGED")
    log_sha,count=_log_inventory(entry["log_root"],guard)
    if log_sha!=entry["driver_log_file_set_sha256"] or count!=entry["expected_driver_log_count"]: raise ValueError("DRIVER_SOURCE_SET_CHANGED")
    attempts=_attempt_rows(entry["log_root"],entry,guard); by_source={}; by_run={}
    for x in attempts:
        by_source.setdefault((x["mode"],basename(x["source_log_path"])),[]).append(x); by_run.setdefault((x["mode"],x["run_id"]),[]).append(x)
    refs=[]; actions=[]; artifacts=[]; action_refs={}; matched_attempts=[]; cross_stage=0
    for stage,_filename,kind,path in table_paths(entry["measurements_root"],guard):
        artifacts.append(stage+":"+_source_sha_file(path,guard))
        with open(path,encoding="utf-8",newline="") as f:
            for row_number,row in enumerate(csv.DictReader(f,delimiter="\t"),2):
                action=""
                if kind in ("hf","hmf"):
                    h=value(row,"h_patterns"); m=value(row,"m_patterns") if kind=="hmf" else ""
                    if not h or (kind=="hmf" and not m): raise ValueError("INVALID_ACTION_KEY")
                    action="|".join((entry["circuit"],"HF" if kind=="hf" else "HMF",h,m)); actions.append(action)
                for mode,result in source_rows(kind,row):
                    marker=basename(result)
                    if kind!="repeatability" and is_not_run(row,mode,marker): status="NOT_RUN"
                    elif not marker: status="NO_RESULT_PATH" if kind=="repeatability" else "MISSING_RESULT_PATH"
                    else:
                        matches=by_source.get((mode,marker),[]) or by_run.get((mode,marker),[])
                        # Coverage is for an actual ATPG wall-runtime label.  A
                        # failed/timeout attempt with a measured wall time stays
                        # chargeable; an attempt with no elapsed wall time cannot
                        # satisfy R07, irrespective of exit/outcome.
                        status="UNIQUE" if len(matches)==1 and matches[0].get("wall_s") else ("MISSING_RUNTIME" if len(matches)==1 else ("MISSING" if not matches else "AMBIGUOUS"))
                    if stage in FORMAL_STAGES and status not in ("NOT_RUN","NO_RESULT_PATH"):
                        refs.append(status)
                        if action: action_refs.setdefault(action,[]).append(status)
                        if status == "UNIQUE":
                            # A real attempt can be a shared baseline for multiple
                            # measurement references.  This is incidence, not a
                            # one-to-one constraint; preserve every reference.
                            attempt=(by_source.get((mode,marker),[]) or by_run.get((mode,marker),[]))[0]
                            matched_attempts.append(attempt["attempt_id"])
                            if attempt.get("stage") and attempt["stage"] != stage: cross_stage += 1
    unique=refs.count("UNIQUE"); missing=sum(x in ("MISSING","MISSING_RUNTIME","MISSING_RESULT_PATH") for x in refs); ambiguous=refs.count("AMBIGUOUS")
    if unique+missing+ambiguous!=len(refs): raise ValueError("UNCLASSIFIED_JOIN_STATUS")
    if not actions: raise ValueError("EMPTY_ACTION_SPACE")
    eligible=sorted(set(actions)); per_action={"all_unique_action_count":sum(bool(action_refs.get(a)) and all(s=="UNIQUE" for s in action_refs[a]) for a in eligible),"eligible_action_count":len(eligible),"formal_action_count":len(set(actions)),"attempt_reference_count":len(refs)}
    return {"circuit":entry["circuit"],"executed_stage_reference_count":len(refs),"unique_runtime_join_count":unique,"missing_runtime_join_count":missing,"ambiguous_runtime_join_count":ambiguous,"coverage_rate":0.0 if not refs else float(unique)/len(refs),"distinct_runtime_attempt_count":len(set(matched_attempts)),"cross_stage_reference_count":cross_stage,"frozen_runtime_eligible_action_space_sha256":sha_lines(eligible),"source_artifact_set_sha256":sha_lines(artifacts+["attempt:"+x["source_artifact_sha256"] for x in attempts]),"action_coverage_summary":per_action}
def json_bytes(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2).encode("utf-8")+b"\n"
def fsync_dir(path):
    if os.name!="nt":
        fd=os.open(path,os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
def exclusive(path,payload):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as f: f.write(payload); f.flush(); os.fsync(f.fileno())
    fsync_dir(os.path.dirname(os.path.abspath(path)))
def atomic(path,payload):
    fd,tmp=tempfile.mkstemp(prefix=".v10-",dir=os.path.dirname(path))
    try:
        with os.fdopen(fd,"wb") as f: f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path); fsync_dir(os.path.dirname(path))
    except Exception:
        if os.path.exists(tmp): os.unlink(tmp)
        raise
def verify_release(contract,contract_sha,tool_sha,out):
    paths={x:os.path.join(out,x) for x in ("CONSUMED","receipt.json","receipt.json.sha256","RELEASED")}
    if not all(os.path.isfile(x) and not os.path.islink(x) for x in paths.values()): return False
    try:
        with open(paths["CONSUMED"],encoding="utf-8") as f: consumed=json.load(f)
        with open(paths["receipt.json"],encoding="utf-8") as f: receipt=json.load(f)
        with open(paths["RELEASED"],encoding="utf-8") as f: released=json.load(f)
        with open(paths["receipt.json.sha256"],encoding="ascii") as f: side=f.read().strip().split()
    except (OSError,ValueError): return False
    digest=hashlib.sha256()
    with open(paths["receipt.json"],"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): digest.update(block)
    dig=digest.hexdigest()
    if side != [dig,"receipt.json"] or consumed!={"schema_version":"blind-runtime-unseal-consumed-v10","status":"CONSUMED","contract_sha256":contract_sha,"tool_set_sha256":tool_sha} or released!={"schema_version":"blind-runtime-unseal-release-v10","status":"RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING","contract_sha256":contract_sha,"receipt_sha256":dig}: return False
    return verify_receipt(contract,contract_sha,tool_sha,receipt)

def verify_receipt(contract,contract_sha,tool_sha,receipt):
    """Validate a complete receipt in memory before any release file exists."""
    rows=receipt.get("circuits",[])
    envelope={"schema_version","status","formal_runtime_membership_sha256","method_registry_sha256","tool_set_sha256","contract_sha256","circuits","failure_code"}
    if set(receipt)!=envelope or receipt.get("schema_version")!="blind-runtime-unseal-receipt-v10" or receipt.get("formal_runtime_membership_sha256")!=contract["scope"].get("formal_runtime_membership_sha256") or receipt.get("method_registry_sha256")!=contract["scope"].get("method_registry_sha256") or receipt.get("tool_set_sha256")!=tool_sha or receipt.get("contract_sha256")!=contract_sha: return False
    if receipt.get("status")=="PASS":
        required={"circuit","executed_stage_reference_count","unique_runtime_join_count","missing_runtime_join_count","ambiguous_runtime_join_count","coverage_rate","distinct_runtime_attempt_count","cross_stage_reference_count","frozen_runtime_eligible_action_space_sha256","source_artifact_set_sha256","action_coverage_summary"}
        return receipt.get("failure_code") is None and [x.get("circuit") for x in rows]==contract["scope"]["blind_circuits"] and all(set(x)==required and x["unique_runtime_join_count"]+x["missing_runtime_join_count"]+x["ambiguous_runtime_join_count"]==x["executed_stage_reference_count"] and x["missing_runtime_join_count"]==0 and x["ambiguous_runtime_join_count"]==0 and x["coverage_rate"]==1.0 and x["action_coverage_summary"].get("eligible_action_count",0)>0 and x["action_coverage_summary"].get("all_unique_action_count")==x["action_coverage_summary"].get("eligible_action_count") and SHA.match(x["frozen_runtime_eligible_action_space_sha256"] or "") and SHA.match(x["source_artifact_set_sha256"] or "") for x in rows)
    return receipt.get("status")=="FAIL" and rows==[] and receipt.get("failure_code") in {"SEALED_AUDIT_FAILED","INPUT_INVENTORY_DRIFT","ATTEMPT_INTEGRITY_FAILURE","R06_R07_FAILED"}
def git_bytes(root,*args):
    try: return subprocess.check_output(["git","-C",root]+list(args),stderr=subprocess.STDOUT)
    except (OSError,subprocess.CalledProcessError): raise Refusal("GIT_VERIFICATION_FAILED")
def git_text(root,*args): return git_bytes(root,*args).decode("ascii").strip()
def require_digest(value, code):
    if value == "PENDING_REGISTRATION" or value == "PENDING_FINAL_DIGEST": raise Refusal("PENDING_SENTINEL_"+code)
    if not SHA.match(value or ""): raise Refusal("DIGEST_FORMAT_"+code)

def verify_external_control_manifest(root, reviewed_commit, manifest_path, expected_digest):
    """Re-read the external pre-submission manifest at execution time."""
    if manifest_path != EXPECTED_EXTERNAL_CONTROL_MANIFEST or not os.path.isabs(manifest_path):
        raise Refusal("EXTERNAL_MANIFEST_PATH")
    if os.path.islink(manifest_path) or os.path.realpath(manifest_path) != manifest_path or not os.path.isfile(manifest_path):
        raise Refusal("EXTERNAL_MANIFEST_FILE")
    try:
        with open(manifest_path,"rb") as stream: raw=stream.read()
        manifest=json.loads(raw.decode("utf-8"))
    except (OSError,UnicodeDecodeError,ValueError):
        raise Refusal("EXTERNAL_MANIFEST_PARSE")
    if hashlib.sha256(raw).hexdigest()!=expected_digest: raise Refusal("EXTERNAL_MANIFEST_DIGEST")
    if set(manifest)!={"schema_version","bundle_root","freeze_commit","files"} or manifest.get("schema_version")!="blind-runtime-unseal-control-manifest-v10" or manifest.get("bundle_root")!=root or manifest.get("freeze_commit")!=reviewed_commit:
        raise Refusal("EXTERNAL_MANIFEST_BINDING")
    files=manifest.get("files")
    if not isinstance(files,list) or len(files)!=len(CONTROL_MANIFEST_PATHS): raise Refusal("EXTERNAL_MANIFEST_FILE_COUNT")
    by_path={}
    for item in files:
        if not isinstance(item,dict) or set(item)!={"path","sha256"}: raise Refusal("EXTERNAL_MANIFEST_FILE_FIELDS")
        relative=item.get("path"); digest=item.get("sha256")
        if not isinstance(relative,str) or relative not in CONTROL_MANIFEST_PATHS or relative in by_path or not SHA.match(digest or ""):
            raise Refusal("EXTERNAL_MANIFEST_FILE_ENTRY")
        by_path[relative]=digest
    if set(by_path)!=CONTROL_MANIFEST_PATHS: raise Refusal("EXTERNAL_MANIFEST_PATH_SET")
    for relative,digest in sorted(by_path.items()):
        if control_sha_file(root,relative)!=digest: raise Refusal("EXTERNAL_MANIFEST_CONTROL_DIGEST")
    return True

def validate_bundle(root):
    contract_rel="contracts/blind_runtime_unseal_v10.json"; contract=control_read_json(root,contract_rel); csha=control_sha_file(root,contract_rel)
    # The contract is finalized once, immediately after the held-job capture.
    # Registration and independent review are proven by their separately
    # receipt-bound artifacts below; changing the contract status afterwards
    # would invalidate the registration receipt and recreate a digest cycle.
    if contract.get("status") != "FINAL_HELD_UNSEAL_REVIEW_REQUIRED": raise Refusal("PENDING_SENTINEL_CONTRACT")
    job_rel=contract["inputs"]["job_spec"]; job_sha=control_sha_file(root,job_rel)
    job=control_read_json(root,job_rel); template_rel=contract["job_template"]["path"]; require_digest(contract["job_template"]["sha256"],"TEMPLATE")
    template_sha=control_sha_file(root,template_rel)
    if template_sha!=contract["job_template"]["sha256"] or job.get("job_template_sha256")!=template_sha: raise Refusal("JOB_TEMPLATE_DIGEST")
    job_fields={"schema_version","status","contract_sha256","job_template_sha256","registration_receipt","registration_receipt_sha256","registration","measurement_files","circuits","output_root"}
    template_fields={"schema_version","status","registration","measurement_files","circuits","template_rule","lifecycle"}
    if set(job)!=job_fields or set(control_read_json(root,template_rel))!=template_fields: raise Refusal("JOB_OR_TEMPLATE_FIELDS")
    if job.get("schema_version")!="blind-runtime-unseal-job-v10" or job.get("status")!="REGISTERED_HELD" or job.get("contract_sha256")!=csha: raise Refusal("JOB_CONTRACT_BINDING")
    expected_measurements=[directory+"/"+filename for directory,filename,_kind in LAYOUTS]
    if job.get("measurement_files")!=expected_measurements: raise Refusal("MEASUREMENT_FILES_LAYOUT_DRIFT")
    if not isinstance(job.get("circuits"),list) or not job["circuits"]: raise Refusal("EMPTY_CIRCUITS")
    expected_names=contract.get("scope",{}).get("blind_circuits")
    if [entry.get("name") if isinstance(entry,dict) else None for entry in job["circuits"]]!=expected_names: raise Refusal("CIRCUIT_SCOPE_ORDER")
    roots=[]
    for entry in job["circuits"]:
        if set(entry)!={"name","root"} or not isinstance(entry["root"],str) or not entry["root"] or not os.path.isabs(entry["root"]): raise Refusal("CIRCUIT_ENTRY_SCHEMA")
        roots.append(entry["root"])
    if len(roots)!=len(set(roots)): raise Refusal("CIRCUIT_ROOT_NOT_UNIQUE")
    template_final=control_read_json(root,template_rel)
    if job.get("registration")!=template_final.get("registration"): raise Refusal("JOB_TEMPLATE_REGISTRATION_BINDING")
    if job.get("measurement_files")!=template_final.get("measurement_files") or job.get("circuits")!=template_final.get("circuits"): raise Refusal("JOB_TEMPLATE_PAYLOAD_BINDING")
    registration_rel=job["registration_receipt"]; require_digest(job["registration_receipt_sha256"],"REGISTRATION")
    if control_sha_file(root,registration_rel)!=job["registration_receipt_sha256"]: raise Refusal("REGISTRATION_DIGEST")
    registration=control_read_json(root,registration_rel); required=("schema_version","status","job_id","owner","submission_host","submit_time_raw","reviewed_commit","contract_sha256","protocol_sha256","gate_snapshot_sha256","runner_sha256","job_template_sha256","normalized_argv","normalized_argv_sha256","queue","resource_request","cwd","stdout_path","stderr_path","raw_bjobs_capture_sha256","raw_global_bjobs_capture_sha256","raw_bjobs_al_capture_sha256","external_control_manifest_path","external_control_manifest_sha256","specified_cwd")
    template=job.get("registration",{})
    if job.get("status")!="REGISTERED_HELD" or set(registration)!=set(required) or registration.get("schema_version")!="blind-runtime-unseal-registration-v10" or registration.get("status")!="REGISTERED_HELD" or template.get("initial_scheduler_state")!="PSUSP" or any(template.get(k) is not False for k in ("array_allowed","retry_allowed","requeue_allowed","rerun_allowed")):
        raise Refusal("REGISTRATION_SCHEMA")
    for key in ("job_id","owner","submission_host","submit_time_raw","reviewed_commit","queue","resource_request","cwd","stdout_path","stderr_path"):
        if registration.get(key) in (None,""): raise Refusal("REGISTRATION_FIELD_"+key.upper())
    if registration.get("job_id") != str(template.get("job_id")) or registration.get("reviewed_commit") != template.get("git_commit") or registration.get("normalized_argv") != template.get("command_argv") or registration.get("normalized_argv") != EXPECTED_COMMAND_ARGV:
        raise Refusal("REGISTRATION_TEMPLATE_MAPPING")
    argv_digest=hashlib.sha256(json.dumps(registration["normalized_argv"],ensure_ascii=True,separators=(",",":")).encode("utf-8")).hexdigest()
    if registration.get("normalized_argv_sha256") != argv_digest or not all(isinstance(x,str) and x and x==x.strip() and "\n" not in x and "\r" not in x and "^" not in x for x in registration["normalized_argv"]): raise Refusal("REGISTRATION_ARGV")
    if registration.get("cwd") != EXPECTED_BUNDLE_ROOT or registration.get("specified_cwd") != EXPECTED_BUNDLE_ROOT: raise Refusal("REGISTRATION_ABSOLUTE_CWD")
    if registration.get("external_control_manifest_path") != EXPECTED_EXTERNAL_CONTROL_MANIFEST: raise Refusal("REGISTRATION_EXTERNAL_MANIFEST_PATH")
    for key in ("contract_sha256","protocol_sha256","gate_snapshot_sha256","runner_sha256","job_template_sha256","raw_bjobs_capture_sha256","raw_global_bjobs_capture_sha256","raw_bjobs_al_capture_sha256","external_control_manifest_sha256"):
        require_digest(registration.get(key),"REGISTRATION_"+key.upper())
    if (registration.get("contract_sha256")!=csha or registration.get("protocol_sha256")!=contract["protocol"]["sha256"] or registration.get("gate_snapshot_sha256")!=contract["gate_snapshot"]["sha256"] or registration.get("job_template_sha256")!=template_sha or registration.get("runner_sha256")!=contract.get("implementation",{}).get("artifact_sha256",{}).get("src/data/run_blind_unseal_v10.py")):
        raise Refusal("REGISTRATION_CONTRACT_BINDING")
    # LSF 9.1 exports LSB_JOBINDEX="0" for a non-array job.  Treating an
    # empty or absent value as equivalent would allow the execution context to
    # drift from the scheduler behavior captured at registration time.
    if os.environ.get("LSB_JOBID") != str(registration["job_id"]) or os.environ.get("LSB_JOBINDEX") != "0": raise Refusal("LSF_JOB_ID_OR_INDEX")
    verify_external_control_manifest(root,registration["reviewed_commit"],registration["external_control_manifest_path"],registration["external_control_manifest_sha256"])
    for node in ("protocol","gate_snapshot","scheduler_fixture"):
        require_digest(contract[node]["sha256"],node.upper())
        if control_sha_file(root,contract[node]["path"])!=contract[node]["sha256"]: raise Refusal("FROZEN_DIGEST_"+node.upper())
    for relative, expected in ((contract["scope"]["split_contract"],contract["scope"]["split_contract_sha256"]),(contract["inputs"]["inventory_freeze_receipt"],contract["inputs"]["inventory_freeze_receipt_sha256"])):
        require_digest(expected,"INPUT")
        if control_sha_file(root,relative)!=expected: raise Refusal("FROZEN_INPUT_DIGEST")
    # The final job exposes only circuit identity and one registered absolute
    # root.  The pre-consumption aggregate freeze supplies the non-secret file
    # set/count commitments needed by the source auditor; measurement rows and
    # logs remain unread until the in-process capability is active.
    frozen_inventory=control_read_json(root,contract["inputs"]["inventory_freeze_receipt"])
    frozen_circuits=frozen_inventory.get("circuits") if isinstance(frozen_inventory,dict) else None
    if not isinstance(frozen_circuits,dict): raise Refusal("FROZEN_INVENTORY_SCHEMA")
    audit_circuits=[]
    for entry in job["circuits"]:
        frozen=frozen_circuits.get(entry["name"])
        if not isinstance(frozen,dict) or set(frozen)!={"measurement_file_set_sha256","driver_log_file_set_sha256","driver_log_count"}: raise Refusal("FROZEN_INVENTORY_CIRCUIT")
        if not SHA.match(frozen["measurement_file_set_sha256"] or "") or not SHA.match(frozen["driver_log_file_set_sha256"] or "") or not isinstance(frozen["driver_log_count"],int) or frozen["driver_log_count"]<0: raise Refusal("FROZEN_INVENTORY_VALUES")
        audit_circuits.append({"circuit":entry["name"],"measurements_root":entry["root"],"log_root":entry["root"],"phase":"BLIND_UNSEAL_v10","cohort":"blind","environment_cohort":"blind","measurement_file_set_sha256":frozen["measurement_file_set_sha256"],"driver_log_file_set_sha256":frozen["driver_log_file_set_sha256"],"expected_driver_log_count":frozen["driver_log_count"]})
    review=control_read_json(root,contract["review_gate"]["receipt"]); artifacts=contract["implementation"]["artifact_sha256"]
    review_fields={"schema_version","status","execution_allowed","blind_data_read","real_unseal_executed","contract_sha256","registration_receipt_sha256","job_spec_sha256","output_root","job_id","reviewed_commit","protocol_sha256","gate_snapshot_sha256","scheduler_fixture_manifest_sha256","normalized_argv","raw_bjobs_capture_sha256","raw_global_bjobs_capture_sha256","raw_bjobs_al_capture_sha256","external_control_manifest_path","external_control_manifest_sha256","specified_cwd","queue","resource_request","cwd","stdout_path","stderr_path","reviewed_artifacts","registration_validator_pass","psusp_verified","nonarray_verified","no_retry","no_requeue","no_rerun","no_blind_parse","no_blind_output"}
    if set(review)!=review_fields or review.get("schema_version")!="blind-unseal-independent-review-v10" or review.get("status")!="PASS" or review.get("execution_allowed") is not True or review.get("blind_data_read") is not False or review.get("real_unseal_executed") is not False or review.get("registration_validator_pass") is not True or any(review.get(key) is not True for key in ("psusp_verified","nonarray_verified","no_retry","no_requeue","no_rerun","no_blind_parse","no_blind_output")) or review.get("contract_sha256")!=csha or review.get("registration_receipt_sha256")!=job["registration_receipt_sha256"] or review.get("job_spec_sha256")!=job_sha or review.get("output_root")!=job.get("output_root") or review.get("job_id")!=registration["job_id"] or review.get("reviewed_commit")!=registration["reviewed_commit"] or review.get("protocol_sha256")!=contract["protocol"]["sha256"] or review.get("gate_snapshot_sha256")!=contract["gate_snapshot"]["sha256"] or review.get("scheduler_fixture_manifest_sha256")!=contract["scheduler_fixture"]["sha256"] or review.get("normalized_argv")!=registration["normalized_argv"] or review.get("raw_bjobs_capture_sha256")!=registration["raw_bjobs_capture_sha256"] or review.get("raw_global_bjobs_capture_sha256")!=registration["raw_global_bjobs_capture_sha256"] or review.get("raw_bjobs_al_capture_sha256")!=registration["raw_bjobs_al_capture_sha256"] or review.get("external_control_manifest_path")!=registration["external_control_manifest_path"] or review.get("external_control_manifest_sha256")!=registration["external_control_manifest_sha256"] or review.get("specified_cwd")!=registration["specified_cwd"] or review.get("queue")!=registration["queue"] or review.get("resource_request")!=registration["resource_request"] or review.get("cwd")!=registration["cwd"] or review.get("stdout_path")!=registration["stdout_path"] or review.get("stderr_path")!=registration["stderr_path"] or review.get("reviewed_artifacts")!=artifacts: raise Refusal("REVIEW_BINDING")
    if git_text(root,"status","--porcelain"): raise Refusal("GIT_DIRTY")
    reviewed=review.get("reviewed_commit",""); head=git_text(root,"rev-parse","HEAD")
    if not re.match(r"^[0-9a-f]{40}$",reviewed) or git_text(root,"rev-parse",reviewed)!=reviewed: raise Refusal("REVIEWED_COMMIT")
    try: subprocess.check_call(["git","-C",root,"merge-base","--is-ancestor",reviewed,head],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError: raise Refusal("REVIEWED_NOT_ANCESTOR")
    for relative, expected in artifacts.items():
        require_digest(expected,"ARTIFACT")
        current=control_read_bytes(root,relative)
        if git_bytes(root,"cat-file","blob",reviewed+":"+relative) != current or hashlib.sha256(current).hexdigest()!=expected: raise Refusal("BLOB_OR_WORKTREE_DRIFT")
    audit_job=dict(job); audit_job["circuits"]=audit_circuits
    return contract,csha,audit_job,artifacts
def write_release(contract,csha,tool,out,receipt):
    # Do not create a PASS release and then attempt to replace it after a later
    # exception.  The whole receipt is checked first, then each output name is
    # created exactly once in release order.
    if not verify_receipt(contract,csha,tool,receipt): raise RuntimeError("RELEASE_RECEIPT_INVALID")
    raw=json_bytes(receipt); digest=hashlib.sha256(raw).hexdigest()
    exclusive(os.path.join(out,"receipt.json"),raw)
    exclusive(os.path.join(out,"receipt.json.sha256"),(digest+"  receipt.json\n").encode("ascii"))
    exclusive(os.path.join(out,"RELEASED"),json_bytes({"schema_version":"blind-runtime-unseal-release-v10","status":"RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING","contract_sha256":csha,"receipt_sha256":digest}))
def run(root):
    contract,csha,job,artifacts=validate_bundle(root); out=os.path.abspath(job["output_root"])
    if os.path.lexists(out) or not os.path.isdir(os.path.dirname(out)): raise Refusal("OUTPUT_ROOT_NOT_EMPTY_OR_PARENT_INVALID")
    os.mkdir(out,0o700); fsync_dir(os.path.dirname(out)); tool=sha_lines(k+":"+v for k,v in artifacts.items()); exclusive(os.path.join(out,"CONSUMED"),json_bytes({"schema_version":"blind-runtime-unseal-consumed-v10","status":"CONSUMED","contract_sha256":csha,"tool_set_sha256":tool}))
    global _ACTIVE_SOURCE_CAPABILITY
    capability=object(); _ACTIVE_SOURCE_CAPABILITY=capability
    try:
        guard=(os.path.join(out,"CONSUMED"),csha,tool,capability)
        rows=[_audit_circuit(x,job["measurement_files"],guard) for x in job["circuits"]]
        if any(x["missing_runtime_join_count"] or x["ambiguous_runtime_join_count"] or x["coverage_rate"]!=1.0 or x["action_coverage_summary"]["all_unique_action_count"]!=x["action_coverage_summary"]["eligible_action_count"] for x in rows): raise ValueError("R06_R07_FAILED")
        receipt={"schema_version":"blind-runtime-unseal-receipt-v10","status":"PASS","formal_runtime_membership_sha256":contract["scope"]["formal_runtime_membership_sha256"],"method_registry_sha256":contract["scope"]["method_registry_sha256"],"tool_set_sha256":tool,"contract_sha256":csha,"circuits":rows,"failure_code":None}; code=0
    except Exception as error:
        failure_code="R06_R07_FAILED" if isinstance(error,ValueError) and str(error)=="R06_R07_FAILED" else "SEALED_AUDIT_FAILED"
        receipt={"schema_version":"blind-runtime-unseal-receipt-v10","status":"FAIL","formal_runtime_membership_sha256":contract["scope"]["formal_runtime_membership_sha256"],"method_registry_sha256":contract["scope"]["method_registry_sha256"],"tool_set_sha256":tool,"contract_sha256":csha,"failure_code":failure_code,"circuits":[]}; code=1
    finally:
        _ACTIVE_SOURCE_CAPABILITY=None
    write_release(contract,csha,tool,out,receipt)
    return code
def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if argv != ["--bundle-root", EXPECTED_BUNDLE_ROOT]: print("BLIND_UNSEAL=REFUSED_FIXED_ARGV"); return 2
    try: code=run(EXPECTED_BUNDLE_ROOT)
    except Refusal as e: print("BLIND_UNSEAL=REFUSED_"+str(e)); return 2
    except (OSError, ValueError): print("BLIND_UNSEAL=REFUSED_BUNDLE_INVALID"); return 2
    print("BLIND_UNSEAL="+("RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING" if code==0 else "INCOMPLETE_CONSUMED")); return code
if __name__=="__main__": raise SystemExit(main())
