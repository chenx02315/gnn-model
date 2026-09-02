#!/usr/bin/env python3
"""Recover an outcome-free attempt_manifest_v2 from logs or Phase2 CSVs."""
from __future__ import print_function
import argparse, csv, hashlib, os, re
from runtime_schema import MANIFEST_V2_FIELDS, PHASE2_WALL_CONTRACT

MARKERS = {"run_id": re.compile(r"^MAPPED_COMMON_ATPG_RUN_ID=(.+)$", re.M), "mode": re.compile(r"^MAPPED_COMMON_ATPG_MODE=(.+)$", re.M), "user_s": re.compile(r"^\s*User time \(seconds\):\s*(\S+)", re.M), "system_s": re.compile(r"^\s*System time \(seconds\):\s*(\S+)", re.M), "elapsed": re.compile(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M), "rss_kb": re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\S+)", re.M), "exit_status": re.compile(r"^\s*Exit status:\s*(\S+)", re.M)}

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()
def wall(text):
    try:
        x = text.split(":")
        return "%.3f" % ((float(x[0])*60+float(x[1])) if len(x)==2 else (float(x[0])*3600+float(x[1])*60+float(x[2]))) if len(x) in (2,3) else ""
    except ValueError: return ""
def val(row, name): return (row.get(name) or "").strip()
def base(adapter, circuit, phase, stage, mode, run, source, source_sha, line="", log_path="", log_sha="", meta=None):
    meta=meta or {}
    return {"adapter":adapter,"circuit":circuit,"family":meta.get("family", ""),"role":meta.get("role", ""),"cohort":meta.get("cohort", ""),"environment_cohort":meta.get("environment_cohort", ""),"phase":phase,"stage":stage,"mode":mode,"run_id":run,"run_id_source":"","wall_s":"","user_s":"","system_s":"","rss_kb":"","exit_status":"","timeout_status":"unknown","retry_order":"","retry_order_status":"UNKNOWN_ORDER","parse_status":"","attempt_outcome_class":"UNKNOWN","semantics_status":"","semantics_contract":"","elapsed_source":"","elapsed_semantics":"","retry_group_id":"","source_artifact":source,"source_artifact_sha256":source_sha,"source_row_number":line,"source_log_path":log_path,"source_log_sha256":log_sha,"inventory_manifest_sha256":meta.get("inventory_manifest_sha256", "")}
def finalize(row):
    identity = "|".join(row.get(k, "") for k in ("source_artifact_sha256","source_row_number","source_log_sha256","run_id"))
    row["attempt_id"] = "attempt_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return row

def gnu_rows(input_path, root, meta):
    paths = []
    for parent, _dirs, files in os.walk(input_path):
        paths.extend(os.path.join(parent, x) for x in files if x.endswith(".driver.log"))
    rows=[]
    for path in sorted(paths):
        log_sha=sha(path)
        with open(path,"rb") as stream:
            stream.seek(0,os.SEEK_END); size=stream.tell(); stream.seek(max(0,size-65536),os.SEEK_SET)
            data=stream.read()
        text=data.decode("utf-8","replace"); found={k:(p.search(text).group(1).strip() if p.search(text) else "") for k,p in MARKERS.items()}
        rel=os.path.relpath(path,root).replace(os.sep,"/"); parts=rel.split("/"); run=found["run_id"] or os.path.basename(path)[:-11]
        circuit=meta.get("circuit") or (parts[1] if len(parts)>1 and parts[0]=="10_circuits" else "")
        row=base("gnu_time_log",circuit,meta.get("phase", ""),parts[-2] if len(parts)>1 else "",found["mode"] or (run[0] if run[:2] in ("H_","M_","F_") else ""),run,rel,log_sha,"",rel,log_sha,meta)
        row.update({"run_id_source":"log_marker" if found["run_id"] else "filename","wall_s":wall(found["elapsed"]),"user_s":found["user_s"],"system_s":found["system_s"],"rss_kb":found["rss_kb"],"exit_status":found["exit_status"],"semantics_status":"VERIFIED_GNU_TIME","semantics_contract":PHASE2_WALL_CONTRACT,"elapsed_source":"gnu_time_footer","elapsed_semantics":"tessent_process_wall_seconds","retry_group_id":run})
        timeout_marker = re.search(r"(?:^|\n)(?:TIMEOUT|TIMED_OUT|KILLED_FOR_TIMEOUT)(?:\b|=)",text,re.I)
        if timeout_marker: row["parse_status"]="TIMEOUT"; row["timeout_status"]="TIMEOUT_MARKER"; row["attempt_outcome_class"]="TIMEOUT"
        elif not row["wall_s"]: row["parse_status"]="MISSING_ELAPSED"
        elif not row["exit_status"]: row["parse_status"]="MISSING_EXIT"
        elif row["exit_status"]!="0": row["parse_status"]="NONZERO_EXIT"; row["attempt_outcome_class"]="NONZERO_EXIT"
        else: row["parse_status"]="PASS"; row["attempt_outcome_class"]="SUCCESS"
        rows.append(finalize(row))
    return rows

def phase2_rows(path, contract, meta):
    digest=sha(path); rows=[]
    with open(path,encoding="utf-8",newline="") as f:
        for number, raw in enumerate(csv.DictReader(f),2):
            row=base("phase2_csv",meta.get("circuit") or val(raw,"circuit"),meta.get("phase") or val(raw,"phase"),val(raw,"phase"),val(raw,"mode"),val(raw,"run_id"),os.path.basename(path),digest,str(number),"","",meta)
            row.update({"run_id_source":"csv_run_id","rss_kb":val(raw,"max_rss_kb"),"semantics_contract":contract or "","elapsed_source":"phase2_csv.wall_time","elapsed_semantics":contract or "","retry_group_id":val(raw,"run_id")})
            if contract != PHASE2_WALL_CONTRACT:
                row.update({"parse_status":"BLOCKED_SEMANTICS","semantics_status":"UNVERIFIED"})
            else:
                row["wall_s"]=wall(val(raw,"wall_time")); row["semantics_status"]="CONTRACT_VERIFIED"; row["parse_status"]="PASS" if row["wall_s"] else "MISSING_ELAPSED"; row["attempt_outcome_class"]="COLLECTED_SUCCESS_ONLY" if row["wall_s"] else "UNKNOWN"
            rows.append(finalize(row))
    return rows

def main():
    p=argparse.ArgumentParser(); p.add_argument("--adapter",choices=("gnu_time_log","phase2_csv"),required=True); p.add_argument("--input",required=True); p.add_argument("--output",required=True); p.add_argument("--evidence-root",default=""); p.add_argument("--semantics-contract",default=""); p.add_argument("--phase",default=""); p.add_argument("--cohort",default=""); p.add_argument("--environment-cohort",default=""); p.add_argument("--circuit",default=""); p.add_argument("--family",default=""); p.add_argument("--role",default=""); p.add_argument("--inventory-manifest-sha256",default="")
    a=p.parse_args(); meta={"phase":a.phase,"cohort":a.cohort,"environment_cohort":a.environment_cohort,"circuit":a.circuit,"family":a.family,"role":a.role,"inventory_manifest_sha256":a.inventory_manifest_sha256}; rows=gnu_rows(a.input,a.evidence_root or a.input,meta) if a.adapter=="gnu_time_log" else phase2_rows(a.input,a.semantics_contract,meta)
    rows.sort(key=lambda r:(r["circuit"],r["phase"],r["stage"],r["run_id"],r["attempt_id"]))
    with open(a.output,"w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=MANIFEST_V2_FIELDS,delimiter="\t",lineterminator="\n"); w.writeheader(); w.writerows({k:r.get(k,"") for k in MANIFEST_V2_FIELDS} for r in rows)
    print("attempts=%d" % len(rows))
if __name__=="__main__": main()
