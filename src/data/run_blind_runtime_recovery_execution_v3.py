#!/usr/bin/env python3
"""v3 recovery control plane: executable only after complete reviewed evidence."""
from __future__ import print_function
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

from src.data import run_blind_runtime_recovery_execution_v1 as base

CONTRACT_RELATIVE = "contracts/blind_runtime_recovery_execution_v3.json"
JOB_TEMPLATE_RELATIVE = "contracts/blind_runtime_recovery_execution_v3_job_template.json"
BUNDLE_MANIFEST_RELATIVE = "bundle_manifest_v3.json"
DESIGN_REVIEW_RELATIVE = "contracts/blind_runtime_recovery_execution_v3_review.json"
JOB_BUNDLE_ROOT = "/temp/jiangchuanc/blind_runtime_recovery_execution_v3_authorized_r1_bundle"
INPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/16_blind_runtime_recovery_execution_v3_inputs_r1"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/17_blind_runtime_recovery_execution_v3_r1_private"
REGISTRATION_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v3_registration_r1"
JOB_NAME = "blind_rt_recovery_v3_r1"
AUTHORIZATION_PATH = REGISTRATION_ROOT + "/authorization.json"
REGISTRATION_REVIEW_PATH = REGISTRATION_ROOT + "/independent_review.json"
PRE_RESUME_REVIEW_PATH = REGISTRATION_ROOT + "/pre_resume_review.json"
REGISTRATION_COMMAND_PATH = REGISTRATION_ROOT + "/registration_command.txt"
BSUB_CAPTURE_PATH = REGISTRATION_ROOT + "/bsub.txt"
BJOBS_CAPTURE_PATH = REGISTRATION_ROOT + "/bjobs.txt"
BJOBS_AL_CAPTURE_PATH = REGISTRATION_ROOT + "/bjobs_al.txt"
TIMEZONE_PATH = REGISTRATION_ROOT + "/timezone_offset.txt"
CAPTURE_UTC_PATH = REGISTRATION_ROOT + "/capture_utc.txt"
PRE_BJOBS_PATH = REGISTRATION_ROOT + "/pre_resume_bjobs.txt"
PRE_BJOBS_AL_PATH = REGISTRATION_ROOT + "/pre_resume_bjobs_al.txt"
PRE_CAPTURE_UTC_PATH = REGISTRATION_ROOT + "/pre_resume_capture_utc.txt"
V2_FAILURE_RELATIVE = "data/manifests/blind_runtime_recovery_execution_v2_registration_failure_20260926.json"
Refusal = base.Refusal
_require = base._require

def _read(path):
    with open(path, "rb") as handle: return handle.read()
def _sha(path): return hashlib.sha256(_read(path)).hexdigest()
def _json(path, code):
    try: return json.loads(_read(path).decode("utf-8"))
    except (ValueError, UnicodeDecodeError): raise Refusal(code)
def _utc(value, code):
    _require(isinstance(value, str) and re.match(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", value), code)
    try: return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError: raise Refusal(code)
def _offset(value):
    match = re.match(r"^([+-])([0-1][0-9]|2[0-3]):([0-5][0-9])$", value or "")
    _require(match is not None, "SCHEDULER_TIMEZONE_OFFSET")
    minutes = int(match.group(2))*60 + int(match.group(3))
    return datetime.timezone(datetime.timedelta(minutes=(-minutes if match.group(1)=="-" else minutes)))

def parse_submit_time(raw, timezone_offset, capture_utc):
    capture = _utc(capture_utc, "SCHEDULER_CAPTURE_UTC"); zone = _offset(timezone_offset)
    match = re.match(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-3][0-9]) ([0-2][0-9]):([0-5][0-9]):([0-5][0-9])$", raw or "")
    _require(match is not None, "SCHEDULER_SUBMIT_TIME")
    weekday,name,day,hour,minute,second = match.groups(); month=("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec").index(name)+1; choices=[]
    for year in (capture.astimezone(zone).year-1,capture.astimezone(zone).year,capture.astimezone(zone).year+1):
        try: local=datetime.datetime(year,month,int(day),int(hour),int(minute),int(second),tzinfo=zone)
        except ValueError: continue
        value=local.astimezone(datetime.timezone.utc)
        if local.strftime("%a")==weekday and datetime.timedelta(0)<=capture-value<=datetime.timedelta(minutes=5): choices.append(value)
    _require(len(choices)==1, "SCHEDULER_SUBMIT_TIME_AMBIGUOUS"); return choices[0]

def validate_job_template(document):
    expected={"queue":"normal","initial_scheduler_state":"PSUSP","job_name":JOB_NAME,"command_argv":["/bin/bash",JOB_BUNDLE_ROOT+"/src/data/launch_blind_runtime_recovery_execution_v3.sh"],"cwd":JOB_BUNDLE_ROOT,"stdout_path":REGISTRATION_ROOT+"/stdout.log","stderr_path":REGISTRATION_ROOT+"/stderr.log","array_allowed":False,"retry_allowed":False,"requeue_allowed":False,"rerun_allowed":False}
    lifecycle={"register":"bsub -H exactly once","resume":"only bresume after a fresh independent pre-resume review","forbidden":["second bsub","bmod","rerun","requeue","array submission","resume before PASS review"]}
    _require(isinstance(document,dict) and set(document)=={"schema_version","status","registration","lifecycle"} and document.get("schema_version")=="blind-runtime-recovery-execution-v3-job-template" and document.get("status")=="AUTHORIZED_PRE_REGISTRATION_TEMPLATE" and document.get("registration")==expected and document.get("lifecycle")==lifecycle,"JOB_TEMPLATE_EXACT"); return document

def validate_contract(root):
    path=os.path.join(root,CONTRACT_RELATIVE); payload=_read(path); contract=_json(path,"CONTRACT_JSON")
    allowed={"DESIGN_REVIEW_PENDING_NO_EXECUTION":{"execution_authorized":False,"lsf_submission_allowed":False,"training_allowed":False},"REVIEWED_EXECUTION_AUTHORIZED":{"execution_authorized":True,"lsf_submission_allowed":True,"training_allowed":False}}
    _require(contract.get("schema_version")=="blind-runtime-recovery-execution-v3" and contract.get("status") in allowed and contract.get("authority")==allowed[contract["status"]],"CONTRACT_AUTHORITY")
    plan=contract.get("private_plan",{})
    _require(plan.get("path")==INPUT_ROOT+"/plan.json" and plan.get("sha256")==base.PLAN_SHA256 and plan.get("expected_attempts")==44 and plan.get("expected_counts")==base.PLAN_COUNTS and contract.get("attempt_order")==["H","M"] and contract.get("output",{}).get("root")==OUTPUT_ROOT and contract.get("output",{}).get("overwrite")=="REFUSE" and contract.get("training_allowed") is False,"CONTRACT_PLAN")
    _require(contract.get("command",{}).get("time_argv")==["/usr/bin/time","-v"] and contract.get("command",{}).get("tessent_argv")==["/cad/mentor/tessent2021_2/bin/tessent","-shell","-license_wait","5"] and set(contract.get("circuit_bindings",{}))==set(base.PLAN_COUNTS),"CONTRACT_EXECUTION_BINDING")
    validate_job_template(_json(os.path.join(root,JOB_TEMPLATE_RELATIVE),"JOB_TEMPLATE_JSON"))
    artifacts=contract.get("implementation",{}).get("artifact_sha256",{}); expected={"src/data/run_blind_runtime_recovery_execution_v1.py","src/data/run_blind_runtime_recovery_execution_v3.py","src/data/launch_blind_runtime_recovery_execution_v3.sh","src/data/register_blind_runtime_recovery_execution_v3.sh",JOB_TEMPLATE_RELATIVE,"tests/test_run_blind_runtime_recovery_execution_v3.py",V2_FAILURE_RELATIVE}
    _require(set(artifacts)==expected and all(re.match(r"^[0-9a-f]{64}$",x or "") for x in artifacts.values()),"IMPLEMENTATION_SET")
    for relative,digest in artifacts.items(): _require(_sha(os.path.join(root,relative))==digest,"IMPLEMENTATION_DIGEST")
    bundle_path=os.path.join(root,BUNDLE_MANIFEST_RELATIVE); bundle=_json(bundle_path,"BUNDLE_MANIFEST_JSON")
    bundle_binding=contract.get("bundle_manifest",{})
    _require(bundle.get("schema_version")=="blind-runtime-recovery-execution-v3-bundle-manifest" and bundle.get("status") in ("LOCAL_DESIGN_REVIEW_PENDING","PASS_INDEPENDENT_DESIGN_REVIEW_NO_EXECUTION") and bundle.get("artifact_sha256")==artifacts and bundle_binding.get("path")==BUNDLE_MANIFEST_RELATIVE and bundle_binding.get("sha256")==_sha(bundle_path),"BUNDLE_MANIFEST_BINDING")
    if bundle.get("status")=="PASS_INDEPENDENT_DESIGN_REVIEW_NO_EXECUTION":
        binding=contract.get("independent_review",{}); review_path=os.path.join(root,DESIGN_REVIEW_RELATIVE)
        _require(binding.get("path")==DESIGN_REVIEW_RELATIVE and binding.get("sha256")==_sha(review_path),"DESIGN_REVIEW_BINDING")
        review=_json(review_path,"DESIGN_REVIEW_JSON")
        _require(review.get("schema_version")=="blind-runtime-recovery-execution-v3-design-review" and review.get("status")=="PASS" and review.get("high_findings")==0 and review.get("medium_findings")==0 and review.get("artifact_sha256")==artifacts and re.match(r"^[0-9a-f]{40}$",review.get("reviewed_commit","")),"DESIGN_REVIEW_RECEIPT")
        _require(bundle.get("reviewed_commit")==review.get("reviewed_commit"),"DESIGN_REVIEW_COMMIT")
    else:
        _require("independent_review" not in contract and "reviewed_commit" not in bundle,"DESIGN_REVIEW_PENDING_EXACT")
    prior=contract.get("prior_failure",{}); _require(prior.get("path")==V2_FAILURE_RELATIVE and prior.get("sha256")==artifacts[V2_FAILURE_RELATIVE] and prior.get("reuse_allowed") is False,"PRIOR_FAILURE_BINDING")
    return contract,hashlib.sha256(payload).hexdigest()

def _scheduler(detail,job_id,timezone_offset,capture_utc):
    _require(isinstance(detail,str),"AUTHORIZATION_SCHEDULER_CAPTURE"); compact=re.sub(r"\s+","",detail); command="Command</bin/bash%s/src/data/launch_blind_runtime_recovery_execution_v3.sh>"%JOB_BUNDLE_ROOT
    _require(compact.count("Job<%s>"%job_id)==1 and "JobName<%s>"%JOB_NAME in compact and "Status<PSUSP>" in compact and "Queue<normal>" in compact and command in compact and "CWD<%s>"%JOB_BUNDLE_ROOT in compact and "OutputFile(overwrite)<%s/stdout.log>"%REGISTRATION_ROOT in compact and "ErrorFile(overwrite)<%s/stderr.log>"%REGISTRATION_ROOT in compact and "NotRe-runnable" in compact and not re.search(r"job\s*array|jobindex|\[[0-9]+\]",detail,re.I),"AUTHORIZATION_SCHEDULER_CAPTURE")
    dates=re.findall(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]",detail); _require(len(dates)==1,"SCHEDULER_SUBMIT_TIME_AMBIGUOUS"); return parse_submit_time(dates[0],timezone_offset,capture_utc)

def _validate_review(path, authorization, contract_sha, runner_sha, pre=False):
    doc = _json(path, "REVIEW_JSON")
    required = {"schema_version", "status", "lsf_job_id", "scheduler_state", "submission_count", "contract_sha256", "plan_sha256", "runner_sha256", "launcher_sha256", "job_template_sha256", "bundle_manifest_sha256", "parsed_submit_utc", "capture_utc", "timezone_offset", "nonarray", "no_retry", "no_requeue", "training_allowed", "bjobs_path", "bjobs_sha256", "bjobs_al_path", "bjobs_al_sha256"}
    if pre: required.update(("checked_at_utc","pre_resume_capture_utc_path","pre_resume_capture_utc_sha256"))
    expected_schema="blind-runtime-recovery-execution-v3-pre-resume-review" if pre else "blind-runtime-recovery-execution-v3-registration-review"
    _require(set(doc) == required and doc.get("schema_version")==expected_schema and doc.get("status") == "PASS" and doc.get("scheduler_state") == "PSUSP" and doc.get("submission_count") == 1 and doc.get("training_allowed") is False and doc.get("nonarray") is True and doc.get("no_retry") is True and doc.get("no_requeue") is True, "REVIEW_SCHEMA")
    for name in ("lsf_job_id", "contract_sha256", "plan_sha256", "runner_sha256", "launcher_sha256", "job_template_sha256", "bundle_manifest_sha256", "parsed_submit_utc", "capture_utc", "timezone_offset"):
        _require(doc.get(name) == authorization.get(name), "REVIEW_BINDING")
    _require(doc["contract_sha256"] == contract_sha and doc["runner_sha256"] == runner_sha, "REVIEW_DIGEST_BINDING")
    expected_bjobs=PRE_BJOBS_PATH if pre else BJOBS_CAPTURE_PATH
    expected_detail=PRE_BJOBS_AL_PATH if pre else BJOBS_AL_CAPTURE_PATH
    _require(doc.get("bjobs_path")==expected_bjobs and doc.get("bjobs_al_path")==expected_detail,"REVIEW_CAPTURE_PATH")
    _require(_sha(expected_bjobs)==doc.get("bjobs_sha256") and _sha(expected_detail)==doc.get("bjobs_al_sha256"),"REVIEW_CAPTURE_DIGEST")
    lines=[x.strip() for x in _read(expected_bjobs).decode("utf-8").splitlines() if x.strip()]
    _require(lines==["%s PSUSP %s normal"%(authorization["lsf_job_id"],JOB_NAME)],"REVIEW_BJOBS_CAPTURE")
    parsed=_scheduler(_read(expected_detail).decode("utf-8"),authorization["lsf_job_id"],authorization["timezone_offset"],authorization["capture_utc"])
    _require(parsed.strftime("%Y-%m-%dT%H:%M:%SZ")==authorization["parsed_submit_utc"],"REVIEW_SCHEDULER_BINDING")
    if pre:
        _require(doc.get("pre_resume_capture_utc_path")==PRE_CAPTURE_UTC_PATH and _sha(PRE_CAPTURE_UTC_PATH)==doc.get("pre_resume_capture_utc_sha256"),"PRE_RESUME_CAPTURE_DIGEST")
        captured=_utc(_read(PRE_CAPTURE_UTC_PATH).decode("utf-8").strip(),"PRE_RESUME_CAPTURE_TIME")
        checked = _utc(doc["checked_at_utc"], "PRE_RESUME_TIME"); now = datetime.datetime.now(datetime.timezone.utc)
        initial=_utc(authorization["capture_utc"],"SCHEDULER_CAPTURE_UTC")
        _require(initial<=captured<=checked<=now and now-checked<=datetime.timedelta(minutes=15) and checked-captured<=datetime.timedelta(minutes=2), "PRE_RESUME_REVIEW_STALE")
    return doc

def validate_authorization(path, contract_sha, runner_sha, contract, environment=None):
    doc = _json(path, "AUTHORIZATION_JSON")
    fields = {"schema_version","status","execution_allowed","training_allowed","contract_sha256","plan_sha256","runner_sha256","launcher_sha256","job_template_sha256","bundle_manifest_sha256","lsf_job_id","timezone_offset_path","timezone_offset_sha256","timezone_offset","capture_utc_path","capture_utc_sha256","capture_utc","parsed_submit_utc","registration_command_path","registration_command_sha256","bsub_path","bsub_sha256","bjobs_path","bjobs_sha256","bjobs_al_path","bjobs_al_sha256","registration_review_path","registration_review_sha256","pre_resume_review_path","pre_resume_review_sha256","pre_resume_bjobs_path","pre_resume_bjobs_sha256","pre_resume_bjobs_al_path","pre_resume_bjobs_al_sha256","pre_resume_capture_utc_path","pre_resume_capture_utc_sha256"}
    _require(set(doc) == fields and doc.get("schema_version") == "blind-runtime-recovery-execution-v3-authorization" and doc.get("status") == "PASS" and doc.get("execution_allowed") is True and doc.get("training_allowed") is False, "AUTHORIZATION_SCHEMA")
    _require(contract.get("status")=="REVIEWED_EXECUTION_AUTHORIZED" and contract.get("authority")=={"execution_authorized":True,"lsf_submission_allowed":True,"training_allowed":False},"AUTHORIZATION_CONTRACT_STATE")
    fixed = {"registration_command_path":REGISTRATION_COMMAND_PATH,"bsub_path":BSUB_CAPTURE_PATH,"bjobs_path":BJOBS_CAPTURE_PATH,"bjobs_al_path":BJOBS_AL_CAPTURE_PATH,"timezone_offset_path":TIMEZONE_PATH,"capture_utc_path":CAPTURE_UTC_PATH,"registration_review_path":REGISTRATION_REVIEW_PATH,"pre_resume_review_path":PRE_RESUME_REVIEW_PATH,"pre_resume_bjobs_path":PRE_BJOBS_PATH,"pre_resume_bjobs_al_path":PRE_BJOBS_AL_PATH,"pre_resume_capture_utc_path":PRE_CAPTURE_UTC_PATH}
    _require(all(doc.get(k) == v for k,v in fixed.items()) and doc.get("contract_sha256") == contract_sha and doc.get("plan_sha256") == base.PLAN_SHA256 and doc.get("runner_sha256") == runner_sha and re.match(r"^[1-9][0-9]*$",doc.get("lsf_job_id","")), "AUTHORIZATION_BINDING")
    pairs = (("registration_command_path","registration_command_sha256"),("bsub_path","bsub_sha256"),("bjobs_path","bjobs_sha256"),("bjobs_al_path","bjobs_al_sha256"),("timezone_offset_path","timezone_offset_sha256"),("capture_utc_path","capture_utc_sha256"),("registration_review_path","registration_review_sha256"),("pre_resume_review_path","pre_resume_review_sha256"),("pre_resume_bjobs_path","pre_resume_bjobs_sha256"),("pre_resume_bjobs_al_path","pre_resume_bjobs_al_sha256"),("pre_resume_capture_utc_path","pre_resume_capture_utc_sha256"))
    _require(all(re.match(r"^[0-9a-f]{64}$",doc.get(d,"")) and _sha(doc[p]) == doc[d] for p,d in pairs), "AUTHORIZATION_CAPTURE_DIGEST")
    command = "bsub -H -rn -cwd %s -q normal -J %s -oo %s/stdout.log -eo %s/stderr.log /bin/bash %s/src/data/launch_blind_runtime_recovery_execution_v3.sh" % (JOB_BUNDLE_ROOT,JOB_NAME,REGISTRATION_ROOT,REGISTRATION_ROOT,JOB_BUNDLE_ROOT)
    _require(_read(REGISTRATION_COMMAND_PATH).decode("utf-8").strip() == command and _read(BSUB_CAPTURE_PATH).decode("utf-8").strip() == "Job <%s> is submitted to queue <normal>." % doc["lsf_job_id"], "AUTHORIZATION_REGISTRATION_CAPTURE")
    _require(_read(TIMEZONE_PATH).decode("utf-8").strip()==doc["timezone_offset"] and _read(CAPTURE_UTC_PATH).decode("utf-8").strip()==doc["capture_utc"],"AUTHORIZATION_TIME_CAPTURE")
    expected_impl=contract["implementation"]["artifact_sha256"]
    _require(doc["launcher_sha256"]==expected_impl["src/data/launch_blind_runtime_recovery_execution_v3.sh"] and doc["job_template_sha256"]==expected_impl[JOB_TEMPLATE_RELATIVE] and doc["bundle_manifest_sha256"]==_sha(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),BUNDLE_MANIFEST_RELATIVE)),"AUTHORIZATION_ARTIFACT_BINDING")
    compact = [x.strip() for x in _read(BJOBS_CAPTURE_PATH).decode("utf-8").splitlines() if x.strip()]
    _require(compact == ["%s PSUSP %s normal" % (doc["lsf_job_id"], JOB_NAME)], "AUTHORIZATION_BJOBS_CAPTURE")
    parsed = _scheduler(_read(BJOBS_AL_CAPTURE_PATH).decode("utf-8"),doc["lsf_job_id"],doc["timezone_offset"],doc["capture_utc"])
    _require(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == doc["parsed_submit_utc"], "AUTHORIZATION_SUBMIT_TIME")
    _validate_review(REGISTRATION_REVIEW_PATH,doc,contract_sha,runner_sha); _validate_review(PRE_RESUME_REVIEW_PATH,doc,contract_sha,runner_sha,True)
    env=os.environ if environment is None else environment
    _require(env.get("LSB_JOBID") == doc["lsf_job_id"] and env.get("LSB_JOBINDEX") == "0" and env.get("LSB_JOBINDEX_END") in (None,"","0") and env.get("LSB_JOBINDEX_STEP") in (None,"","0"), "AUTHORIZATION_ARRAY")
    return doc

def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--root",default="."); parser.add_argument("--plan"); parser.add_argument("--authorization"); parser.add_argument("--registration-preflight",action="store_true"); parser.add_argument("--source-preflight",action="store_true"); parser.add_argument("--execute",action="store_true"); args=parser.parse_args(argv)
    try:
        root=os.path.abspath(args.root); contract,contract_sha=validate_contract(root)
        authorized=contract.get("status")=="REVIEWED_EXECUTION_AUTHORIZED" and contract.get("authority")=={"execution_authorized":True,"lsf_submission_allowed":True,"training_allowed":False}
        _require(authorized,"EXECUTION_NOT_AUTHORIZED")
        if args.registration_preflight:
            _require(not args.plan and not args.authorization and not args.source_preflight and not args.execute,"REGISTRATION_PREFLIGHT_SCOPE")
            print(json.dumps({"status":"PASS_V3_REGISTRATION_PREFLIGHT","training_allowed":False},sort_keys=True)); return 0
        _require(args.plan,"PLAN_REQUIRED")
        plan=base.validate_plan_bytes(_read(args.plan),contract); manifest=base.build_command_manifest(plan,contract)
        if args.source_preflight: base.preflight_sources(contract)
        result={"status":"PASS_V3_DESIGN_NO_EXECUTION","attempts":len(manifest),"training_allowed":False}
        if args.execute:
            _require(os.getcwd() == JOB_BUNDLE_ROOT and contract["authority"]["execution_authorized"] is True and args.authorization and os.path.realpath(args.authorization)==AUTHORIZATION_PATH,"EXECUTION_NOT_AUTHORIZED"); validate_authorization(args.authorization,contract_sha,contract["implementation"]["artifact_sha256"]["src/data/run_blind_runtime_recovery_execution_v3.py"],contract); values,source_sha=base.prepare_workspaces(contract); base.execute_manifest(manifest,contract,values,source_sha); result["status"]="PASS_V3_EXECUTION_COMPLETE_AUDIT_PENDING"
        print(json.dumps(result,sort_keys=True)); return 0
    except (IOError,OSError,Refusal) as exc:
        print("BLIND_RUNTIME_RECOVERY_EXECUTION_V3=REFUSED:%s"%exc,file=sys.stderr); return 2
if __name__=="__main__": sys.exit(main())
