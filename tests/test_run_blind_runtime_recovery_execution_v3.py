import contextlib
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from src.data import run_blind_runtime_recovery_execution_v3 as runner


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def detail(job="45678", stamp="Fri Sep 25 23:59:00"):
    return ("Job <%s>, Job Name <%s>, Status <PSUSP>, Queue <normal>\n"
            "Submitted at %s, Command </bin/bash %s/src/data/launch_blind_runtime_recovery_execution_v3.sh>,\n"
            " CWD <%s>, Output File (overwrite) <%s/stdout.log>,\n"
            " Error File (overwrite) <%s/stderr.log>, Not Re-runnable;\n" %
            (job, runner.JOB_NAME, stamp, runner.JOB_BUNDLE_ROOT,
             runner.JOB_BUNDLE_ROOT, runner.REGISTRATION_ROOT,
             runner.REGISTRATION_ROOT))


class V3Tests(unittest.TestCase):
    def test_contract_and_bundle_manifest_are_sealed(self):
        root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        contract,digest=runner.validate_contract(root)
        self.assertEqual(64,len(digest))
        self.assertFalse(contract["authority"]["execution_authorized"])

    def test_wrapped_bjobs_al_binds_fields_and_raw_time(self):
        value=runner._scheduler(detail(),"45678","+08:00","2026-09-25T16:00:30Z")
        self.assertEqual("2026-09-25T15:59:00+00:00",value.isoformat())
        for old,new in (("CWD <","CWD </old/"),("(overwrite)",""),("launch_blind_runtime_recovery_execution_v3.sh","old.sh"),("blind_rt_recovery_v3_r1","blind_rt_recovery_v2_r1")):
            with self.subTest(old=old),self.assertRaises(runner.Refusal):
                runner._scheduler(detail().replace(old,new,1),"45678","+08:00","2026-09-25T16:00:30Z")

    def test_ambiguity_stale_window_and_array_refuse(self):
        with self.assertRaisesRegex(runner.Refusal,"AMBIGUOUS"):
            runner._scheduler(detail()+"Submitted at Fri Sep 25 23:58:00\n","45678","+08:00","2026-09-25T16:00:30Z")
        with self.assertRaisesRegex(runner.Refusal,"AMBIGUOUS"):
            runner.parse_submit_time("Fri Sep 25 23:59:00","+08:00","2026-09-25T16:06:00Z")
        with self.assertRaises(runner.Refusal):
            runner._scheduler(detail()+"Job Array <1>\n","45678","+08:00","2026-09-25T16:00:30Z")

    def test_launcher_and_registration_are_one_shot_designs(self):
        root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root,"src/data/launch_blind_runtime_recovery_execution_v3.sh")) as handle:
            launch=handle.read()
        with open(os.path.join(root,"src/data/register_blind_runtime_recovery_execution_v3.sh")) as handle:
            register=handle.read()
        self.assertIn('cd -- "$BUNDLE_ROOT"',launch)
        self.assertIn("--authorization",launch)
        self.assertIn("python3 -m src.data.run_blind_runtime_recovery_execution_v3",launch)
        self.assertIn("REVIEWED_ONE_SHOT_V3",register)
        self.assertEqual(1,len(re.findall(r"^bsub -H -rn -cwd ",register,re.M)))
        self.assertNotIn("bmod",register)
        self.assertNotIn("bresume",register)
        self.assertIn('date +%:z',register)
        self.assertIn("python3 -m src.data.run_blind_runtime_recovery_execution_v3",register)

    def test_real_module_cli_starts_and_refuses_pending_contract_before_plan_read(self):
        root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result=subprocess.run([sys.executable,"-m","src.data.run_blind_runtime_recovery_execution_v3","--root",root,"--registration-preflight"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
        self.assertEqual(2,result.returncode)
        self.assertIn("REFUSED:EXECUTION_NOT_AUTHORIZED",result.stderr)
        self.assertNotIn("ModuleNotFoundError",result.stderr)

    @contextlib.contextmanager
    def authorization_fixture(self):
        names=("REGISTRATION_ROOT","REGISTRATION_COMMAND_PATH","BSUB_CAPTURE_PATH","BJOBS_CAPTURE_PATH","BJOBS_AL_CAPTURE_PATH","TIMEZONE_PATH","CAPTURE_UTC_PATH","REGISTRATION_REVIEW_PATH","PRE_RESUME_REVIEW_PATH","PRE_BJOBS_PATH","PRE_BJOBS_AL_PATH","PRE_CAPTURE_UTC_PATH","JOB_BUNDLE_ROOT")
        saved={name:getattr(runner,name) for name in names}
        with tempfile.TemporaryDirectory() as tmp:
            reg=os.path.join(tmp,"registration"); bundle=os.path.join(tmp,"bundle")
            os.mkdir(reg); os.mkdir(bundle)
            values={"REGISTRATION_ROOT":reg,"JOB_BUNDLE_ROOT":bundle,
                "REGISTRATION_COMMAND_PATH":os.path.join(reg,"registration_command.txt"),
                "BSUB_CAPTURE_PATH":os.path.join(reg,"bsub.txt"),
                "BJOBS_CAPTURE_PATH":os.path.join(reg,"bjobs.txt"),
                "BJOBS_AL_CAPTURE_PATH":os.path.join(reg,"bjobs_al.txt"),
                "TIMEZONE_PATH":os.path.join(reg,"timezone_offset.txt"),
                "CAPTURE_UTC_PATH":os.path.join(reg,"capture_utc.txt"),
                "REGISTRATION_REVIEW_PATH":os.path.join(reg,"independent_review.json"),
                "PRE_RESUME_REVIEW_PATH":os.path.join(reg,"pre_resume_review.json"),
                "PRE_BJOBS_PATH":os.path.join(reg,"pre_resume_bjobs.txt"),
                "PRE_BJOBS_AL_PATH":os.path.join(reg,"pre_resume_bjobs_al.txt"),
                "PRE_CAPTURE_UTC_PATH":os.path.join(reg,"pre_resume_capture_utc.txt")}
            for name,value in values.items(): setattr(runner,name,value)
            try: yield tmp
            finally:
                for name,value in saved.items(): setattr(runner,name,value)

    def build_authorization(self,root):
        repo=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo,runner.CONTRACT_RELATIVE),encoding="utf-8") as handle: contract=json.load(handle)
        contract["status"]="REVIEWED_EXECUTION_AUTHORIZED"
        contract["authority"]={"execution_authorized":True,"lsf_submission_allowed":True,"training_allowed":False}
        impl=contract["implementation"]["artifact_sha256"]; job="45678"
        capture=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        submitted=capture-datetime.timedelta(seconds=30)
        stamp=submitted.strftime("%a %b %d %H:%M:%S"); capture_text=capture.strftime("%Y-%m-%dT%H:%M:%SZ"); parsed_text=submitted.strftime("%Y-%m-%dT%H:%M:%SZ")
        command="bsub -H -rn -cwd %s -q normal -J %s -oo %s/stdout.log -eo %s/stderr.log /bin/bash %s/src/data/launch_blind_runtime_recovery_execution_v3.sh"%(runner.JOB_BUNDLE_ROOT,runner.JOB_NAME,runner.REGISTRATION_ROOT,runner.REGISTRATION_ROOT,runner.JOB_BUNDLE_ROOT)
        captures={runner.REGISTRATION_COMMAND_PATH:command+"\n",runner.BSUB_CAPTURE_PATH:"Job <%s> is submitted to queue <normal>.\n"%job,runner.BJOBS_CAPTURE_PATH:"%s PSUSP %s normal\n"%(job,runner.JOB_NAME),runner.BJOBS_AL_CAPTURE_PATH:detail(job,stamp),runner.TIMEZONE_PATH:"+00:00\n",runner.CAPTURE_UTC_PATH:capture_text+"\n",runner.PRE_BJOBS_PATH:"%s PSUSP %s normal\n"%(job,runner.JOB_NAME),runner.PRE_BJOBS_AL_PATH:detail(job,stamp),runner.PRE_CAPTURE_UTC_PATH:capture_text+"\n"}
        for path,text in captures.items():
            with open(path,"w",encoding="utf-8",newline="\n") as handle: handle.write(text)
        contract_sha="a"*64; runner_sha=impl["src/data/run_blind_runtime_recovery_execution_v3.py"]; bundle_sha=sha(os.path.join(repo,runner.BUNDLE_MANIFEST_RELATIVE))
        common={"status":"PASS","lsf_job_id":job,"scheduler_state":"PSUSP","submission_count":1,"contract_sha256":contract_sha,"plan_sha256":runner.base.PLAN_SHA256,"runner_sha256":runner_sha,"launcher_sha256":impl["src/data/launch_blind_runtime_recovery_execution_v3.sh"],"job_template_sha256":impl[runner.JOB_TEMPLATE_RELATIVE],"bundle_manifest_sha256":bundle_sha,"parsed_submit_utc":parsed_text,"capture_utc":capture_text,"timezone_offset":"+00:00","nonarray":True,"no_retry":True,"no_requeue":True,"training_allowed":False}
        registration=dict(common,schema_version="blind-runtime-recovery-execution-v3-registration-review",bjobs_path=runner.BJOBS_CAPTURE_PATH,bjobs_sha256=sha(runner.BJOBS_CAPTURE_PATH),bjobs_al_path=runner.BJOBS_AL_CAPTURE_PATH,bjobs_al_sha256=sha(runner.BJOBS_AL_CAPTURE_PATH))
        pre=dict(common,schema_version="blind-runtime-recovery-execution-v3-pre-resume-review",checked_at_utc=capture_text,pre_resume_capture_utc_path=runner.PRE_CAPTURE_UTC_PATH,pre_resume_capture_utc_sha256=sha(runner.PRE_CAPTURE_UTC_PATH),bjobs_path=runner.PRE_BJOBS_PATH,bjobs_sha256=sha(runner.PRE_BJOBS_PATH),bjobs_al_path=runner.PRE_BJOBS_AL_PATH,bjobs_al_sha256=sha(runner.PRE_BJOBS_AL_PATH))
        for path,document in ((runner.REGISTRATION_REVIEW_PATH,registration),(runner.PRE_RESUME_REVIEW_PATH,pre)):
            with open(path,"w",encoding="utf-8",newline="\n") as handle: json.dump(document,handle,sort_keys=True,separators=(",",":"))
        doc={"schema_version":"blind-runtime-recovery-execution-v3-authorization","status":"PASS","execution_allowed":True,"training_allowed":False,"contract_sha256":contract_sha,"plan_sha256":runner.base.PLAN_SHA256,"runner_sha256":runner_sha,"launcher_sha256":common["launcher_sha256"],"job_template_sha256":common["job_template_sha256"],"bundle_manifest_sha256":bundle_sha,"lsf_job_id":job,"timezone_offset_path":runner.TIMEZONE_PATH,"timezone_offset_sha256":sha(runner.TIMEZONE_PATH),"timezone_offset":"+00:00","capture_utc_path":runner.CAPTURE_UTC_PATH,"capture_utc_sha256":sha(runner.CAPTURE_UTC_PATH),"capture_utc":capture_text,"parsed_submit_utc":parsed_text}
        for prefix,path in (("registration_command",runner.REGISTRATION_COMMAND_PATH),("bsub",runner.BSUB_CAPTURE_PATH),("bjobs",runner.BJOBS_CAPTURE_PATH),("bjobs_al",runner.BJOBS_AL_CAPTURE_PATH),("registration_review",runner.REGISTRATION_REVIEW_PATH),("pre_resume_review",runner.PRE_RESUME_REVIEW_PATH),("pre_resume_bjobs",runner.PRE_BJOBS_PATH),("pre_resume_bjobs_al",runner.PRE_BJOBS_AL_PATH),("pre_resume_capture_utc",runner.PRE_CAPTURE_UTC_PATH)):
            doc[prefix+"_path"]=path; doc[prefix+"_sha256"]=sha(path)
        auth=os.path.join(root,"authorization.json")
        with open(auth,"w",encoding="utf-8",newline="\n") as handle: json.dump(doc,handle,sort_keys=True,separators=(",",":"))
        env={"LSB_JOBID":job,"LSB_JOBINDEX":"0","LSB_JOBINDEX_END":"0","LSB_JOBINDEX_STEP":"0"}
        return auth,contract_sha,runner_sha,contract,env,doc

    def test_positive_authorization_and_capture_tamper(self):
        with self.authorization_fixture() as root:
            args=self.build_authorization(root)
            self.assertEqual("PASS",runner.validate_authorization(*args[:4],environment=args[4])["status"])
            with open(runner.BJOBS_AL_CAPTURE_PATH,"a",encoding="utf-8") as handle: handle.write("tamper\n")
            with self.assertRaisesRegex(runner.Refusal,"CAPTURE_DIGEST"):
                runner.validate_authorization(*args[:4],environment=args[4])

    def test_wrong_fixed_path_weak_review_wrong_cwd_and_array_refuse(self):
        with self.authorization_fixture() as root:
            args=list(self.build_authorization(root)); doc=args[5]; doc["bjobs_path"]=os.path.join(root,"wrong.txt")
            with open(args[0],"w",encoding="utf-8") as handle: json.dump(doc,handle)
            with self.assertRaisesRegex(runner.Refusal,"AUTHORIZATION_BINDING"): runner.validate_authorization(*args[:4],environment=args[4])
        with self.authorization_fixture() as root:
            args=list(self.build_authorization(root))
            with open(runner.REGISTRATION_REVIEW_PATH,encoding="utf-8") as handle: review=json.load(handle)
            review.pop("no_retry")
            with open(runner.REGISTRATION_REVIEW_PATH,"w",encoding="utf-8") as handle: json.dump(review,handle)
            args[5]["registration_review_sha256"]=sha(runner.REGISTRATION_REVIEW_PATH)
            with open(args[0],"w",encoding="utf-8") as handle: json.dump(args[5],handle)
            with self.assertRaisesRegex(runner.Refusal,"REVIEW_SCHEMA"): runner.validate_authorization(*args[:4],environment=args[4])
        with self.assertRaises(runner.Refusal): runner._scheduler(detail().replace("CWD <%s>"%runner.JOB_BUNDLE_ROOT,"CWD <$HOME>"),"45678","+08:00","2026-09-25T16:00:30Z")
        with self.authorization_fixture() as root:
            args=list(self.build_authorization(root)); args[4]["LSB_JOBINDEX"]="1"
            with self.assertRaisesRegex(runner.Refusal,"AUTHORIZATION_ARRAY"): runner.validate_authorization(*args[:4],environment=args[4])


if __name__=="__main__": unittest.main()
