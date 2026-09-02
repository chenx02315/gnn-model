from __future__ import print_function
import csv, os, subprocess, sys, tempfile, unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); SCRIPT=os.path.join(ROOT,"src","data","recover_runtime_attempts.py")
sys.path.insert(0, os.path.join(ROOT, "src", "data"))
def put(path,text):
    parent=os.path.dirname(path)
    if not os.path.isdir(parent): os.makedirs(parent)
    with open(path,"w",encoding="utf-8",newline="\n") as f:f.write(text)
class RuntimeRecoveryTest(unittest.TestCase):
 def test_gnu_statuses_and_order_independent_ids(self):
  with tempfile.TemporaryDirectory() as d:
   logs=os.path.join(d,"10_circuits","b18","stage")
   put(os.path.join(logs,"H_one.driver.log"),"MAPPED_COMMON_ATPG_RUN_ID=one\nMAPPED_COMMON_ATPG_MODE=H\nElapsed (wall clock) time (h:mm:ss or m:ss): 1:02\nExit status: 0\n")
   put(os.path.join(logs,"F_two.driver.log"),"Elapsed (wall clock) time (h:mm:ss or m:ss): 0:02\nExit status: 3\n")
   put(os.path.join(logs,"M_three.driver.log"),"MAPPED_COMMON_ATPG_RUN_ID=three\nExit status: 0\n")
   put(os.path.join(logs,"H_four.driver.log"),"Elapsed (wall clock) time (h:mm:ss or m:ss): 0:03\n")
   put(os.path.join(logs,"F_five.driver.log"),"Elapsed (wall clock) time (h:mm:ss or m:ss): 0:04\nExit status: 0\nTIMEOUT\n")
   out=os.path.join(d,"out.tsv"); subprocess.check_call([sys.executable,SCRIPT,"--adapter","gnu_time_log","--input",d,"--evidence-root",d,"--output",out])
   with open(out,encoding="utf8",newline="") as f:rows=list(csv.DictReader(f,delimiter="\t"))
   self.assertEqual(["MISSING_ELAPSED","MISSING_EXIT","NONZERO_EXIT","PASS","TIMEOUT"],sorted(r["parse_status"] for r in rows)); self.assertEqual(5,len(set(r["attempt_id"] for r in rows))); self.assertTrue(all(r["retry_order_status"]=="UNKNOWN_ORDER" for r in rows)); self.assertEqual(("TIMEOUT_MARKER","TIMEOUT"),tuple([r for r in rows if r["run_id"]=="F_five"][0][k] for k in ("timeout_status","attempt_outcome_class")))
   ids={r["run_id"]:r["attempt_id"] for r in rows}; put(os.path.join(logs,"H_one.driver.log"),"MAPPED_COMMON_ATPG_RUN_ID=one\nElapsed (wall clock) time (h:mm:ss or m:ss): 1:02\nExit status: 0\n# changed\n")
   subprocess.check_call([sys.executable,SCRIPT,"--adapter","gnu_time_log","--input",d,"--evidence-root",d,"--output",out])
   with open(out,encoding="utf8",newline="") as f: changed=list(csv.DictReader(f,delimiter="\t"))
   self.assertNotEqual(ids["one"],[r for r in changed if r["run_id"]=="one"][0]["attempt_id"])
 def test_phase2_requires_contract(self):
  with tempfile.TemporaryDirectory() as d:
   inp=os.path.join(d,"p.csv"); put(inp,"circuit,phase,mode,run_id,wall_time,max_rss_kb\nb18,05_two_mode,H,x,1:02,9\n")
   out=os.path.join(d,"o.tsv"); cmd=[sys.executable,SCRIPT,"--adapter","phase2_csv","--input",inp,"--output",out]
   subprocess.check_call(cmd)
   with open(out,encoding="utf8",newline="") as f:self.assertEqual("BLOCKED_SEMANTICS",list(csv.DictReader(f,delimiter="\t"))[0]["parse_status"])
   subprocess.check_call(cmd+["--semantics-contract","tessent_process_wall_seconds"])
   with open(out,encoding="utf8",newline="") as f:r=list(csv.DictReader(f,delimiter="\t"))[0]
   self.assertEqual(("PASS","62.000","2","COLLECTED_SUCCESS_ONLY"),(r["parse_status"],r["wall_s"],r["source_row_number"],r["attempt_outcome_class"])); self.assertNotIn("cycles",r)
   from runtime_schema import FORBIDDEN_OUTCOME_FIELDS, MANIFEST_V2_FIELDS
   self.assertFalse(set(FORBIDDEN_OUTCOME_FIELDS).intersection(MANIFEST_V2_FIELDS))
if __name__=="__main__":unittest.main()
