"""Synthetic Node harness only; never opens actual history/session files."""
import json
from pathlib import Path
import subprocess
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts/find_ranking_v6_e51_creation_commands_r2.cjs"


def node(body):
    prefix = "const m=require(" + json.dumps(str(MODULE)) + ");const {Readable}=require('node:stream');const z=require('node:zlib');\n"
    result = subprocess.run(["node", "-e", prefix + body], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


RECORD_JS = """
function record(cmd, timestamp='2026-10-02T10:53:00Z', name='functions.exec_command') {
  return JSON.stringify({timestamp,type:'response_item',payload:{type:'function_call',name,
    arguments: name.endsWith('exec_command') ? JSON.stringify({cmd}) : cmd}})+'\\n';
}
"""


class CreationCommandTests(unittest.TestCase):
    def test_selected_invocation_exports_paths_not_command(self):
        data = node(RECORD_JS + """
const s=m.makeScanner();s.begin('synthetic.jsonl');
s.feed(Buffer.from(record('python scripts/build_formal_candidate_space_v2.py --output-root /ssd/cjc/formal_candidate_space_v2_r1 --password DO_NOT_EXPORT')));
s.finish();console.log(JSON.stringify(s));
""")
        record = data["records"][0]
        self.assertTrue(record["has_invocation"])
        self.assertEqual(record["evidence"], "COMMAND_RECORD_NOT_EXECUTION_PROOF")
        self.assertTrue(any(x["value"] == "/ssd/cjc/formal_candidate_space_v2_r1" for x in record["snippets"]))
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(data))
        self.assertNotIn("cmd", record)

    def test_user_assistant_tool_output_wrong_date_not_exported(self):
        data = node(RECORD_JS + """
const s=m.makeScanner();s.begin('synthetic.jsonl');
const text='formal_candidate_space_v2 function_call';
const lines=['user','assistant','function_call_output'].map(type => JSON.stringify({
 timestamp:'2026-10-02T10:53:00Z',type,payload:{type,text}})+'\\n');
lines.push(record('python scripts/build_formal_candidate_space_v2.py --output-root /ssd/cjc/formal_candidate_space_v2', '2026-10-03T00:00:00Z'));
lines.push(record('python scripts/build_formal_candidate_space_v2.py --output-root /ssd/cjc/formal_candidate_space_v2', undefined, 'web.run'));
for(const line of lines)s.feed(Buffer.from(line));
s.finish();console.log(JSON.stringify(s));
""")
        self.assertEqual(data["records"], [])
        # Wrong tools and user/assistant/output envelopes never reach parsing.
        self.assertEqual(data["stats"]["preselected_lines"], 0)

    def test_poison_parse_and_utf8_decode_never_see_output_envelopes(self):
        data = node(RECORD_JS + """
const s=m.makeScanner();s.begin('synthetic.jsonl');
const cmd='cat data/formal_candidate_space_v2_r1/receipt_v2.json';
const nested={type:'function_call',name:'functions.exec_command',arguments:JSON.stringify({cmd})};
const outer={timestamp:'2026-10-02T10:53:00Z',type:'response_item',payload:{type:'function_call_output',output:nested}};
const disguised={timestamp:outer.timestamp,type:'response_item',payload:{...nested,output:{sensitive:'MUST_NOT_PARSE'}}};
const user={timestamp:outer.timestamp,type:'response_item',payload:{type:'message',role:'user',content:JSON.stringify(nested)}};
const buffers=[outer,disguised,user].map(x=>Buffer.from(JSON.stringify(x)+'\\n'));
const oldParse=JSON.parse, oldString=Buffer.prototype.toString;
let parses=0,utf8=0;
JSON.parse=()=>{parses++;throw Error('POISON_PARSE');};
Buffer.prototype.toString=function(encoding,...args){if(!encoding||encoding==='utf8'||encoding==='utf-8'){utf8++;throw Error('POISON_UTF8');}return oldString.call(this,encoding,...args);};
try{for(const raw of buffers)s.feed(raw);s.finish();}finally{JSON.parse=oldParse;Buffer.prototype.toString=oldString;}
console.log(JSON.stringify({parses,utf8,records:s.records,stats:s.stats}));
""")
        self.assertEqual(data["parses"], 0)
        self.assertEqual(data["utf8"], 0)
        self.assertEqual(data["records"], [])
        self.assertEqual(data["stats"]["envelope_skipped_lines"], 3)

    def test_custom_tool_call_module_invocation_and_a_paths(self):
        data = node("""
const s=m.makeScanner();s.begin('synthetic.jsonl');
const obj={timestamp:'2026-10-02T10:53:00Z',type:'response_item',payload:{type:'custom_tool_call',call_id:'test',name:'functions.exec',input:'await tools.exec_command({cmd: "python -m src.data.build_formal_candidate_space_v2 --output-root /temp/jiangchuanc/formal_candidate_space_v2_r1 --candidate-root /home/cjc/formal_candidate_space_v2_r2"});'}};
s.feed(Buffer.from(JSON.stringify(obj)+'\\n'));s.finish();
console.log(JSON.stringify({records:s.records,a:m.cleanPath('/home/jiangchuanc/formal_candidate_space_v2/receipt_v2.json')}));
""")
        self.assertEqual(len(data["records"]), 1)
        self.assertTrue(data["records"][0]["has_invocation"])
        self.assertEqual(data["records"][0]["recordtype"], "custom_tool_call")
        self.assertTrue(data["a"].startswith("/home/jiangchuanc/"))

    def test_unused_command_and_metadata_objects_rejected_before_decode(self):
        data = node("""
const s=m.makeScanner();s.begin('synthetic.jsonl');
const cmd='cat data/formal_candidate_space_v2_r1/receipt_v2.json';
const base={type:'function_call',name:'functions.exec_command',arguments:JSON.stringify({cmd})};
const extra=[{input:{type:'function_call_output',output:'PRIVATE'}},{input:'PRIVATE'},
 {status:{output:'PRIVATE'}},{status:['PRIVATE']},{status:'UNKNOWN_STATUS'},
 {call_id:['PRIVATE']},{call_id:{output:'PRIVATE'}},{call_id:42}];
const calls=extra.map(x=>({...base,...x}));
calls.push({type:'custom_tool_call',name:'functions.exec',input:cmd,arguments:{output:'PRIVATE'}});
calls.push({type:'custom_tool_call',name:'functions.exec',input:cmd,arguments:'PRIVATE'});
const buffers=calls.map(payload=>Buffer.from(JSON.stringify({timestamp:'2026-10-02T10:53:00Z',type:'response_item',payload})+'\\n'));
const oldParse=JSON.parse,oldString=Buffer.prototype.toString;let parses=0,utf8=0;
JSON.parse=()=>{parses++;throw Error('POISON_PARSE');};
Buffer.prototype.toString=function(encoding,...args){if(!encoding||encoding==='utf8'||encoding==='utf-8'){utf8++;throw Error('POISON_UTF8');}return oldString.call(this,encoding,...args);};
try{for(const raw of buffers)s.feed(raw);s.finish();}finally{JSON.parse=oldParse;Buffer.prototype.toString=oldString;}
console.log(JSON.stringify({parses,utf8,records:s.records,skipped:s.stats.envelope_skipped_lines}));
""")
        self.assertEqual(data, {"parses": 0, "utf8": 0, "records": [], "skipped": 10})

    def test_legitimate_scalar_metadata_for_both_record_types(self):
        data = node("""
const s=m.makeScanner();s.begin('synthetic.jsonl');
const cmd='cat data/formal_candidate_space_v2_r1/receipt_v2.json';
const calls=[{type:'function_call',name:'functions.exec_command',arguments:JSON.stringify({cmd}),call_id:'synthetic-id',status:'completed'},
 {type:'custom_tool_call',name:'functions.exec',input:cmd,call_id:null,status:null}];
for(const payload of calls)s.feed(Buffer.from(JSON.stringify({timestamp:'2026-10-02T10:53:00Z',type:'response_item',payload})+'\\n'));
s.finish();console.log(JSON.stringify(s.records));
""")
        self.assertEqual({r["recordtype"] for r in data}, {"function_call", "custom_tool_call"})

    def test_retained_identity_set_is_bounded(self):
        data = node(RECORD_JS + """
const s=m.makeScanner({...m.LIMITS,records:3});s.begin('synthetic.jsonl');
for(let i=0;i<2000;i++)s.feed(Buffer.from(record('cat data/formal_candidate_space_v2_r'+i+'/receipt_v2.json')));
s.finish();console.log(JSON.stringify({retained:s.identityCount(),records:s.records.length,dropped:s.stats.records_dropped}));
""")
        self.assertEqual(data, {"retained": 3, "records": 3, "dropped": 1997})

    def test_chunked_bytes_oversized_lines_and_no_unselected_decode(self):
        data = node(RECORD_JS + """
const limits={...m.LIMITS,lineBytes:512};const s=m.makeScanner(limits);s.begin('synthetic.jsonl');
const oversized=Buffer.from('x'.repeat(600)+'\\n');
s.feed(oversized.subarray(0,300));s.feed(oversized.subarray(300));
const raw=Buffer.from(record('cat data/formal_candidate_space_v2_r1/source_provenance_v2.tsv'));
for(let i=0;i<raw.length;i+=7)s.feed(raw.subarray(i,i+7));
s.finish();console.log(JSON.stringify(s));
""")
        self.assertEqual(data["stats"]["oversized_lines"], 1)
        self.assertEqual(len(data["records"]), 1)
        self.assertFalse(data["records"][0]["has_invocation"])

    def test_protected_and_sensitive_paths_removed_but_denied_metadata_kept(self):
        data = node("""
console.log(JSON.stringify({
 protected:m.cleanPath('/ssd/cjc/multimode_ate_gnn_v1/formal_candidate_space_v2'),
 checkpoint:m.cleanPath('/ssd/cjc/checkpoints/formal_candidate_space_v2'),
 traversal:m.cleanPath('/ssd/cjc/../formal_candidate_space_v2'),
 local:m.cleanPath('C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928/formal_candidate_space_v2_r1/receipt_v2.json'),
 paths:m.selectedPaths('--candidate-root "C:/Users/86155/Desktop/new lab/runtime_training_staging_20260928/formal_candidate_space_v2_r1"')
}));
""")
        self.assertIsNone(data["protected"])
        self.assertIsNone(data["checkpoint"])
        self.assertIsNone(data["traversal"])
        self.assertTrue(data["local"].endswith("receipt_v2.json"))
        self.assertTrue(any(x["kind"] == "argv_candidate_root" for x in data["paths"]))

    def test_compressed_stream_and_global_bounds(self):
        data = node(RECORD_JS + """
(async()=>{
const raw=Buffer.from(record('cat data/formal_candidate_space_v2_r1/receipt_v2.json'));
const compressed=z.zstdCompressSync(raw);
const result=await m.scanFiles([{filename:'synthetic.jsonl.zst',size:compressed.length,compressed:true}],
 async()=>Readable.from([compressed]));
console.log(JSON.stringify(result));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        self.assertEqual(len(data["records"]), 1)
        self.assertTrue(data["coverage"]["files"][0]["complete_frozen_prefix"])
        self.assertGreater(data["coverage"]["compressed_decoded_bytes"], 0)
        self.assertFalse(data["data_files_opened"])

    def test_raw_and_decoded_byte_bounds_report_incomplete(self):
        data = node("""
(async()=>{
const raw=Buffer.from('x'.repeat(200)+'\\n');
const compressed=z.zstdCompressSync(raw);
const rawResult=await m.scanFiles([{filename:'raw.jsonl',size:raw.length,compressed:false}],
 async()=>Readable.from([raw]),{...m.LIMITS,inputBytes:100});
const decodedResult=await m.scanFiles([{filename:'compressed.jsonl.zst',size:compressed.length,compressed:true}],
 async()=>Readable.from([compressed]),{...m.LIMITS,decodedPerFile:100});
console.log(JSON.stringify([rawResult,decodedResult]));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        for item in data:
            self.assertFalse(item["coverage"]["files"][0]["complete_frozen_prefix"])
            self.assertTrue(item["coverage"]["files"][0]["bound_reached"])
        self.assertEqual(data[0]["coverage"]["input_bytes"], 100)
        self.assertEqual(data[1]["coverage"]["compressed_decoded_bytes"], 100)

    def test_record_output_and_file_count_bounds(self):
        data = node(RECORD_JS + """
(async()=>{
const s=m.makeScanner({...m.LIMITS,records:1});s.begin('synthetic.jsonl');
s.feed(Buffer.from(record('cat data/formal_candidate_space_v2_r1/receipt_v2.json')+
 record('cat data/formal_candidate_space_v2_r2/receipt_v2.json')));s.finish();
let rejected=false;try{await m.scanFiles(Array.from({length:13},()=>({})),async()=>Readable.from([]));}catch{rejected=true;}
const p=m.packet(s,{}, {...m.LIMITS,outputBytes:1000});
console.log(JSON.stringify({p,rejected,bytes:Buffer.byteLength(JSON.stringify(p))+1}));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        self.assertTrue(data["rejected"])
        self.assertLessEqual(data["bytes"], 1000)
        self.assertGreaterEqual(data["p"]["counts"]["records_dropped"], 1)

    def test_frozen_prefix_ignores_appended_bytes(self):
        data = node(RECORD_JS + """
(async()=>{
const first=Buffer.from('unselected\\n');
const appended=Buffer.from(record('cat data/formal_candidate_space_v2_r1/receipt_v2.json'));
const result=await m.scanFiles([{filename:'raw.jsonl',size:first.length,compressed:false}],
 async()=>Readable.from([Buffer.concat([first,appended])]));
console.log(JSON.stringify(result));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        self.assertEqual(data["records"], [])
        self.assertEqual(data["coverage"]["input_bytes"], len("unselected\n"))
        self.assertTrue(data["coverage"]["append_ignored"])


    def test_terminal_cleanup_precedes_single_success_output(self):
        data = node("""
(async()=>{
const events=[],out=[];
const code=await m.terminalRun(async()=>{events.push('scan');return {status:'PASS'};},
 async()=>{events.push('close');},row=>{events.push('emit');out.push(row);});
console.log(JSON.stringify({events,out,code}));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        self.assertEqual(data["events"], ["scan", "close", "emit"])
        self.assertEqual(data["out"], [{"status": "PASS"}])
        self.assertEqual(data["code"], 0)

    def test_terminal_close_failure_emits_only_failure(self):
        data = node("""
(async()=>{
const out=[],events=[];
const code=await m.terminalRun(async()=>({status:'PASS'}),
 async()=>{events.push('close');throw Error('synthetic close failure');},
 row=>{events.push('emit');out.push(row);});
console.log(JSON.stringify({out,events,code}));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")
        self.assertEqual(len(data["out"]), 1)
        self.assertEqual(data["out"][0]["status"], "FAIL_CLOSED_CREATION_FORMAT_DIAGNOSTIC")
        self.assertEqual(data["events"], ["close", "emit"])
        self.assertEqual(data["code"], 2)

    def test_metadata_format_diagnostic_never_decodes_or_parses_body(self):
        data = node("""
const s=m.makeScanner();s.begin('synthetic.jsonl');
const payload={type:'function_call_output',name:'functions.exec',output:{
 sensitive:'PRIVATE_QUALITY_VALUE',nested:{type:'function_call',arguments:'PRIVATE'}}};
const raw=Buffer.from(JSON.stringify({timestamp:'2026-10-02T10:53:00Z',type:'response_item',payload,
 extra_field:'formal_candidate_space_v2'})+'\\n');
const oldParse=JSON.parse,oldString=Buffer.prototype.toString;let parses=0,utf8=0;
JSON.parse=()=>{parses++;throw Error('POISON_PARSE');};
Buffer.prototype.toString=function(encoding,...args){if(!encoding||encoding==='utf8'||encoding==='utf-8'){utf8++;throw Error('POISON_UTF8');}return oldString.call(this,encoding,...args);};
try{s.feed(raw);s.finish();}finally{JSON.parse=oldParse;Buffer.prototype.toString=oldString;}
console.log(JSON.stringify({parses,utf8,diagnostic:s.diagnostic,records:s.records}));
""")
        self.assertEqual(data["parses"], 0)
        self.assertEqual(data["utf8"], 0)
        self.assertEqual(data["records"], [])
        shape = data["diagnostic"]["formats"][0]
        self.assertEqual(shape["root_type"], "response_item")
        self.assertEqual(shape["payload_type"], "function_call_output")
        self.assertEqual(shape["toolname"], "functions.exec")
        self.assertIn({"key": "output", "kind": "object"}, shape["payload_keys"])
        self.assertNotIn("PRIVATE", json.dumps(data))
        self.assertNotIn("sensitive", json.dumps(data))

    def test_unknown_identifier_keys_are_not_exported(self):
        data = node("""
const s=m.makeScanner();s.begin('synthetic.jsonl');
for(let i=0;i<80;i++){
const obj={timestamp:'2026-10-02T10:53:00Z',type:'response_item',
 payload:{type:'custom_tool_call',name:'functions.exec',input:'formal_candidate_space_v2',status:'PRIVATE_STATUS'}};
obj['POISON_IDENTIFIER_DO_NOT_EXPORT_'+i]=['PRIVATE_ARRAY'];
s.feed(Buffer.from(JSON.stringify(obj)+'\\n'));
}
s.finish();console.log(JSON.stringify(s.diagnostic));
""")
        self.assertEqual(len(data["formats"]), 1)
        self.assertEqual(data["formats"][0]["count"], 80)
        self.assertEqual(data["format_bound_skipped_lines"], 0)
        self.assertIn({"key": "UNKNOWN_KEY", "kind": "array"}, data["formats"][0]["root_keys"])
        self.assertNotIn("POISON_IDENTIFIER", json.dumps(data))
        self.assertNotIn("PRIVATE", json.dumps(data))


if __name__ == "__main__":
    unittest.main()
