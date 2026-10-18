'use strict';
// E53 feasibility prototype. Actual history execution is intentionally disabled.
const crypto = require('node:crypto');
const { structuralSelector } = require('./find_ranking_v6_e51_creation_commands_r3.cjs');
const ROOT = 'C:/Users/86155/.codex/sessions/2026/07/25/rollout-2026-07-25T22-51-41-019f99c2-b229-7f42-8f37-255b4339afc8.jsonl';
const SCHEMA = 'formal-candidate-space-v2-receipt';
const EXPECTED_SHA = '48c164e99e653c1d00dbf8e7655447e2ffc09c9519c63b7191dff9a151b7456d';
const LIMITS = Object.freeze({inputBytes:512*1024*1024,lineBytes:2*1024*1024,
  selectedBytes:65536,outputBytes:65536,workers:1});
const MARKER = Buffer.from(SCHEMA);
const DATE = Buffer.from('"2026-10-02T');
const EXECUTION_AUTHORIZED = false;
const HASH_KEYS = ['source_provenance','candidate_space','normalized_measurements'];

function quotedEquals(buffer, range, value) {
  return range && buffer.subarray(...range).equals(Buffer.from('"'+value+'"'));
}
function outputRange(buffer,allowedCallIds) {
  if(!buffer.includes(MARKER)||!buffer.includes(DATE))return null;
  try {
    const parser=structuralSelector(buffer),root=parser.fields(0,['timestamp','type','payload']);
    if(parser.ws(root.end)!==buffer.length||!quotedEquals(buffer,root.found.get('type'),'response_item'))return null;
    const timestamp=root.found.get('timestamp'),payload=root.found.get('payload');
    if(!timestamp||!payload||!buffer.subarray(timestamp[0],timestamp[0]+DATE.length).equals(DATE))return null;
    const call=parser.fields(payload[0],['type','call_id','name','output']);
    if(call.end!==payload[1])return null;
    if(!['custom_tool_call_output','function_call_output'].some(t=>quotedEquals(buffer,call.found.get('type'),t)))return null;
    const id=call.found.get('call_id'),name=call.found.get('name'),output=call.found.get('output');
    if(!id||buffer[id[0]]!==34||!output)return null;
    if(!allowedCallIds.some(value=>quotedEquals(buffer,id,value)))return null;
    if(name&&!['exec','exec_command','functions.exec','functions.exec_command','tools.exec','tools.exec_command']
      .some(t=>quotedEquals(buffer,name,t)))return null;
    if(buffer[output[0]]!==34&&buffer[output[0]]!==91)return null;
    return output;
  }catch{return null;}
}

// Grammar only: nodes retain byte ranges, never semantic result values.
function lexicalJson(buffer) {
  let nodes=0;
  const ws = i => {while([32,9,10,13].includes(buffer[i]))i++;return i;};
  const hex=b=>b>=48&&b<=57||b>=65&&b<=70||b>=97&&b<=102;
  function stringEnd(i) {
    if(buffer[i++]!==34)throw Error('STRING');
    for(;i<buffer.length;i++){
      const b=buffer[i];
      if(b===34)return i+1;
      if(b<32)throw Error('CONTROL');
      if(b===92){
        const escape=buffer[++i];
        if(escape===117){for(let j=0;j<4;j++)if(!hex(buffer[++i]))throw Error('UNICODE_ESCAPE');}
        else if(![34,92,47,98,102,110,114,116].includes(escape))throw Error('ESCAPE');
      }
    }
    throw Error('STRING_END');
  }
  function parse(start,depth=0) {
    if(depth>32||++nodes>4096)throw Error('LEXICAL_BOUND');
    let i=ws(start),kind;
    const begin=i;
    if(buffer[i]===34)return {kind:'string',start:i,end:stringEnd(i)};
    if(buffer[i]===123){
      const pairs=[],seen=new Set();i=ws(i+1);
      if(buffer[i]===125)return {kind:'object',start:begin,end:i+1,pairs};
      while(i<buffer.length){
        const keyStart=i,keyEnd=stringEnd(i),key=buffer.subarray(i,keyEnd);
        if(key.includes(92)||key.length>80)throw Error('KEY_ENCODING');
        const identity=key.toString('hex');
        if(seen.has(identity))throw Error('DUPLICATE_KEY');
        seen.add(identity);i=ws(keyEnd);
        if(buffer[i++]!==58)throw Error('COLON');
        const value=parse(i,depth+1);pairs.push({keyStart,keyEnd,value});
        i=ws(value.end);if(buffer[i]===125)return {kind:'object',start:begin,end:i+1,pairs};
        if(buffer[i++]!==44)throw Error('COMMA');i=ws(i);
      }
      throw Error('OBJECT_END');
    }
    if(buffer[i]===91){
      const items=[];i=ws(i+1);
      if(buffer[i]===93)return {kind:'array',start:begin,end:i+1,items};
      while(i<buffer.length){
        const item=parse(i,depth+1);items.push(item);i=ws(item.end);
        if(buffer[i]===93)return {kind:'array',start:begin,end:i+1,items};
        if(buffer[i++]!==44)throw Error('ARRAY_COMMA');i=ws(i);
      }
      throw Error('ARRAY_END');
    }
    for(const [text,type] of [['true','boolean'],['false','boolean'],['null','null']]){
      const token=Buffer.from(text);
      if(buffer.subarray(i,i+token.length).equals(token))return {kind:type,start:i,end:i+token.length};
    }
    kind='number';if(buffer[i]===45)i++;
    if(buffer[i]===48)i++;
    else{
      if(!(buffer[i]>=49&&buffer[i]<=57))throw Error('NUMBER');
      while(buffer[i]>=48&&buffer[i]<=57)i++;
    }
    if(buffer[i]===46){
      i++;if(!(buffer[i]>=48&&buffer[i]<=57))throw Error('FRACTION');
      while(buffer[i]>=48&&buffer[i]<=57)i++;
    }
    if(buffer[i]===101||buffer[i]===69){
      i++;if(buffer[i]===43||buffer[i]===45)i++;
      if(!(buffer[i]>=48&&buffer[i]<=57))throw Error('EXPONENT');
      while(buffer[i]>=48&&buffer[i]<=57)i++;
    }
    return {kind,start:begin,end:i};
  }
  const root=parse(0);
  if(ws(root.end)!==buffer.length)throw Error('TRAILING');
  return root;
}
function field(buffer,node,key) {
  if(node.kind!=='object')return null;
  const token=Buffer.from('"'+key+'"'),pair=node.pairs.find(p=>buffer.subarray(p.keyStart,p.keyEnd).equals(token));
  return pair?pair.value:null;
}
function exactObject(buffer,node,keys) {
  return node&&node.kind==='object'&&node.pairs.length===keys.length&&keys.every(key=>field(buffer,node,key));
}
function exactReceipt(buffer,node) {
  const top=['schema_version','status','required_circuits','counts','sha256','gates','boundaries'];
  if(!exactObject(buffer,node,top))return false;
  const schema=field(buffer,node,'schema_version');
  if(schema.kind!=='string'||!quotedEquals(buffer,[schema.start,schema.end],SCHEMA))return false;
  if(field(buffer,node,'status').kind!=='string')return false;
  const roster=field(buffer,node,'required_circuits');
  if(roster.kind!=='array'||roster.items.length>64||roster.items.some(n=>n.kind!=='string'))return false;
  const shapes=[
    ['counts',['input_measurement_count','eligible_source_invocation_count','action_count','duplicate_action_count',
      'outcome_conflict_action_count','phase4_reproduced_source_invocation_count','phase4_reproduced_action_count'],'number'],
    ['sha256',[...HASH_KEYS,'candidate_space_audit'],'string'],
    ['gates',['phase4_source_reproduction_exact','phase4_action_reproduction_exact','circuit_roster_exact',
      'source_candidate_uid_unique','action_uid_unique','outcome_conflict_count_zero'],'boolean'],
    ['boundaries',['training_allowed','blind_rows_read','lsf_or_tessent_submitted','repeat_aggregation_allowed'],'boolean']
  ];
  return shapes.every(([name,keys,kind])=>{
    const value=field(buffer,node,name);
    return exactObject(buffer,value,keys)&&keys.every(key=>field(buffer,value,key).kind===kind);
  });
}
// Unescape only a schema-bearing selected text literal into ASCII bytes.
// Builder json.dumps defaults to ensure_ascii=True: raw non-ASCII is unsupported.
function unescapeSelected(buffer,node,cap) {
  if(node.kind!=='string')throw Error('TEXT_STRING');
  const raw=buffer.subarray(node.start,node.end);
  if(!raw.includes(MARKER))throw Error('SCHEMA_MARKER_REQUIRED');
  let last=raw.length-2;
  while(last>1){
    if([32,9,10,13].includes(raw[last])){last--;continue;}
    if([110,114,116].includes(raw[last])&&raw[last-1]===92){last-=2;continue;}
    break;
  }
  if(raw[1]!==123||raw[last]!==125)throw Error('EXACT_RECEIPT_TEXT_ONLY');
  const out=[];
  function add(b){if(b>127||out.length>=cap)throw Error('SELECTED_TEXT_BOUND_OR_ENCODING');out.push(b);}
  for(let i=1;i<raw.length-1;i++){
    let b=raw[i];
    if(b!==92){add(b);continue;}
    b=raw[++i];
    const simple={34:34,92:92,47:47,98:8,102:12,110:10,114:13,116:9};
    if(b===117){
      let value=0;
      for(let j=0;j<4;j++){
        const c=raw[++i],digit=c>=48&&c<=57?c-48:c>=65&&c<=70?c-55:c>=97&&c<=102?c-87:-1;
        if(digit<0)throw Error('UNICODE_ESCAPE');value=value*16+digit;
      }
      add(value);
    }else if(Object.hasOwn(simple,b))add(simple[b]);else throw Error('ESCAPE');
  }
  return Buffer.from(out);
}
function prettyBytes(buffer,node,depth=0) {
  const space=n=>Buffer.from(' '.repeat(n));
  if(node.kind==='object'){
    if(!node.pairs.length)return Buffer.from('{}');
    const sorted=[...node.pairs].sort((a,b)=>Buffer.compare(buffer.subarray(a.keyStart,a.keyEnd),buffer.subarray(b.keyStart,b.keyEnd)));
    const parts=[Buffer.from('{\n')];
    sorted.forEach((p,i)=>{
      parts.push(space((depth+1)*2),buffer.subarray(p.keyStart,p.keyEnd),Buffer.from(': '),prettyBytes(buffer,p.value,depth+1),
        Buffer.from(i===sorted.length-1?'\n':',\n'));
    });
    parts.push(space(depth*2),Buffer.from('}'));return Buffer.concat(parts);
  }
  if(node.kind==='array'){
    if(!node.items.length)return Buffer.from('[]');
    const parts=[Buffer.from('[\n')];
    node.items.forEach((n,i)=>parts.push(space((depth+1)*2),prettyBytes(buffer,n,depth+1),Buffer.from(i===node.items.length-1?'\n':',\n')));
    parts.push(space(depth*2),Buffer.from(']'));return Buffer.concat(parts);
  }
  return buffer.subarray(node.start,node.end);
}
function authenticateText(text,expectedSha=EXPECTED_SHA,limits=LIMITS) {
  if(text.length>limits.selectedBytes||[...text].some(b=>b>127))return {reason:'text_bound_or_encoding'};
  let node;
  try{node=lexicalJson(text);}catch{return {reason:'candidate_grammar'};}
  if(!exactReceipt(text,node))return {reason:'candidate_schema'};
  const canonical=Buffer.concat([prettyBytes(text,node),Buffer.from('\n')]);
  if(canonical.length>limits.selectedBytes)return {reason:'canonical_bound'};
  if(crypto.createHash('sha256').update(canonical).digest('hex')!==expectedSha)return {reason:'hash_mismatch'};
  const hashes=field(text,node,'sha256'),projection={schema_version:SCHEMA,sha256:{}};
  for(const key of HASH_KEYS){
    const value=field(text,hashes,key),raw=text.subarray(value.start+1,value.end-1);
    if(raw.length!==64||[...raw].some(b=>!(b>=48&&b<=57||b>=97&&b<=102)))return {reason:'matched_hash_field_shape'};
    projection.sha256[key]=raw.toString('ascii');
  }
  return {reason:'authenticated',projection};
}
function selectedTexts(buffer,range) {
  const raw=buffer.subarray(...range),node=lexicalJson(raw);
  function markerCount(text){
    const bytes=raw.subarray(text.start,text.end);let count=0,start=0;
    while((start=bytes.indexOf(MARKER,start))!==-1){count++;start+=MARKER.length;}
    return count;
  }
  if(node.kind==='string'){
    if(markerCount(node)!==1)throw Error('EXACTLY_ONE_SCHEMA_TEXT_REQUIRED');
    return [{buffer:raw,node}];
  }
  if(node.kind!=='array'||node.items.length!==1)throw Error('EXACTLY_ONE_TEXT_ENTRY_REQUIRED');
  const result=[];
  for(const item of node.items){
    if(!exactObject(raw,item,['type','text']))throw Error('TEXT_WRAPPER_SCHEMA');
    const type=field(raw,item,'type'),text=field(raw,item,'text');
    if(!quotedEquals(raw,[type.start,type.end],'text')||text.kind!=='string')throw Error('TEXT_WRAPPER_TYPE');
    const count=markerCount(text);
    if(count>1)throw Error('DUPLICATE_SCHEMA_TEXT');
    if(count===1)result.push({buffer:raw,node:text});
  }
  if(result.length!==1)throw Error('EXACTLY_ONE_SCHEMA_TEXT_REQUIRED');
  return result;
}
function createRecovery(options={}) {
  // Expected-hash/limit injection is for synthetic fixtures. CLI cannot run history.
  const expectedSha=options.expectedSha||EXPECTED_SHA,limits={...LIMITS,...options.limits};
  if(Object.keys(options.limits||{}).some(key=>!Object.hasOwn(LIMITS,key))||
    Object.keys(LIMITS).some(key=>!Number.isSafeInteger(limits[key])||limits[key]<1||limits[key]>LIMITS[key]))throw Error('LIMITS_MAY_ONLY_TIGHTEN');
  if(!/^[a-f0-9]{64}$/.test(expectedSha))throw Error('EXPECTED_SHA');
  if(!Array.isArray(options.allowedCallIds)||options.allowedCallIds.length>32||
    options.allowedCallIds.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_-]{1,180}$/.test(id))||
    new Set(options.allowedCallIds).size!==options.allowedCallIds.length)throw Error('EXPLICIT_CALL_ID_BINDING_REQUIRED');
  const allowedCallIds=[...options.allowedCallIds];
  const counts={input_bytes:0,lines:0,oversized_lines:0,envelope_skipped:0,unsupported_wrappers:0,
    selected_texts:0,text_rejected:0,candidate_grammar:0,candidate_schema:0,hash_mismatch:0,
    canonical_bound:0,matched_hash_field_shape:0,authenticated:0};
  let pending=Buffer.alloc(0),discarding=false,bound=false,projection=null;
  function line(buffer){
    counts.lines++;
    const range=outputRange(buffer,allowedCallIds);if(!range){counts.envelope_skipped++;return;}
    let texts;try{texts=selectedTexts(buffer,range);}catch{counts.unsupported_wrappers++;return;}
    for(const part of texts){
      counts.selected_texts++;
      let text;try{text=unescapeSelected(part.buffer,part.node,limits.selectedBytes);}catch{counts.text_rejected++;continue;}
      const result=authenticateText(text,expectedSha,limits);
      if(result.reason==='authenticated'){counts.authenticated++;projection=result.projection;}
      else if(Object.hasOwn(counts,result.reason))counts[result.reason]++;
      else counts.text_rejected++;
    }
  }
  function feed(chunk){
    if(!Buffer.isBuffer(chunk))throw Error('BUFFER_ONLY');
    if(bound)return;
    const room=limits.inputBytes-counts.input_bytes;
    if(chunk.length>room){chunk=chunk.subarray(0,Math.max(0,room));bound=true;}
    counts.input_bytes+=chunk.length;
    let start=0;
    for(let i=0;i<chunk.length;i++){
      if(chunk[i]!==10)continue;
      const part=chunk.subarray(start,i);
      if(discarding)counts.lines++;
      else if(pending.length+part.length>limits.lineBytes){counts.oversized_lines++;counts.lines++;}
      else line(pending.length?Buffer.concat([pending,part]):part);
      pending=Buffer.alloc(0);discarding=false;start=i+1;
    }
    const rest=chunk.subarray(start);
    if(!discarding&&pending.length+rest.length>limits.lineBytes){discarding=true;pending=Buffer.alloc(0);counts.oversized_lines++;}
    else if(!discarding&&rest.length)pending=pending.length?Buffer.concat([pending,rest]):Buffer.from(rest);
  }
  function finish(){
    if(!bound&&pending.length&&!discarding)line(pending);
    else if(discarding)counts.lines++;
    pending=Buffer.alloc(0);
    const incomplete=bound||counts.oversized_lines>0;
    const accepted=!incomplete&&counts.authenticated===1;
    const status=incomplete?'INCOMPLETE_INPUT_NO_RELEASE':counts.authenticated>1?'AMBIGUOUS_MATCHING_COPIES_NO_RELEASE':
      accepted?'SYNTHETIC_OR_REVIEW_GATED_RECEIPT_AUTHENTICATED':'NO_AUTHENTICATED_RECEIPT';
    const result={status,
      execution_authorized:false,counts,input_bound_reached:bound,projection:accepted?projection:null,
      ordinary_result_values_decoded:false,history_commands_executed:false,training_release:false,
      provenance_recovered:false};
    if(Buffer.byteLength(JSON.stringify(result))+1>limits.outputBytes)throw Error('OUTPUT_BOUND');
    return result;
  }
  return {feed,finish};
}
module.exports={ROOT,SCHEMA,EXPECTED_SHA,LIMITS,EXECUTION_AUTHORIZED,lexicalJson,exactReceipt,
  prettyBytes,unescapeSelected,authenticateText,outputRange,createRecovery};
if(require.main===module){
  process.stdout.write('{"status":"DISABLED_PENDING_SCOPE_AND_INDEPENDENT_REVIEW","execution_authorized":false}\n');
  process.exitCode=2;
}
