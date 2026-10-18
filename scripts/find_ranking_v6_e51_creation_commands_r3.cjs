'use strict';
// E51: creator-command hints only. No execution proof, result content, or data opens.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const { isUtf8 } = require('node:buffer');

const ROOT = 'C:/Users/86155/.codex/sessions/2026/07/25/rollout-2026-07-25T22-51-41-019f99c2-b229-7f42-8f37-255b4339afc8.jsonl';
const COMPRESSED_DIR = 'C:/Users/86155/.codex/sessions/2026/10/02';
const LIMITS = Object.freeze({ inputBytes: 512*1024*1024, decodedPerFile: 32*1024*1024,
  decodedTotal: 128*1024*1024, lineBytes: 2*1024*1024, files: 12,
  records: 100, outputBytes: 65536 });
const MARKERS = ['build_formal_candidate_space_v2', 'source_provenance_v2.tsv', 'formal_candidate_space_v2'].map(x => Buffer.from(x));
const DATE = Buffer.from('"2026-10-02T');
const DENIED = /multimode_ate_gnn_v1|checkpoints?|BLIND|outcome|rawdata|raw_data|labels?|password|token|secret|credential/i;

function structuralSelector(buffer) {
  const white = b => b===32||b===9||b===13||b===10;
  const ws = i => { while(white(buffer[i]))i++; return i; };
  const hex = b => b>=48&&b<=57||b>=65&&b<=70||b>=97&&b<=102;
  function stringEnd(start) {
    if(buffer[start]!==34)throw Error('STRING');
    for(let i=start+1;i<buffer.length;i++){
      const b=buffer[i];
      if(b===34)return i+1;
      if(b<32)throw Error('CONTROL');
      if(b===92){
        const escape=buffer[++i];
        if(escape===117){
          for(let j=0;j<4;j++)if(!hex(buffer[++i]))throw Error('UNICODE_ESCAPE');
        }else if(![34,92,47,98,102,110,114,116].includes(escape))throw Error('ESCAPE');
      }
    }
    throw Error('STRING_END');
  }
  function valueEnd(start,depth=0){
    if(depth>64)throw Error('STRUCTURE_DEPTH');
    let i=ws(start);
    if(buffer[i]===34)return stringEnd(i);
    if(buffer[i]===123){
      i=ws(i+1);if(buffer[i]===125)return i+1;
      while(i<buffer.length){
        i=ws(stringEnd(i));if(buffer[i++]!==58)throw Error('COLON');
        i=ws(valueEnd(i,depth+1));
        if(buffer[i]===125)return i+1;
        if(buffer[i++]!==44)throw Error('COMMA');
        i=ws(i);
      }
      throw Error('OBJECT_END');
    }
    if(buffer[i]===91){
      i=ws(i+1);if(buffer[i]===93)return i+1;
      while(i<buffer.length){
        i=ws(valueEnd(i,depth+1));if(buffer[i]===93)return i+1;
        if(buffer[i++]!==44)throw Error('ARRAY_COMMA');i=ws(i);
      }
      throw Error('ARRAY_END');
    }
    for(const token of ['true','false','null']){
      const bytes=Buffer.from(token);
      if(buffer.subarray(i,i+bytes.length).equals(bytes))return i+bytes.length;
    }
    if(buffer[i]===45)i++;
    if(buffer[i]===48)i++;
    else {
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
    return i;
  }
  function fields(start,allowed){
    const tokens=allowed.map(key=>[key,Buffer.from('"'+key+'"')]);
    let i=ws(start);
    if(buffer[i++]!==123)throw Error('OBJECT');
    const found=new Map();
    i=ws(i);if(buffer[i]===125)return {found,end:i+1};
    while(i<buffer.length){
      const keyStart=i,keyEnd=stringEnd(i);
      const keyBytes=buffer.subarray(keyStart,keyEnd);
      // Escaped envelope keys are outside format coverage; never decode them.
      if(keyBytes.includes(92))throw Error('ESCAPED_ENVELOPE_KEY');
      const key=tokens.find(([,token])=>keyBytes.equals(token));
      i=ws(keyEnd);if(buffer[i++]!==58)throw Error('COLON');
      i=ws(i);const end=valueEnd(i);
      if(key){
        if(found.has(key[0]))throw Error('DUPLICATE_KNOWN_KEY');
        found.set(key[0],[i,end]);
      }
      i=ws(end);if(buffer[i]===125)return {found,end:i+1};
      if(buffer[i++]!==44)throw Error('COMMA');i=ws(i);
    }
    throw Error('OBJECT_END');
  }
  return {fields,ws};
}

function commandEnvelope(buffer) {
  const parser=structuralSelector(buffer);
  function equals(found,key,literal){
    const range=found.get(key);
    return range&&buffer.subarray(...range).equals(Buffer.from('"'+literal+'"'));
  }
  try{
    const root=parser.fields(0,['timestamp','type','payload']);
    if(parser.ws(root.end)!==buffer.length||!equals(root.found,'type','response_item'))return null;
    const timestamp=root.found.get('timestamp'),payload=root.found.get('payload');
    if(!timestamp||!payload||!buffer.subarray(timestamp[0],timestamp[0]+DATE.length).equals(DATE))return null;
    const call=parser.fields(payload[0],['type','call_id','name','arguments','input','status']);
    if(call.end!==payload[1])return null;
    const kind=['function_call','custom_tool_call'].find(x=>equals(call.found,'type',x));
    const name=['exec_command','functions.exec_command','tools.exec_command','exec','functions.exec','tools.exec']
      .find(x=>equals(call.found,'name',x));
    if(!kind||!name||call.found.has(kind==='function_call'?'input':'arguments'))return null;
    const command=call.found.get(kind==='function_call'?'arguments':'input');
    if(!command||buffer[command[0]]!==34)return null;
    const callId=call.found.get('call_id');
    if(callId&&buffer[callId[0]]!==34&&!buffer.subarray(...callId).equals(Buffer.from('null')))return null;
    const status=call.found.get('status');
    if(status&&!['null','"completed"','"in_progress"','"incomplete"']
      .some(value=>buffer.subarray(...status).equals(Buffer.from(value))))return null;
    return {kind,name,timestamp,command};
  }catch{return null;}
}

function decodeSelectedString(buffer,range){
  const bytes=buffer.subarray(...range);
  if(!isUtf8(bytes))throw Error('SELECTED_UTF8');
  const result=JSON.parse(bytes.toString('utf8'));
  if(typeof result!=='string')throw Error('SELECTED_STRING');
  return result;
}

function selectedExecCommand(argumentsText){
  const buffer=Buffer.from(argumentsText,'utf8'),parser=structuralSelector(buffer);
  const args=parser.fields(0,['cmd']);
  const command=args.found.get('cmd');
  if(parser.ws(args.end)!==buffer.length||!command||buffer[command[0]]!==34)throw Error('CMD_FIELD');
  return decodeSelectedString(buffer,command);
}

function cleanPath(value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 350) return null;
  value = value.replace(/\\/g, '/').replace(/^[\"']|[\"',;)]+$/g, '');
  if (!/^[A-Za-z0-9_./: -]+$/.test(value) || value.includes('://') ||
      value.split('/').includes('..') || DENIED.test(value)) return null;
  if (value.includes(' ') && (!value.startsWith('C:/Users/86155/Desktop/new lab/') ||
      value.slice('C:/Users/86155/Desktop/new lab/'.length).includes(' '))) return null;
  if (!(['/ssd/cjc/', '/temp/jiangchuanc/', '/home/cjc/', '/home/jiangchuanc/', 'C:/Users/86155/Desktop/new lab/'].some(prefix => value.startsWith(prefix)) || /^(?:\.\/)?(?:data|inputs?|artifacts|package|formal_candidate_space|runtime_training)/.test(value))) return null;
  return value;
}

function selectedPaths(command) {
  const found = new Map();
  function add(kind, text) {
    const value = cleanPath(text);
    if (value) found.set(kind + ':' + value, {kind, value});
  }
  for (const m of command.matchAll(/--(output-root|candidate-root)(?:=|\s+)(?:["']([^"'\r\n]+)["']|([^\s"'\r\n;]+))/g)) {
    add('argv_' + m[1].replace('-', '_'), m[2] || m[3]);
  }
  for (const m of command.matchAll(/[A-Za-z0-9_./:-]*(?:formal_candidate_space_v2|source_provenance_v2\.tsv|receipt_v2\.json)[A-Za-z0-9_./:-]*/g)) {
    add('metadata_path', m[0]);
  }
  for (const m of command.matchAll(/["']([^"'\r\n]*(?:formal_candidate_space_v2|source_provenance_v2\.tsv|receipt_v2\.json)[^"'\r\n]*)["']/g)) {
    add('metadata_path', m[1]);
  }
  return [...found.values()].sort((a,b) => (a.kind + a.value).localeCompare(b.kind + b.value)).slice(0, 12);
}


// Metadata-only diagnostics: structurally skip bodies without UTF-8/JSON decoding.
function formatOf(buffer) {
  const diagnosticKeys = ['timestamp','type','payload','call_id','name','arguments','input','status',
    'id','role','content','output','summary','encrypted_content','recipient','channel','phase'];
  const keyTokens = diagnosticKeys.map(key=>[key,Buffer.from('"'+key+'"')]);
  const white = b => b === 32 || b === 9 || b === 13 || b === 10;
  const ws = i => { while (white(buffer[i])) i++; return i; };
  function stringEnd(i) {
    if (buffer[i++] !== 34) throw Error('STRING');
    while (i < buffer.length) {
      if (buffer[i] === 92) { i += 2; continue; }
      if (buffer[i++] === 34) return i;
    }
    throw Error('STRING_END');
  }
  function endValue(i, depth = 0) {
    if (depth > 64) throw Error('DEPTH');
    i = ws(i);
    if (buffer[i] === 34) return stringEnd(i);
    if (buffer[i] === 123 || buffer[i] === 91) {
      const close = buffer[i++] === 123 ? 125 : 93;
      while ((i = ws(i)) < buffer.length) {
        if (buffer[i] === close) return i + 1;
        if ([44,58].includes(buffer[i])) { i++; continue; }
        if ([93,125].includes(buffer[i])) throw Error('MISMATCH');
        i = endValue(i, depth + 1);
      }
      throw Error('END');
    }
    const start = i;
    while (i < buffer.length && !white(buffer[i]) && ![44,58,93,125].includes(buffer[i])) i++;
    if (i === start) throw Error('VALUE');
    return i;
  }
  function object(i) {
    i = ws(i);
    if (buffer[i++] !== 123) throw Error('OBJECT');
    const fields = [];
    if (buffer[ws(i)] === 125) return {fields, end: ws(i)+1};
    while (i < buffer.length) {
      i = ws(i);
      const keyEnd = stringEnd(i);
      const key = keyTokens.find(([,token])=>buffer.subarray(i,keyEnd).equals(token))?.[0] || 'UNKNOWN_KEY';
      if (fields.length >= 32) throw Error('KEY_BOUND');
      i = ws(keyEnd);
      if (buffer[i++] !== 58) throw Error('COLON');
      i = ws(i);
      const end = endValue(i);
      const b = buffer[i];
      const kind = b===34?'string':b===123?'object':b===91?'array':b===110?'null':
        b===116||b===102?'boolean':b===45||b>=48&&b<=57?'number':'unknown';
      fields.push({key, kind, start:i, end});
      i = ws(end);
      if (buffer[i] === 125) return {fields, end:i+1};
      if (buffer[i++] !== 44) throw Error('COMMA');
    }
    throw Error('OBJECT_END');
  }
  function one(fields, key) {
    const matches = fields.filter(x => x.key===key);
    return matches.length===1?matches[0]:null;
  }
  function known(field, values) {
    if (!field || field.kind!=='string') return 'MISSING_OR_NONSTRING';
    return values.find(v => buffer.subarray(field.start,field.end).equals(Buffer.from('"'+v+'"'))) || 'OTHER';
  }
  try {
    const root = object(0);
    if (ws(root.end)!==buffer.length) throw Error('TRAILING');
    const timestamp = one(root.fields,'timestamp');
    if (!timestamp || !buffer.subarray(timestamp.start,timestamp.start+DATE.length).equals(DATE)) return null;
    const payloadField = one(root.fields,'payload');
    const payload = payloadField && payloadField.kind==='object' ? object(payloadField.start).fields : [];
    const types = ['response_item','event_msg','session_meta','turn_context','function_call','custom_tool_call',
      'function_call_output','custom_tool_call_output','message','reasoning','agent_message','user_message'];
    const tools = ['functions.exec','functions.exec_command','tools.exec','tools.exec_command','exec','exec_command'];
    const shape = fields => fields.map(({key,kind})=>({key,kind})).sort((a,b)=>a.key.localeCompare(b.key));
    return {root_type:known(one(root.fields,'type'),types), payload_type:known(one(payload,'type'),types),
      toolname:known(one(payload,'name'),tools),root_keys:shape(root.fields),payload_keys:shape(payload)};
  } catch {
    return {root_type:'FORMAT_UNSUPPORTED',payload_type:'UNKNOWN',toolname:'UNKNOWN',root_keys:[],payload_keys:[]};
  }
}

function makeScanner(limits = LIMITS) {
  const records = [], seen = new Set(), formats = new Map();
  const diagnostic = {formats: [], format_bound_skipped_lines: 0, metadata_only: true};
  const stats = { lines: 0, oversized_lines: 0, preselected_lines: 0, envelope_skipped_lines: 0,
    selected_command_records: 0, records_dropped: 0 };
  let pending = Buffer.alloc(0), discarding = false, filename = null;
  function line(buffer) {
    stats.lines++;
    // Unselected bytes are never UTF-8 decoded or JSON parsed.
    if (!buffer.includes(DATE) || !MARKERS.some(x => buffer.includes(x))) return;
    const format = formatOf(buffer);
    if (format) {
      const formatKey = JSON.stringify(format);
      if (formats.has(formatKey)) formats.get(formatKey).count++;
      else if (formats.size < 64) {
        const row = {...format,count:1};
        formats.set(formatKey,row); diagnostic.formats.push(row);
      } else diagnostic.format_bound_skipped_lines++;
    }
    const envelope = commandEnvelope(buffer);
    if (!envelope) { stats.envelope_skipped_lines++; return; }
    stats.preselected_lines++;
    let timestamp,command;
    try {
      timestamp=decodeSelectedString(buffer,envelope.timestamp);
      command=decodeSelectedString(buffer,envelope.command);
      if(envelope.name.endsWith('exec_command')) command=selectedExecCommand(command);
    } catch { return; }
    const name=envelope.name,callType=envelope.kind;
    if (!MARKERS.some(x => command.includes(x.toString('ascii')))) return;
    const snippets = selectedPaths(command);
    if (!snippets.length) return;
    stats.selected_command_records++;
    const hasInvocation = /\bpython(?:3|\.exe)?\s+(?:-[^\s]+\s+)*(?:-m\s+src\.data\.build_formal_candidate_space_v2(?:\s|$)|["']?(?:[A-Za-z0-9_./:-]*\/)?build_formal_candidate_space_v2\.py(?:["']?\s|["']?$))/.test(command);
    const record = { filename, timestamp, toolname: name, recordtype: callType, has_invocation: hasInvocation,
      evidence: 'COMMAND_RECORD_NOT_EXECUTION_PROOF', snippets };
    const key = JSON.stringify(record);
    if (seen.has(key)) return;
    if (records.length >= limits.records) { stats.records_dropped++; return; }
    seen.add(key);
    records.push(record);
  }
  function feed(chunk) {
    if (!Buffer.isBuffer(chunk)) throw Error('BUFFER_ONLY');
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 10) continue;
      const part = chunk.subarray(start, i);
      if (!discarding) {
        if (pending.length + part.length > limits.lineBytes) {
          stats.oversized_lines++; stats.lines++;
        } else {
          line(pending.length ? Buffer.concat([pending, part]) : part);
        }
      } else stats.lines++;
      pending = Buffer.alloc(0); discarding = false; start = i + 1;
    }
    const rest = chunk.subarray(start);
    if (!discarding && pending.length + rest.length > limits.lineBytes) {
      stats.oversized_lines++; pending = Buffer.alloc(0); discarding = true;
    } else if (!discarding && rest.length) {
      pending = pending.length ? Buffer.concat([pending, rest]) : Buffer.from(rest);
    }
  }
  function begin(name) {
    if (filename !== null) throw Error('FILE_NOT_FINISHED');
    if (typeof name !== 'string' || path.basename(name) !== name || name.length > 200) throw Error('FILENAME_SCOPE');
    filename = name;
  }
  function finish() {
    if (pending.length && !discarding) line(pending);
    else if (discarding) stats.lines++;
    pending = Buffer.alloc(0); discarding = false; filename = null;
  }
  return { begin, feed, finish, records, stats, diagnostic, identityCount: () => seen.size };
}

function packet(scanner, coverage, limits = LIMITS) {
  const result = { status: 'PASS_BOUNDED_CREATION_SELECTED_COMMANDS',
    evidence: 'COMMAND_RECORD_NOT_EXECUTION_PROOF',
    scope_date: '2026-10-02', records: scanner.records, counts: scanner.stats, coverage, diagnostic: scanner.diagnostic,
    data_files_opened: false, network_used: false, training_release: false };
  while (Buffer.byteLength(JSON.stringify(result)) + 1 > limits.outputBytes && result.records.length) {
    result.records.pop(); result.counts.records_dropped++;
  }
  while (Buffer.byteLength(JSON.stringify(result)) + 1 > limits.outputBytes && result.diagnostic.formats.length) {
    result.diagnostic.format_bound_skipped_lines += result.diagnostic.formats.pop().count;
  }
  if (Buffer.byteLength(JSON.stringify(result)) + 1 > limits.outputBytes) throw Error('OUTPUT_BOUND');
  return result;
}

async function scanFiles(specs, opener, limits = LIMITS) {
  if (!Array.isArray(specs) || specs.length > limits.files) throw Error('FILE_COUNT_BOUND');
  const scanner = makeScanner(limits);
  const coverage = { files: [], input_bytes: 0, compressed_decoded_bytes: 0,
    frozen_prefix_only: true, append_ignored: true, global_history_absence_claimed: false };
  const used = new Set();
  let globalBound = false;
  for (const spec of specs) {
    if (used.has(spec.filename)) throw Error('DUPLICATE_FILE');
    used.add(spec.filename);
    if (!Number.isSafeInteger(spec.size) || spec.size < 0) throw Error('SIZE_BOUND');
    const row = { filename: spec.filename, frozen_input_bytes: spec.size,
      input_bytes: 0, decoded_bytes: 0, complete_frozen_prefix: false, bound_reached: false };
    coverage.files.push(row);
    if (globalBound) { row.bound_reached = true; continue; }
    scanner.begin(spec.filename);
    const input = await opener(spec);
    let decoded, sourceStream, localBound = false;
    async function* boundedInput() {
      for await (const chunk of input) {
        const remaining = Math.min(spec.size - row.input_bytes, limits.inputBytes - coverage.input_bytes);
        if (remaining <= 0) { localBound = row.input_bytes < spec.size; break; }
        const part = chunk.subarray(0, remaining);
        row.input_bytes += part.length; coverage.input_bytes += part.length;
        yield part;
        if (part.length < chunk.length || row.input_bytes === spec.size) {
          if (row.input_bytes < spec.size) localBound = true;
          break;
        }
      }
    }
    try {
      sourceStream = Readable.from(boundedInput());
      decoded = spec.compressed ? sourceStream.pipe(zlib.createZstdDecompress()) : sourceStream;
      if (spec.compressed) sourceStream.on('error', err => decoded.destroy(err));
      for await (const chunk of decoded) {
        let room = chunk.length;
        if (spec.compressed) room = Math.min(room, limits.decodedPerFile - row.decoded_bytes,
          limits.decodedTotal - coverage.compressed_decoded_bytes);
        if (room > 0) {
          scanner.feed(chunk.subarray(0, room)); row.decoded_bytes += room;
          if (spec.compressed) coverage.compressed_decoded_bytes += room;
        }
        if (room < chunk.length) { localBound = true; break; }
      }
      row.complete_frozen_prefix = !localBound && row.input_bytes === spec.size;
      row.bound_reached = localBound;
      if (coverage.input_bytes >= limits.inputBytes || coverage.compressed_decoded_bytes >= limits.decodedTotal) globalBound = true;
    } finally {
      if (decoded) decoded.destroy();
      if (sourceStream) sourceStream.destroy();
      input.destroy();
      scanner.finish();
    }
  }
  return packet(scanner, coverage, limits);
}

async function terminalRun(operation, cleanup, emit) {
  let result, failed = false;
  try { result = await operation(); } catch { failed = true; }
  try { await cleanup(); } catch { failed = true; }
  if (failed) {
    emit({status:'FAIL_CLOSED_CREATION_SELECTED_COMMANDS',code:'BOUNDED_HISTORY_REJECTED'});
    return 2;
  }
  emit(result);
  return 0;
}

async function main() {
  const handles = [];
  return terminalRun(async () => {
    if (process.argv.length !== 2) throw Error('FIXED_SCOPE_NO_ARGUMENTS');
    if (typeof zlib.createZstdDecompress !== 'function') throw Error('ZSTD_UNAVAILABLE');
    const names = fs.readdirSync(COMPRESSED_DIR, {withFileTypes:true}).filter(x=>x.name.endsWith('.jsonl.zst'));
    if (names.length!==11 || names.some(x=>!x.isFile()||x.isSymbolicLink())) throw Error('FROZEN_COMPRESSED_FILE_COUNT');
    const filenames = [ROOT,...names.map(x=>COMPRESSED_DIR+'/'+x.name).sort()];
    const specs = [];
    for (let i=0;i<filenames.length;i++) {
      const filename=filenames[i], before=fs.lstatSync(filename);
      if (!before.isFile()||before.isSymbolicLink()) throw Error('FIXED_FILE_ONLY');
      const handle=await fs.promises.open(filename,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
      handles.push(handle);
      const st=await handle.stat();
      if (!st.isFile()||!Number.isSafeInteger(st.size)||before.dev!==st.dev||before.ino!==st.ino) throw Error('FIXED_FILE_ONLY');
      specs.push({filename:path.basename(filename),handle,size:st.size,compressed:i!==0});
    }
    return scanFiles(specs,async spec=>spec.size?
      spec.handle.createReadStream({autoClose:false,start:0,end:spec.size-1}):Readable.from([]));
  }, async () => {
    // FileHandle owns each descriptor; close is idempotent if a stream already closed it.
    const results=await Promise.allSettled(handles.map(handle=>handle.close()));
    if (results.some(result=>result.status==='rejected')) throw Error('CLEANUP_REJECTED');
  }, result=>process.stdout.write(JSON.stringify(result)+'\n'));
}

module.exports={ROOT,COMPRESSED_DIR,LIMITS,cleanPath,selectedPaths,commandEnvelope,structuralSelector,decodeSelectedString,selectedExecCommand,formatOf,makeScanner,scanFiles,packet,terminalRun};
if(require.main===module)main().then(code=>{process.exitCode=code;}).catch(()=>{process.exitCode=2;});


