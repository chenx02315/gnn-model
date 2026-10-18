'use strict';
// E51: creator-command hints only. No execution proof, result content, or data opens.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');

const ROOT = 'C:/Users/86155/.codex/sessions/2026/07/25/rollout-2026-07-25T22-51-41-019f99c2-b229-7f42-8f37-255b4339afc8.jsonl';
const COMPRESSED_DIR = 'C:/Users/86155/.codex/sessions/2026/10/02';
const LIMITS = Object.freeze({ inputBytes: 512*1024*1024, decodedPerFile: 32*1024*1024,
  decodedTotal: 128*1024*1024, lineBytes: 2*1024*1024, files: 12,
  records: 100, outputBytes: 65536 });
const MARKERS = ['build_formal_candidate_space_v2', 'source_provenance_v2.tsv', 'formal_candidate_space_v2'].map(x => Buffer.from(x));
const DATE = Buffer.from('"2026-10-02T');
const DENIED = /multimode_ate_gnn_v1|checkpoints?|BLIND|outcome|rawdata|raw_data|labels?|password|token|secret|credential/i;

function commandEnvelope(buffer) {
  // Select structural root/payload fields without decoding ANY string values.
  // Escaped envelope keys/type/name values are deliberately unsupported and skipped.
  const whitespace = b => b === 32 || b === 9 || b === 13 || b === 10;
  const ws = start => { while (whitespace(buffer[start])) start++; return start; };
  function stringEnd(start) {
    if (buffer[start] !== 34) throw Error('STRING');
    for (let i = start + 1; i < buffer.length; i++) {
      if (buffer[i] === 92) { i++; continue; }
      if (buffer[i] === 34) return i + 1;
    }
    throw Error('STRING_END');
  }
  function valueEnd(start, depth = 0) {
    if (depth > 64) throw Error('ENVELOPE_DEPTH');
    start = ws(start);
    if (buffer[start] === 34) return stringEnd(start);
    if (buffer[start] === 123 || buffer[start] === 91) {
      const close = buffer[start] === 123 ? 125 : 93;
      let i = start + 1;
      while ((i = ws(i)) < buffer.length) {
        if (buffer[i] === close) return i + 1;
        if (buffer[i] === 44 || buffer[i] === 58) { i++; continue; }
        if (buffer[i] === 125 || buffer[i] === 93) throw Error('MISMATCH');
        const next = valueEnd(i, depth + 1);
        if (next <= i) throw Error('VALUE');
        i = next;
      }
      throw Error('CONTAINER_END');
    }
    let i = start;
    while (i < buffer.length && !whitespace(buffer[i]) && ![44,58,93,125].includes(buffer[i])) i++;
    if (i === start) throw Error('PRIMITIVE');
    return i;
  }
  function fields(start, allowed) {
    const targets = allowed.map(key => [key, Buffer.from('"' + key + '"')]);
    let i = ws(start);
    if (buffer[i++] !== 123) throw Error('OBJECT');
    const found = new Map();
    if (buffer[ws(i)] === 125) return { found, end: ws(i) + 1 };
    while (i < buffer.length) {
      i = ws(i);
      const keyEnd = stringEnd(i);
      const key = targets.find(([, token]) => buffer.subarray(i, keyEnd).equals(token));
      if (!key) throw Error('UNKNOWN_OR_ESCAPED_ENVELOPE_KEY');
      i = ws(keyEnd);
      if (buffer[i++] !== 58) throw Error('COLON');
      i = ws(i);
      const end = valueEnd(i);
      if (key) {
        if (found.has(key[0])) throw Error('DUPLICATE_ENVELOPE_KEY');
        found.set(key[0], [i, end]);
      }
      i = ws(end);
      if (buffer[i] === 125) return { found, end: i + 1 };
      if (buffer[i++] !== 44) throw Error('COMMA');
    }
    throw Error('OBJECT_END');
  }
  function equals(found, key, literal) {
    const range = found.get(key);
    return range && buffer.subarray(...range).equals(Buffer.from('"' + literal + '"'));
  }
  try {
    const root = fields(0, ['timestamp', 'type', 'payload']);
    if (ws(root.end) !== buffer.length || !equals(root.found, 'type', 'response_item')) return null;
    const timestamp = root.found.get('timestamp');
    if (!timestamp || !buffer.subarray(timestamp[0], timestamp[0] + DATE.length).equals(DATE)) return null;
    const payload = root.found.get('payload');
    if (!payload) return null;
    const call = fields(payload[0], ['type', 'call_id', 'name', 'arguments', 'input', 'status']);
    if (call.end !== payload[1]) return null;
    const kind = ['function_call', 'custom_tool_call'].find(x => equals(call.found, 'type', x));
    const tool = ['exec_command', 'functions.exec_command', 'tools.exec_command', 'exec', 'functions.exec', 'tools.exec']
      .find(x => equals(call.found, 'name', x));
    if (!kind || call.found.has(kind === 'function_call' ? 'input' : 'arguments')) return null;
    const command = call.found.get(kind === 'function_call' ? 'arguments' : 'input');
    if (!command || buffer[command[0]] !== 34) return null;
    const callId = call.found.get('call_id');
    if (callId && buffer[callId[0]] !== 34 && !buffer.subarray(...callId).equals(Buffer.from('null'))) return null;
    const status = call.found.get('status');
    if (status && !['null', '"completed"', '"in_progress"', '"incomplete"']
      .some(value => buffer.subarray(...status).equals(Buffer.from(value)))) return null;
    return kind && tool ? kind : null;
  } catch { return null; }
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

function makeScanner(limits = LIMITS) {
  const records = [], seen = new Set();
  const stats = { lines: 0, oversized_lines: 0, preselected_lines: 0, envelope_skipped_lines: 0,
    selected_command_records: 0, records_dropped: 0 };
  let pending = Buffer.alloc(0), discarding = false, filename = null;
  function line(buffer) {
    stats.lines++;
    // Unselected bytes are never UTF-8 decoded or JSON parsed.
    if (!buffer.includes(DATE) || !MARKERS.some(x => buffer.includes(x))) return;
    const callType = commandEnvelope(buffer);
    if (!callType) { stats.envelope_skipped_lines++; return; }
    stats.preselected_lines++;
    let obj;
    try { obj = JSON.parse(buffer.toString('utf8')); } catch { return; }
    if (!obj || typeof obj.timestamp !== 'string' || !/^2026-10-02T/.test(obj.timestamp)) return;
    const call = obj.type === 'response_item' ? obj.payload : null;
    if (!call || call.type !== callType || typeof call.name !== 'string') return;
    const name = call.name;
    if (!/^(?:(?:functions|tools)\.)?(?:exec_command|exec)$/.test(name)) return;
    let command = callType === 'function_call' ? call.arguments : call.input;
    if (typeof command !== 'string') return;
    if (name.endsWith('exec_command')) {
      try {
        const args = JSON.parse(command);
        if (!args || typeof args.cmd !== 'string') return;
        command = args.cmd;
      } catch { return; }
    }
    if (!MARKERS.some(x => command.includes(x.toString('ascii')))) return;
    const snippets = selectedPaths(command);
    if (!snippets.length) return;
    stats.selected_command_records++;
    const hasInvocation = /\bpython(?:3|\.exe)?\s+(?:-[^\s]+\s+)*(?:-m\s+src\.data\.build_formal_candidate_space_v2(?:\s|$)|["']?(?:[A-Za-z0-9_./:-]*\/)?build_formal_candidate_space_v2\.py(?:["']?\s|["']?$))/.test(command);
    const record = { filename, timestamp: obj.timestamp, toolname: name, recordtype: callType, has_invocation: hasInvocation,
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
  return { begin, feed, finish, records, stats, identityCount: () => seen.size };
}

function packet(scanner, coverage, limits = LIMITS) {
  const result = { status: 'PASS_BOUNDED_CREATION_COMMAND_HINTS',
    evidence: 'COMMAND_RECORD_NOT_EXECUTION_PROOF',
    scope_date: '2026-10-02', records: scanner.records, counts: scanner.stats, coverage,
    data_files_opened: false, network_used: false, training_release: false };
  while (Buffer.byteLength(JSON.stringify(result)) + 1 > limits.outputBytes && result.records.length) {
    result.records.pop(); result.counts.records_dropped++;
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

async function main() {
  if (process.argv.length !== 2) throw Error('FIXED_SCOPE_NO_ARGUMENTS');
  if (typeof zlib.createZstdDecompress !== 'function') throw Error('ZSTD_UNAVAILABLE');
  const names = fs.readdirSync(COMPRESSED_DIR, {withFileTypes: true})
    .filter(x => x.name.endsWith('.jsonl.zst'));
  if (names.length !== 11 || names.some(x => !x.isFile() || x.isSymbolicLink())) throw Error('FROZEN_COMPRESSED_FILE_COUNT');
  const filenames = [ROOT, ...names.map(x => COMPRESSED_DIR + '/' + x.name).sort()];
  const handles = [];
  try {
    const specs = filenames.map((filename, i) => {
      const before = fs.lstatSync(filename);
      if (!before.isFile() || before.isSymbolicLink()) throw Error('FIXED_FILE_ONLY');
      const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      handles.push(fd);
      const st = fs.fstatSync(fd);
      if (!st.isFile() || !Number.isSafeInteger(st.size) ||
          before.dev !== st.dev || before.ino !== st.ino) throw Error('FIXED_FILE_ONLY');
      return { filename: path.basename(filename), fullpath: filename, fd,
        size: st.size, compressed: i !== 0 };
    });
    const result = await scanFiles(specs, async spec => spec.size ?
      fs.createReadStream(null, {fd: spec.fd, autoClose: false, start: 0, end: spec.size - 1}) : Readable.from([]));
    process.stdout.write(JSON.stringify(result) + '\n');
  } finally {
    for (const fd of handles) fs.closeSync(fd);
  }
}

module.exports = { ROOT, COMPRESSED_DIR, LIMITS, cleanPath, selectedPaths, commandEnvelope, makeScanner, scanFiles, packet };
if (require.main === module) main().catch(() => {
  process.stdout.write('{"status":"FAIL_CLOSED_CREATION_COMMAND_HINTS","code":"BOUNDED_HISTORY_REJECTED"}\n');
  process.exitCode = 2;
});
