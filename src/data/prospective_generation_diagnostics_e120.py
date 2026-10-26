"""Phase-bound generation diagnostics registry. No ignored unknown warnings.

Exact frozen Tcl echoes are code, not executed error diagnostics. Known search
warnings remain explicit outcome risks, never harmlessness or D95 proofs.
Only the deployment controller can bind a policy to independently reviewed bytes.
"""
import base64
import copy
import json
import re
from decimal import Decimal
from . import prospective_generation_recipe_e108 as recipe
from .direct_runtime_compatibility_e102 import warning_inventory

require, sha, canonical = recipe.require, recipe.sha, recipe.canonical
ERROR = re.compile(rb'(?<![A-Za-z0-9_])(?:ERRORS?|FATAL)(?![A-Za-z0-9_])', re.I)
INVALID_PATH = re.compile(rb'invalid[\s_-]+(?:(?:pin|file)[\s_-]+)?path(?:name)?(?![a-z0-9_])', re.I)
LIBRARY_LINE = b"//     All model attributes are from file '"
LIBRARY_TOKEN = b'EXACT_PINNED_LIBRARY_BYTES'
SCHEMA = 'prospective-generation-diagnostic-policy-e120-v1'


def strip_frozen_echo(raw, tcl):
    """Remove only complete exact frozen command echoes, including continuations."""
    require(type(raw) is bytes and len(raw) <= 16777216 and type(tcl) is bytes and
            sha(tcl) in {row[2] for row in recipe.SOURCE_PINS.values()}, 'FROZEN_TCL_ECHO_SOURCE')
    blocks, current, balance = {}, [], 0
    for line in tcl.splitlines():
        if not current and not line.strip():
            continue
        current.append(line)
        balance += line.count(b'{') - line.count(b'}')
        require(balance >= 0 and len(current) <= 64, 'FROZEN_TCL_COMMAND_BOUND')
        if balance == 0:
            first = b'//  command: '+current[0]
            block = [first] + [b'//           '+item for item in current[1:]]
            if ERROR.search(b'\n'.join(current)):
                blocks[first] = block
            current = []
    require(not current, 'FROZEN_TCL_COMMAND_UNCLOSED')
    lines, result, index = raw.splitlines(), [], 0
    omitted = 0
    while index < len(lines):
        block = blocks.get(lines[index])
        if block and lines[index:index+len(block)] == block:
            result.extend([b'// EXACT_FROZEN_TCL_CODE_ECHO']*len(block))
            omitted += 1
            index += len(block)
        else:
            result.append(lines[index])
            index += 1
    return b'\n'.join(result), omitted


def _normalize_library(block, library):
    expected = LIBRARY_LINE+library.encode('utf-8')+b"'."
    found = sum(line == expected for line in block)
    require(found == 1, 'EXACT_LIBRARY_ATTRIBUTE_SOURCE_LINE')
    return [LIBRARY_LINE+LIBRARY_TOKEN+b"'." if line == expected else line for line in block]


def extract(raw, library):
    """Return complete diagnostic blocks with phase; raw evidence is never changed."""
    lines = raw.splitlines()
    inventory = warning_inventory(raw)
    first_import = next((i for i, line in enumerate(lines)
                         if re.match(rb'^//  command: read_faults\b', line)), None)
    create = [i for i, line in enumerate(lines)
              if line == b'//  command: create_patterns -compaction_effort High -coverage_effort High']
    end_generation = next((i for i, line in enumerate(lines) if create and i > create[0] and
                           line.startswith(b'//  command: ')), len(lines))
    rows = []
    for warning in inventory['warnings']:
        start = warning['line_number']-1
        category = warning['category']
        if first_import is not None and start < first_import:
            phase = 'STARTUP'
            end = start+1
            if category == 'LIBRARY_ATTRIBUTE_MODELS_UNMATCHED':
                while end < len(lines) and not lines[end].startswith((b'//  ---', b'//  command:')):
                    require(end-start < 32, 'DIAGNOSTIC_BLOCK_BOUND')
                    end += 1
                normalized = _normalize_library(lines[start:end], library)
            else:
                while end < len(lines) and lines[end].startswith((b'//    ', b'    ')):
                    require(end-start < 32, 'DIAGNOSTIC_BLOCK_BOUND')
                    end += 1
                normalized = lines[start:end]
        else:
            phase = 'GENERATION' if len(create) == 1 and create[0] < start < end_generation else 'OTHER'
            end = start+1
            if b'Split capture handling is on but not needed.' in lines[start]:
                category, end = 'SPLIT_CAPTURE_COST_NOTICE', start+2
            elif b'Clock off simulation is on but not needed.' in lines[start]:
                category, end = 'CLOCK_OFF_COST_NOTICE', start+2
            elif lines[start] == b'//  Warning: Many unsuccessful tests. Terminating current ATPG phase.':
                category = 'UNSUCCESSFUL_SEARCH_PHASE'
            elif b'The number of AU faults has increased by' in lines[start]:
                category, end = 'AU_INCREASE_RISK', start+2
            # Capture unreviewed continuation text rather than silently truncate
            # a purportedly complete message at the expected line count.
            while end < len(lines):
                line = lines[end]
                table = line.startswith(b'// |')
                blank_or_border = (re.fullmatch(rb'// \| *\|', line) is not None or
                                   re.fullmatch(rb'// \| [-]+ \|', line) is not None)
                continuation = line.startswith((b'//    ', b'    ')) or (table and not blank_or_border)
                if not continuation:
                    break
                require(end-start < 32, 'DIAGNOSTIC_BLOCK_BOUND')
                end += 1
            normalized = lines[start:end]
        raw_block = b'\n'.join(lines[start:end])
        normalized_block = b'\n'.join(normalized)
        rows.append(dict(category=category, phase=phase, line_number=start+1,
            block_lines=end-start, raw_block_sha256=sha(raw_block),
            normalized_block_sha256=sha(normalized_block),
            block_base64=base64.b64encode(normalized_block).decode('ascii'),
            reported_number=warning['reported_number']))
    return rows, inventory['top_level_fault_import_commands_seen'], len(create)


def build_gate(raw_policy):
    require(type(raw_policy) is bytes and len(raw_policy) <= 65536, 'POLICY_BYTES')
    policy = json.loads(raw_policy.decode('ascii'))
    require(policy.get('schema') == SCHEMA and policy.get('library_sha256') == recipe.identities.LIBRARY_SHA256,
            'REVIEWED_GENERATION_POLICY_SCHEMA')
    require(set(policy.get('startup', {})) == {c+':'+m for c in ('aes_core', 'spi') for m in ('H','M','F')},
            'EXACT_SIX_STARTUP_PROFILES')
    tcls = {}
    for mode in ('H', 'M', 'F'):
        tcl = base64.b64decode(policy['effective_tcl_base64'][mode], validate=True)
        require(sha(tcl) == recipe.SOURCE_PINS['common' if mode == 'H' else 'incremental'][2],
                'POLICY_TCL_PIN')
        tcls[mode] = tcl
    generation = policy['generation']
    require(set(generation) == {'SPLIT_CAPTURE_COST_NOTICE', 'CLOCK_OFF_COST_NOTICE',
                               'UNSUCCESSFUL_SEARCH_PHASE', 'AU_INCREASE_RISK'}, 'KNOWN_GENERATION_KINDS')
    au_width = policy.get('au_table_line_bytes')
    require(type(au_width) is int and 64 <= au_width <= 256, 'FROZEN_AU_TABLE_WIDTH')

    def gate(raw, binding, envelope):
        mode, circuit = envelope['stage'], binding['circuit']
        require(mode in tcls and circuit in ('aes_core', 'spi'), 'DIAGNOSTIC_CONTEXT')
        library = recipe.ROOT+'/'+circuit+'/inputs/'+circuit+'/cells.lib'
        require(envelope['env']['CELL_LIBRARY'] == library, 'DEPLOYED_LIBRARY_PATH')
        filtered, omitted = strip_frozen_echo(raw, tcls[mode])
        require(ERROR.search(filtered) is None and INVALID_PATH.search(filtered) is None,
                'ACTUAL_ERROR_DIAGNOSTIC')
        rows, imports, creates = extract(filtered, library)
        require(imports == (1 if mode == 'H' else 2) and creates == 1, 'EXACT_GENERATION_PHASES')
        lines = filtered.splitlines()
        actual_imports = [(i, line) for i, line in enumerate(lines)
                          if re.match(rb'^//  command: read_faults\b', line)]
        wanted_imports = ([b'//  command: read_faults $source -show_warnings'] if mode == 'H' else
            [b'//  command: read_faults $common_source -show_warnings',
             b'//  command: read_faults $status -merge -show_warnings'])
        create_index = next(i for i, line in enumerate(lines)
            if line == b'//  command: create_patterns -compaction_effort High -coverage_effort High')
        post_commands = [(i, line) for i, line in enumerate(lines)
                         if i > create_index and line.startswith(b'//  command: ')]
        require([line for i, line in actual_imports] == wanted_imports and
                actual_imports[-1][0] < create_index and post_commands and
                post_commands[0][1] == b'//  command: report_statistics -detailed_analysis > [file join $out statistics.rpt]',
                'FROZEN_IMPORT_GENERATION_REPORT_ORDER')
        startup = [row for row in rows if row['phase'] == 'STARTUP']
        wanted = policy['startup'][circuit+':'+mode]
        require([{k: row[k] for k in ('category','block_lines','normalized_block_sha256','reported_number')}
                 for row in startup] == wanted, 'STARTUP_DIAGNOSTIC_CHANGED')
        counts, reviewed = {}, []
        for row in rows:
            if row['phase'] == 'STARTUP':
                reviewed.append(dict(row, disposition='REVIEWED_FROZEN_INPUT_STARTUP_NOT_HARMLESSNESS'))
                continue
            require(row['phase'] == 'GENERATION' and row['category'] in generation, 'UNKNOWN_WARNING_OR_PHASE')
            kind = row['category']
            counts[kind] = counts.get(kind, 0)+1
            cap = 4 if kind in ('AU_INCREASE_RISK', 'UNSUCCESSFUL_SEARCH_PHASE') else 1
            require(counts[kind] <= cap, 'WARNING_OCCURRENCE_BOUND')
            template = base64.b64decode(generation[kind], validate=True)
            block = base64.b64decode(row['block_base64'], validate=True)
            if kind == 'AU_INCREASE_RISK':
                percent = re.search(rb'([0-9]{1,8}\.[0-9]{2})% since the start of this ATPG run\.', block)
                require(percent is not None and Decimal(percent.group(1).decode('ascii')) <=
                        Decimal(100*recipe.identities.COUNTS[circuit]),
                        'AU_PERCENTAGE_GRAMMAR')
                wanted_lines, actual_lines = template.splitlines(), block.splitlines()
                require(len(wanted_lines) == len(actual_lines) == 2 and
                        actual_lines[0] == wanted_lines[0] and wanted_lines[1].endswith(b'|'),
                        'GENERATION_WARNING_BLOCK_CHANGED')
                core = wanted_lines[1][:-1].replace(b'EXACT_BOUNDED_PERCENT', percent.group(1)).rstrip(b' ')
                require(len(core)+2 <= au_width, 'AU_PERCENTAGE_GRAMMAR')
                rendered = core+b' '*(au_width-len(core)-1)+b'|'
                require(actual_lines[1] == rendered, 'AU_FIXED_TABLE_PADDING_CHANGED')
                block = template
            require(block == template, 'GENERATION_WARNING_BLOCK_CHANGED')
            reviewed.append(dict(row, disposition='RECORDED_SEARCH_OR_CONTROL_OUTCOME_RISK_NOT_HARMLESSNESS'))
        return dict(schema='generation-diagnostics-review-e120-v1', passed=True,
            source_policy_sha256=sha(raw_policy), reviewed=reviewed, warning_count=len(reviewed),
            frozen_code_echo_blocks_omitted=omitted, unknown_warnings_ignored=0,
            quality_harmlessness_proven=False, outcome_risks_remain=True,
            d95_verified=False, training_release=False)
    return gate
