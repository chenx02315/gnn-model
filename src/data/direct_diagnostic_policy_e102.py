"""Exact per-mode startup exceptions for fixed import execution, never D95.

Historical diagnostic blocks are observations, not declarations of harmlessness.
Unknown/changed/post-import warnings fail. The runner separately requires a
clean supervisor return and pins the tool/library/TSDB/Tcl inputs.
"""
import hashlib
import json
import re
from .direct_runtime_compatibility_e102 import warning_inventory

POLICY = json.loads("{\"cases\":[{\"circuit\":\"aes_core\",\"source_log_bytes\":11378,\"source_log_sha256\":\"4cf1469d35878711adb948163b39b26b29b28b6db827b6aae1cd6cf7cbce62c3\",\"transition\":\"H_TO_M\",\"warnings\":[{\"block_lines\":16,\"block_sha256\":\"81fe896fa399f0f8b850a44915325939b1145ac4f55cef6c5ad47f44d93ce645\",\"category\":\"LIBRARY_ATTRIBUTE_MODELS_UNMATCHED\",\"line_number\":49,\"message_sha256\":\"27c8821601aef17aa7e0f4d577161850ce604e1525a1d98afdfc064a35ec978e\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":null,\"reviewed_for_acceptance\":false,\"historical_block_sha256\":\"e1ecc981832d53d585ac5d2865ef871858c8f6e1ac3808c245866ab52d457cd2\",\"current_block_source_log_sha256\":\"2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d\"},{\"block_lines\":1,\"block_sha256\":\"91a6666f1b867f473910a0cce255f3dbebeb4d788db7b0f8dff1bda0510c5644\",\"category\":\"FN1\",\"line_number\":84,\"message_sha256\":\"91a6666f1b867f473910a0cce255f3dbebeb4d788db7b0f8dff1bda0510c5644\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":6,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"44472cc1409461aa884c7e378cd6226ed44969b45376ab2e9bd580f51c697bfb\",\"category\":\"FN4\",\"line_number\":85,\"message_sha256\":\"44472cc1409461aa884c7e378cd6226ed44969b45376ab2e9bd580f51c697bfb\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":637,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"0fb66c6462a6727ea36de725f867e303998c33adc7e6014efe36582207719f6c\",\"category\":\"D7_STABLE_HIGH_CLOCK_PORTS\",\"line_number\":123,\"message_sha256\":\"0fb66c6462a6727ea36de725f867e303998c33adc7e6014efe36582207719f6c\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":16,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"a8f98d63a5b55e55920548d6c3d49c2fbc711206fd04bef4ab9443872e5e6765\",\"category\":\"EDT_INITIALIZATION_OVERHEAD_PERCENT\",\"line_number\":129,\"message_sha256\":\"a8f98d63a5b55e55920548d6c3d49c2fbc711206fd04bef4ab9443872e5e6765\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":26,\"reviewed_for_acceptance\":false}]},{\"circuit\":\"aes_core\",\"source_log_bytes\":7857,\"source_log_sha256\":\"2104aa0dbacab38bee4df6a596058593296124fb6909b5c68778b63291496f4e\",\"transition\":\"H_TO_F\",\"warnings\":[{\"block_lines\":16,\"block_sha256\":\"81fe896fa399f0f8b850a44915325939b1145ac4f55cef6c5ad47f44d93ce645\",\"category\":\"LIBRARY_ATTRIBUTE_MODELS_UNMATCHED\",\"line_number\":47,\"message_sha256\":\"27c8821601aef17aa7e0f4d577161850ce604e1525a1d98afdfc064a35ec978e\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":null,\"reviewed_for_acceptance\":false,\"historical_block_sha256\":\"e1ecc981832d53d585ac5d2865ef871858c8f6e1ac3808c245866ab52d457cd2\",\"current_block_source_log_sha256\":\"2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d\"},{\"block_lines\":1,\"block_sha256\":\"91a6666f1b867f473910a0cce255f3dbebeb4d788db7b0f8dff1bda0510c5644\",\"category\":\"FN1\",\"line_number\":75,\"message_sha256\":\"91a6666f1b867f473910a0cce255f3dbebeb4d788db7b0f8dff1bda0510c5644\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":6,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"e4ad9663b9068f7b11cb04d897ead11bce49f03f2d37e6e5d934ccdf63b32f80\",\"category\":\"FN4\",\"line_number\":76,\"message_sha256\":\"e4ad9663b9068f7b11cb04d897ead11bce49f03f2d37e6e5d934ccdf63b32f80\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":541,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"fc8f2fae016409cc476e7b9ebacc4130ff8d68e3e7c5a87874a37d619609e180\",\"category\":\"D7_STABLE_HIGH_CLOCK_PORTS\",\"line_number\":93,\"message_sha256\":\"fc8f2fae016409cc476e7b9ebacc4130ff8d68e3e7c5a87874a37d619609e180\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":4,\"reviewed_for_acceptance\":false}]},{\"circuit\":\"spi\",\"source_log_bytes\":11031,\"source_log_sha256\":\"67bfcd8d22c4836347b175035be4562b40e1de465401726827faf3e8efc4889f\",\"transition\":\"H_TO_M\",\"warnings\":[{\"block_lines\":16,\"block_sha256\":\"81fe896fa399f0f8b850a44915325939b1145ac4f55cef6c5ad47f44d93ce645\",\"category\":\"LIBRARY_ATTRIBUTE_MODELS_UNMATCHED\",\"line_number\":49,\"message_sha256\":\"27c8821601aef17aa7e0f4d577161850ce604e1525a1d98afdfc064a35ec978e\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":null,\"reviewed_for_acceptance\":false,\"historical_block_sha256\":\"e1ecc981832d53d585ac5d2865ef871858c8f6e1ac3808c245866ab52d457cd2\",\"current_block_source_log_sha256\":\"2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d\"},{\"block_lines\":1,\"block_sha256\":\"7f16c8b38c23747691161e6593775ec2e1c9185ef1f00adb5fa6cf4a40d51a05\",\"category\":\"FN1\",\"line_number\":84,\"message_sha256\":\"7f16c8b38c23747691161e6593775ec2e1c9185ef1f00adb5fa6cf4a40d51a05\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":7,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"f4a269bece13734907446c02f6c506de3ca867dafeed2520efb1d88ccd6bab7f\",\"category\":\"FN4\",\"line_number\":85,\"message_sha256\":\"f4a269bece13734907446c02f6c506de3ca867dafeed2520efb1d88ccd6bab7f\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":336,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"0fb66c6462a6727ea36de725f867e303998c33adc7e6014efe36582207719f6c\",\"category\":\"D7_STABLE_HIGH_CLOCK_PORTS\",\"line_number\":123,\"message_sha256\":\"0fb66c6462a6727ea36de725f867e303998c33adc7e6014efe36582207719f6c\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":16,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"c364ed7a84ef4a1a109ad3a995875f6b258776deb64a378428f481081254f929\",\"category\":\"EDT_INITIALIZATION_OVERHEAD_PERCENT\",\"line_number\":129,\"message_sha256\":\"c364ed7a84ef4a1a109ad3a995875f6b258776deb64a378428f481081254f929\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":60,\"reviewed_for_acceptance\":false}]},{\"circuit\":\"spi\",\"source_log_bytes\":8345,\"source_log_sha256\":\"0c5a7cab0377a170c7ac2707b084aa246297018620642ec63c8aa38db826b647\",\"transition\":\"H_TO_F\",\"warnings\":[{\"block_lines\":16,\"block_sha256\":\"81fe896fa399f0f8b850a44915325939b1145ac4f55cef6c5ad47f44d93ce645\",\"category\":\"LIBRARY_ATTRIBUTE_MODELS_UNMATCHED\",\"line_number\":47,\"message_sha256\":\"27c8821601aef17aa7e0f4d577161850ce604e1525a1d98afdfc064a35ec978e\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":null,\"reviewed_for_acceptance\":false,\"historical_block_sha256\":\"e1ecc981832d53d585ac5d2865ef871858c8f6e1ac3808c245866ab52d457cd2\",\"current_block_source_log_sha256\":\"2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d\"},{\"block_lines\":1,\"block_sha256\":\"7f16c8b38c23747691161e6593775ec2e1c9185ef1f00adb5fa6cf4a40d51a05\",\"category\":\"FN1\",\"line_number\":75,\"message_sha256\":\"7f16c8b38c23747691161e6593775ec2e1c9185ef1f00adb5fa6cf4a40d51a05\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":7,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"663b338268d97a530175be3fcabfb6452b2d4a303f024d5cd0eaf3f087283315\",\"category\":\"FN4\",\"line_number\":76,\"message_sha256\":\"663b338268d97a530175be3fcabfb6452b2d4a303f024d5cd0eaf3f087283315\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":240,\"reviewed_for_acceptance\":false},{\"block_lines\":1,\"block_sha256\":\"fc8f2fae016409cc476e7b9ebacc4130ff8d68e3e7c5a87874a37d619609e180\",\"category\":\"D7_STABLE_HIGH_CLOCK_PORTS\",\"line_number\":93,\"message_sha256\":\"fc8f2fae016409cc476e7b9ebacc4130ff8d68e3e7c5a87874a37d619609e180\",\"phase\":\"STARTUP_BEFORE_FAULT_IMPORT\",\"reported_number\":4,\"reviewed_for_acceptance\":false}]}],\"historical_readback_sha256\":\"1b37434da83e2330d504e5781867bb18d2c050219cf808752d1c72c0eda7d04d\",\"schema\":\"e102-reviewed-startup-exceptions-v1\",\"scope\":\"FIXED_IMPORT_EXECUTION_ONLY_NOT_D95_OR_FAULT_SEMANTICS\",\"current_library_path\":\"/home/jiangchuanc/Desktop/work/SCC28NHK_HSC31_LVT_V0p1/liberty/0.8v/scc28nhk_hsc31_lvt_scan.tcelllib\",\"current_library_block_source_log_sha256\":\"2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d\",\"arbitrary_path_normalization_allowed\":false}")


def evaluate(log, marker, circuit, transition, tcl):
    result = dict(passed=False, d95_verified=False, fault_semantics_verified=False,
                  scope='FIXED_IMPORT_EXECUTION_ONLY_NOT_D95_OR_FAULT_SEMANTICS',
                  startup_exceptions=[], reason='UNVALIDATED')
    try:
        if type(log) is not bytes or len(log)>16777216 or type(tcl) is not bytes:
            raise ValueError('BOUNDED_BYTES_REQUIRED')
        candidates=[r for r in POLICY['cases'] if
                    (r['circuit'],r['transition'])==(circuit,transition)]
        if len(candidates)!=1:raise ValueError('UNREVIEWED_CASE')
        lines=log.splitlines()
        if re.search(rb'(?<![a-z0-9_])(?:errors?|fatal)(?![a-z0-9_])|invalid[\s_-]+(?:pin_pathname|(?:file[\s_-]+)?path(?:name)?)(?![a-z0-9_])',log,re.I):
            raise ValueError('TOOL_ERROR_DIAGNOSTIC')
        commands=[]
        for i,line in enumerate(lines):
            match=re.match(rb'^//\s+command:\s+(.*)$',line)
            if match:commands.append((i,match.group(1)))
        expected=[line for line in tcl.splitlines() if line.startswith(b'read_faults ')]
        actual=[(i,cmd) for i,cmd in commands if re.match(rb'read_faults\b',cmd)]
        if len(expected)!=2 or [cmd for i,cmd in actual]!=expected:
            raise ValueError('EXACT_TWO_IMPORT_COMMANDS_REQUIRED')
        for prefix in (b'read_cell_library ',b'read_design '):
            wanted=[line for line in tcl.splitlines() if line.startswith(prefix)]
            seen=[(i,cmd) for i,cmd in commands if cmd.startswith(prefix)]
            if len(wanted)!=1 or [cmd for i,cmd in seen]!=wanted or seen[0][0]>=actual[0][0]:
                raise ValueError('FROZEN_DESIGN_LIBRARY_COMMAND_REQUIRED')
        marks=[i for i,line in enumerate(lines) if line.strip()==marker]
        if len(marks)!=1 or marks[0]<=actual[-1][0]:
            raise ValueError('TAIL_MARKER_AFTER_IMPORTS_REQUIRED')
        inventory=warning_inventory(log)
        expected_warnings=candidates[0]['warnings']
        if len(inventory['warnings'])!=len(expected_warnings):
            raise ValueError('UNREVIEWED_WARNING_COUNT')
        for observed,pin in zip(inventory['warnings'],expected_warnings):
            start=observed['line_number']-1;end=start+1
            if observed['category']=='LIBRARY_ATTRIBUTE_MODELS_UNMATCHED':
                while end<len(lines) and not lines[end].startswith(b'//  ---') and not lines[end].startswith(b'//  command:'):
                    if end-start>=32:raise ValueError('DIAGNOSTIC_BLOCK_BOUND')
                    end+=1
            else:
                while end<len(lines) and (lines[end].startswith(b'//    ') or
                                          lines[end].startswith(b'    ')):
                    if end-start>=32:raise ValueError('DIAGNOSTIC_BLOCK_BOUND')
                    end+=1
            block=hashlib.sha256(b'\n'.join(lines[start:end])).hexdigest()
            if (start>=actual[0][0] or observed['category']!=pin['category'] or
                    observed['message_sha256']!=pin['message_sha256'] or
                    observed['reported_number']!=pin['reported_number'] or
                    block!=pin['block_sha256'] or end-start!=pin['block_lines']):
                raise ValueError('UNREVIEWED_WARNING_BLOCK_OR_PHASE')
            result['startup_exceptions'].append(dict(
                category=observed['category'],message_sha256=observed['message_sha256'],
                block_sha256=block,line_number=observed['line_number'],
                reviewed_startup_exception=True,quality_harmlessness_proven=False))
        result.update(passed=True,reason='EXACT_IMPORT_SEQUENCE_NO_NEW_DIAGNOSTIC',
                      source_log_sha256=candidates[0]['source_log_sha256'])
    except ValueError as exc:
        result['reason']=str(exc)
    return result
