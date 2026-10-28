"""Local-only evidence-bound preparation; not a remote or Tessent executor."""
import base64
import hashlib
import json
import re

E128_SHA = 'd70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
E134_FILE_SHA = '0469bb1c0c18404c790efb3f0eeae89148d505549e1bf4b0809a0443b1e16e3a'
E134_AUDIT_SHA = '5a398e911d13f8a5c73032b6caeb73a0f50531d50faab080158b1fb9f308c831'
ROOT = '/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1'
F_UID = 'aes_core:HF:h1:F'
TCL_SHA = '50982a3c1b9b93b452313ef503bbfe6d17a44f7f3a018334041244807587dafe'
DRIVER_SHA = '4c089a2410fcaebc6aed3167a8b4b14015cf8afad5d8e7a019078679d78d7d94'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def build_plan(e128_raw, e134_raw):
    require(type(e128_raw) is bytes and len(e128_raw) <= 1048576 and sha(e128_raw) == E128_SHA,
            'EXACT_EXISTING_E128_RESPONSE')
    require(type(e134_raw) is bytes and len(e134_raw) <= 65536 and sha(e134_raw) == E134_FILE_SHA,
            'EXACT_SEALED_E134_AUDIT_FILE')
    response, audit = decode(e128_raw), decode(e134_raw)
    require(response.get('capture_complete') is True and response.get('error') is None,
            'COMPLETE_EXISTING_CAPTURE')
    saved = audit.pop('audit_sha256', None)
    require(saved == E134_AUDIT_SHA == sha(canonical(audit)) and
            audit.get('synthetic_only') is False and audit.get('status') == 'UNPROVEN' and
            audit.get('common_count') == 71216 and audit.get('H_physical_DT_count') == 18323 and
            audit.get('physical_HF_D95_verified') is False and audit.get('training_release') is False,
            'SEALED_PRIOR_DIAGNOSTIC_NOT_PHYSICAL_PASS')

    def body(path, pin):
        found = [row for row in response['files'] if row['path'] == path]
        require(len(found) == 1, 'EXACT_EXISTING_SOURCE_ROW')
        row = found[0]
        raw = base64.b64decode(row['body_base64'], validate=True)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'] == pin,
                'COMPLETE_EXISTING_SOURCE_PIN')
        return raw.decode('ascii')

    tcl = body(ROOT + '/code/incremental.tcl', TCL_SHA)
    driver = body(ROOT + '/aes_core/runs/e116-aes_core/logs/F_' + F_UID + '.log', DRIVER_SHA)
    export = 'write_patterns [file join $out tester.stil] -stil -replace'
    require(tcl.splitlines().count(export) == 1 and
            driver.splitlines().count('//  command: ' + export) == 1,
            'PATTERN_EXPORT_SOURCE_AND_OBSERVED_COMMAND')
    require(driver.index('//  command: ' + export) < driver.index('MAPPED_INCREMENTAL_ATPG_STATUS=PASS\n') and
            driver.splitlines().count('MAPPED_INCREMENTAL_RUN_ID=' + F_UID) == 1,
            'EXACT_COMPLETED_F_DRIVER')
    counts = re.findall(r'^#test_patterns\s+([0-9]+)\s*$', driver, re.M)
    require(bool(counts) and int(counts[-1]) == 256, 'ORIGINAL_REPORTED_PATTERN_COUNT')

    plan = dict(schema='physical-pattern-replay-local-plan-e135-v1',
        status='LOCAL_PREPARATION_ONLY_NEW_REMOTE_AUTHORIZATION_REQUIRED',
        e128_response_sha256=E128_SHA, e134_audit_sha256=E134_AUDIT_SHA,
        source_tcl_sha256=TCL_SHA, source_driver_sha256=DRIVER_SHA,
        circuit='aes_core', mode='F', action_uid='aes_core:HF:h1',
        common_count=71216, d95_integer_threshold=67656,
        H_proven_DT_count=18323, H_proven_DT_set_sha256=audit['H_physical_DT_set_sha256'],
        candidate_pattern=dict(
            path=ROOT + '/aes_core/runs/e116-aes_core/attempts/F_' + F_UID + '/tester.stil',
            export_declared_in_frozen_source=True, export_command_observed=True,
            file_exists_verified=False, bytes=None, sha256=None,
            imported_pattern_count_verified=False, original_generated_report_count=256),
        proposed_stages=[
            'Bounded exact-path stat/full hash of existing STIL and source-input identity verification',
            'Freeze one fresh isolated F4 simulation recipe and exact packet; independent review',
            'Fresh F state with complete baseline-only common faults and no H/F post-state merge',
            'Read the authenticated existing external F patterns; fault simulate only',
            'Export complete pre/post native faults, group reports, statistics and pattern import counts',
            'Canonical H-proven union fresh F-simulated hard detections; independent set recomputation'],
        simulation_command_family=['read_patterns', 'simulate_patterns -source external'],
        exact_Stuck_STIL_command_options_verified=False,
        independent_final_recipe_reviewed=False,
        required_stop_gates=[
            'Pattern absent, oversized, changed or not provenance-bound',
            'Exact same F design, library, scan mode or constraints not verified',
            'Unreviewed command options, unsupported STIL import, skipped/zero/mismatched patterns',
            'Foreign detected-status import, retained old patterns, or non-baseline pre-state credit',
            'Missing/duplicate/mode-outside fault keys or unsupported PT/PD detection credit',
            'First failure, uncertain process cleanup, resource or time budget exceeded'],
        old_artifacts_may_be_modified=False, LSF_allowed=False,
        proposed_ATPG_generations=0, proposed_new_pattern_generations=0,
        measured_ATPG_speedup=False, runtime_label_qualified=False,
        user_authorization_received=False, remote_calls_authorized=0,
        Tessent_launches_authorized=0, execution_ready=False,
        physical_HF_D95_verified=False, certificate_sealed=False, training_release=False)
    plan['plan_sha256'] = sha(canonical(plan))
    return plan
