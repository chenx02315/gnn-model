"""Exclusive E108 input preparation, never a runner or permission controller.

Linux anchored IO is required. An injected trusted controller must admit every
operation; its return is only a caller claim here. IO-phase errors retain partial
output and poison the object. Validation/admission rejection does not mutate or
poison it. No resume, cleanup, subprocess, network or resource grant.
"""
import copy
import os

from . import prospective_acceptance_materializer_v1 as io
from . import prospective_tessent_acceptance_v1 as pins
from . import prospective_generation_recipe_e108 as recipe

E88_SHA256 = 'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8'
SCHEMA = 'prospective-generation-materialization-e111-v1'
require = pins.require
sha = pins.sha
canonical = pins.canonical


def _receipt(path, count, digest):
    return dict(path=path, bytes=count, sha256=digest)


def _hash_file(path, count, parent_identity=None):
    """Reuse bounded stable-source hashing without retaining file bodies."""
    parent, name = path.rsplit('/', 1)
    fd = io._directory(parent)
    discard = None
    try:
        if parent_identity is not None:
            info = os.fstat(fd)
            require((info.st_dev, info.st_ino) == parent_identity, 'BUNDLE_REPLACED')
        discard = os.open('/dev/null', os.O_WRONLY | os.O_NOFOLLOW)
        _, size, digest = io._read_at(fd, name, [0], sink=discard,
                                     expected_bytes=count, max_bytes=count)
        return _receipt(path, size, digest)
    finally:
        if discard is not None:
            os.close(discard)
        os.close(fd)


def _copy_file(source, destination, count, digest, destination_identity=None):
    require(type(count) is int and 0 < count <= io.MAX_FILE, 'FILE_SIZE_BOUND')
    parent, name = source.rsplit('/', 1)
    target_parent, target_name = destination.rsplit('/', 1)
    src = io._directory(parent)
    dst = out = None
    try:
        dst = io._directory(target_parent)
        if destination_identity is not None:
            info = os.fstat(dst)
            require((info.st_dev, info.st_ino) == destination_identity, 'BUNDLE_REPLACED')
        out = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW, 0o600, dir_fd=dst)
        _, size, observed = io._read_at(src, name, [0], sink=out,
                                       expected_bytes=count, max_bytes=count)
        require(observed == digest, 'SOURCE_FILE_SHA')
        os.fsync(out)
        os.fsync(dst)
        result = _hash_file(destination, count, destination_identity)
        require(result['sha256'] == digest, 'COPY_FILE_SHA')
        require(_hash_file(source, count)['sha256'] == digest, 'SOURCE_REREAD_SHA')
        return result
    finally:
        for fd in (out, dst, src):
            if fd is not None:
                os.close(fd)


class Materializer(object):
    def __init__(self, raw_e85, raw_e88, raw_e93, common_base_bytes,
                 incremental_base_bytes, authorize):
        require(callable(authorize), 'CALLER_ADMISSION_CALLBACK_REQUIRED')
        self.e85 = pins.observation(raw_e85, pins.E85_SHA256, pins.E85_SHA256, 'E85')
        self.trees = pins.validate_e85(self.e85)
        self.e93 = pins.observation(raw_e93, pins.E93_SHA256, pins.E93_SHA256, 'E93')
        pins.validate_e93(self.e93)
        self.e88 = pins.observation(raw_e88, E88_SHA256, E88_SHA256, 'E88')
        require(self.e88.get('schema') == 'e88-acquisition-semantics-probe-v1' and
                self.e88.get('status') == 'PASS_BOUNDED_NAMESPACE_SETS_AND_LAUNCHER_BODY_ONLY' and
                self.e88.get('execution_ready') is False, 'E88_STATUS')
        self.common = {}
        for row in self.e88['roots']:
            circuit = row['circuit']
            require(circuit in pins.TOPS and circuit not in self.common and
                    row['expected_common_count'] == pins.COUNTS[circuit] and
                    set(row['files']) == {'manifest.json', 'canonical_fault_mapping.tsv',
                        'H_common_initial_faults.basic', 'M_common_initial_faults.basic',
                        'F_common_initial_faults.basic'}, 'E88_COMMON_SET')
            for name, pin in row['files'].items():
                require(type(pin['bytes']) is int and 0 < pin['bytes'] <= io.MAX_FILE and
                        pins.SHA_RE.fullmatch(pin['sha256']) is not None, 'E88_FILE_PIN')
                role = {'manifest.json': 'manifest', 'canonical_fault_mapping.tsv': 'mapping',
                        'M_common_initial_faults.basic': 'M_basic',
                        'F_common_initial_faults.basic': 'F_basic'}.get(name)
                if role is not None:
                    require(any(p == dict(circuit=circuit, role=role, **pin)
                                for p in self.e93['input_files']), 'E88_E93_PIN_MISMATCH')
            self.common[circuit] = copy.deepcopy(row['files'])
        require(set(self.common) == set(pins.TOPS), 'E88_CIRCUIT_SET')
        for row in self.trees.values():
            require(type(row['body_bytes']) is int and 0 < row['body_bytes'] <= io.MAX_TREE,
                    'TREE_SIZE_BOUND')
        self.sources = recipe.freeze_sources(common_base_bytes, incremental_base_bytes)
        self.authorize = authorize
        self.directories = {}
        self.started = self.failed = self.closed = False
        self.bundle_receipt = None
        self.runs = {}
        self.prepared_translations = {}
        self.attempts = set()

    def _admit(self, operation, envelope_sha256=None, semantic_binding_sha256=None):
        request = dict(schema=SCHEMA, operation=operation, root=recipe.ROOT,
                       effective_envelope_sha256=envelope_sha256,
                       semantic_binding_sha256=semantic_binding_sha256,
                       grants_execution_authority=False)
        require(self.authorize(copy.deepcopy(request)) is True, 'CALLER_ADMISSION_REQUIRED')

    def _owned(self, path):
        require(path in self.directories, 'DIRECTORY_NOT_OWNED')
        fd = io._directory(path)
        try:
            info = os.fstat(fd)
            require((info.st_dev, info.st_ino) == self.directories[path], 'BUNDLE_REPLACED')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _mkdir(self, path):
        parent, name = path.rsplit('/', 1)
        fd = self._owned(parent) if self.started else io._directory(parent)
        child = None
        try:
            child = io._mkdir(fd, name)
            info = os.fstat(child)
            self.directories[path] = (info.st_dev, info.st_ino)
        finally:
            if child is not None:
                os.close(child)
            os.close(fd)

    def _publish(self, path, raw):
        parent, name = path.rsplit('/', 1)
        fd = self._owned(parent)
        try:
            io._publish(fd, name, raw)
        finally:
            os.close(fd)
        return _receipt(path, len(raw), sha(raw))

    def _seal(self, path, body):
        body = dict(body, schema=SCHEMA, caller_admission_claim=True,
                    caller_admission_authenticated=False, execution_authorized=False,
                    execution_ready=False, training_release=False)
        body['receipt_sha256'] = sha(canonical(body))
        publication = self._publish(path, canonical(body) + b'\n')
        return dict(body, receipt_file=publication)

    def initialize_bundle(self):
        require(not self.started and not self.failed and not self.closed, 'NO_RESUME')
        self._admit('INITIALIZE_FIXED_E108_INPUTS')
        try:
            self._mkdir(recipe.ROOT)
            self.started = True
            self._mkdir(recipe.ROOT + '/code')
            files = []
            for name in ('common', 'incremental'):
                files.append(self._publish(recipe.ROOT + '/code/' + name + '.tcl',
                                           self.sources[name]['tcl_bytes']))
            for circuit in ('aes_core', 'spi'):
                base = recipe.ROOT + '/' + circuit
                for suffix in ('', '/inputs', '/inputs/' + circuit,
                               '/03_fault_universe', '/03_fault_universe/common_frozen', '/runs'):
                    self._mkdir(base + suffix)
                library = base + '/inputs/' + circuit + '/cells.lib'
                files.append(_copy_file(pins.LIBRARY, library, self.e85['library']['bytes'],
                                        pins.LIBRARY_SHA256,
                                        self.directories[base + '/inputs/' + circuit]))
                source = pins.PHASE4 + '/' + circuit + '/03_fault_universe/common_' + circuit + '_m16_phase4_v2/'
                target = base + '/03_fault_universe/common_frozen/'
                for name in sorted(self.common[circuit]):
                    pin = self.common[circuit][name]
                    files.append(_copy_file(source + name, target + name, pin['bytes'], pin['sha256'],
                                            self.directories[target[:-1]]))
            self.bundle_receipt = self._seal(recipe.ROOT + '/materialization_receipt.json',
                dict(status='INPUTS_PUBLISHED_NOT_EXECUTED', files=files,
                     observation_sha256=dict(e85=pins.E85_SHA256, e88=E88_SHA256, e93=pins.E93_SHA256)))
            return copy.deepcopy(self.bundle_receipt)
        except BaseException:
            self.failed = True
            raise

    def materialize_attempt(self, freeze, binding):
        require(self.started and not self.failed and not self.closed, 'BUNDLE_NOT_ACTIVE')
        self._check_freeze(freeze)
        envelope = recipe.compile_execution(freeze, binding, self.sources)
        circuit = envelope['circuit']
        run_identity = (binding['request']['run_uid'], freeze['freeze_sha256'])
        require(circuit not in self.runs or self.runs[circuit] == run_identity,
                'CIRCUIT_RUN_OR_FREEZE_CHANGED')
        if envelope['stage'] != 'H':
            require(self.prepared_translations.get(binding['task_uid']) ==
                    (binding['translation_task_uid'], run_identity), 'TRANSLATION_PREPARATION_REQUIRED')
        self._admit('PREPARE_FRESH_ATTEMPT_INPUTS', envelope['envelope_sha256'],
                    binding['binding_sha256'])
        env = envelope['env']
        run = env['CIRCUIT_ROOT'] + '/runs/' + binding['request']['run_uid']
        tree_path = env['TSDB_INPUT_DIR']
        tree = self.trees[(envelope['circuit'], envelope['stage'])]
        bounds = dict(expected_bytes=tree['body_bytes'], expected_files=tree['regular_files_hashed'],
                      expected_directories=tree['directories'])
        try:
            # Recheck shared deployed inputs before each future attempt.
            for item in self.bundle_receipt['files']:
                parent = item['path'].rsplit('/', 1)[0]
                require(_hash_file(item['path'], item['bytes'], self.directories[parent]) == item,
                        'DEPLOYED_INPUT_CHANGED')
            if run not in self.directories:
                for suffix in ('', '/tsdb', '/logs', '/attempts', '/attempts/_prereq'):
                    self._mkdir(run + suffix)
            self._mkdir(tree_path)
            fd = self._owned(tree_path)
            try:
                require(io._tree(tree['root'], fd, **bounds) == tree['tree_sha256'], 'SOURCE_TREE_SHA')
            finally:
                os.close(fd)
            fd = self._owned(tree_path)
            os.close(fd)
            require(io._tree(tree_path, **bounds) == tree['tree_sha256'], 'COPY_TREE_SHA')
            fd = self._owned(tree_path)
            os.close(fd)
            require(io._tree(tree['root'], **bounds) == tree['tree_sha256'], 'SOURCE_REREAD_TREE_SHA')
            prereq = run + '/attempts/_prereq/' + binding['request']['attempt_uid']
            if envelope['stage'] == 'H':
                self._mkdir(prereq)
            else:
                fd = self._owned(prereq)
                os.close(fd)
            # Reviewed Tcl creates result_dir itself; never pre-create it or its log.
            for path in (envelope['result_dir'], envelope['argv'][5]):
                parent, name = path.rsplit('/', 1)
                fd = self._owned(parent)
                try:
                    try:
                        os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ValueError('OUTPUT_ALREADY_EXISTS')
                finally:
                    os.close(fd)
            receipt = self._seal(prereq + '/input_materialization_receipt.json', dict(
                status='ATTEMPT_INPUTS_PUBLISHED_NOT_EXECUTED',
                effective_envelope_sha256=envelope['envelope_sha256'],
                bundle_receipt_sha256=self.bundle_receipt['receipt_sha256'],
                circuit=envelope['circuit'], task_uid=envelope['task_uid'],
                tsdb=dict(path=tree_path, bytes=tree['body_bytes'], sha256=tree['tree_sha256'],
                          sha256_scope='E85_SORTED_CHILD_DEPTH_FIRST_TREE',
                          regular_files=tree['regular_files_hashed'], directories=tree['directories']),
                tcl_path=envelope['argv'][7], result_dir=envelope['result_dir'],
                log_path=envelope['argv'][5], prereq_dir=prereq,
                translation_outputs_materialized=False, result_dir_created=False,
                log_created=False, resource_budget=None))
            self.runs[circuit] = run_identity
            self.attempts.add(binding['task_uid'])
            return receipt
        except BaseException:
            self.failed = True
            raise

    def prepare_translation(self, freeze, binding):
        """Reserve exact target prerequisite before the translation DAG commit.

        No translation bodies, receipt authentication, launch count or MTFI SHA
        are inferred from the E86 small translation-reference object.
        """
        require(self.started and not self.failed and not self.closed, 'BUNDLE_NOT_ACTIVE')
        self._check_freeze(freeze)
        require(type(binding) is dict and set(binding) == recipe.BINDING_KEYS and
                binding['schema'] == recipe.bindings.SCHEMA and binding['kind'] == 'TRANSLATION' and
                sha(canonical({k: v for k, v in binding.items() if k != 'binding_sha256'})) ==
                binding['binding_sha256'], 'TRANSLATION_BINDING_CHANGED')
        plan = recipe.pilot.build_plan()
        phase = next(p for p in plan['phases'] if p['circuit'] == freeze['circuit'])
        slot = binding['slot']
        require(type(slot) is int and 0 < slot < len(phase['tasks']) - 1, 'TRANSLATION_SLOT')
        node, target = phase['tasks'][slot:slot + 2]
        require(node['kind'] == 'TRANSLATION' and target['kind'] == 'TESSENT' and
                binding['plan_sha256'] == freeze['plan_sha256'] and
                binding['freeze_sha256'] == freeze['freeze_sha256'] and
                binding['circuit'] == freeze['circuit'] and
                binding['task_uid'] == node['task_uid'] and binding['action_uid'] == node['action_uid'] and
                binding['target_mode'] == node['target_mode'] == target['stage'] and
                binding['parent_task_uid'] == node['parent_result_task_uid'] and
                node['task_uid'] == target['depends_on'][1] and
                binding['parent_task_uid'] in self.attempts, 'EXACT_TRANSLATION_TASK')
        require(binding['compilation_ready'] is False and binding['caller_claims_not_os_proof'] is True and
                binding['execution_ready'] is False and binding['training_release'] is False and
                all(binding[key] is None for key in ('request', 'recipe', 'control',
                    'translation_task_uid', 'translation_result_sha256', 'translation_receipt_sha256')) and
                all(type(binding[key]) is str and recipe.stage.SHA.fullmatch(binding[key]) is not None
                    for key in ('previous_receipt_sha256', 'parent_result_sha256', 'parent_receipt_sha256')),
                'TRANSLATION_CLAIM_SHAPE')
        circuit = freeze['circuit']
        require(circuit in self.runs and self.runs[circuit][1] == freeze['freeze_sha256'], 'REGISTERED_RUN_REQUIRED')
        run_identity = self.runs[circuit]
        base = recipe.ROOT + '/' + circuit
        prereq = base + '/runs/' + run_identity[0] + '/attempts/_prereq/' + target['task_uid']
        self._admit('PREPARE_TRANSLATION_INPUTS', semantic_binding_sha256=binding['binding_sha256'])
        try:
            self._mkdir(prereq)
            common = base + '/03_fault_universe/common_frozen/'
            inputs = []
            for name in ('manifest.json', 'canonical_fault_mapping.tsv', target['stage'] + '_common_initial_faults.basic'):
                pin = self.common[circuit][name]
                item = _hash_file(common + name, pin['bytes'], self.directories[common[:-1]])
                require(item['sha256'] == pin['sha256'], 'DEPLOYED_INPUT_CHANGED')
                inputs.append(item)
            receipt = self._seal(prereq + '/translation_preparation_receipt.json', dict(
                status='TRANSLATION_INPUTS_PREPARED_NOT_TRANSLATED', target_task_uid=target['task_uid'],
                semantic_binding_sha256=binding['binding_sha256'],
                translation_task_uid=node['task_uid'], inputs=inputs,
                target_native_common_faults=common + target['stage'] + '_common_initial_faults.basic',
                mapping=common + 'canonical_fault_mapping.tsv', manifest=common + 'manifest.json',
                output_status_file=prereq + '/translated_status.mtfi',
                output_manifest=prereq + '/translation_manifest.json',
                translation_reference_is_native_mtfi_hash=False, translation_outputs_materialized=False))
            self.prepared_translations[target['task_uid']] = (node['task_uid'], run_identity)
            return receipt
        except BaseException:
            self.failed = True
            raise

    def _check_freeze(self, freeze):
        recipe.requests.validate_freeze(freeze)
        circuit = freeze['circuit']
        require(freeze['common_fault_count'] == pins.COUNTS[circuit], 'FROZEN_COMMON_COUNT_MISMATCH')
        require(freeze['authenticated_input_manifest_sha256'] ==
                self.common[circuit]['manifest.json']['sha256'], 'FROZEN_MANIFEST_SHA_MISMATCH')

    def close(self):
        self.closed = True
