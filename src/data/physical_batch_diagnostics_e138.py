"""Pure bounded diagnostics, not an execution authority or cleanup receipt.

Stages describe a step about to be attempted, never proof it completed.
Unknown errors are redacted without formatting or retaining the exception.
"""

STAGES = ('ADMISSION','HOST_CLOCK','BOOTSTRAP','LAUNCH_SPEC','ENGINE_COLLECTION',
    'INSTANCE_BUILD','ROOT_SERVICES','INITIAL_INTENT','ROOT_CREATE','SOURCE_COPY',
    'RECIPE_WRITE','DEPENDENCIES','SELFCHECKS','PRELAUNCH_RECHECK','LAUNCH_DEBIT',
    'TOOL_OBSERVATION','RAW_PUBLICATION','ROOT_RECEIPT')

# Exact, manually selected checks. Never infer membership from a prefix.
ERROR_CODES = frozenset((
    'E138_REMOTE_PACKAGE_UNRELEASED',
    'E138_FREEZE_NOT_CONFIGURED',
    'BATCH_FIXED_HOST_PLATFORM','BATCH_ORIGINAL_BOOT','BATCH_ORIGINAL_DEADLINE',
    'BATCH_SAMPLED_MEMORY','BATCH_SAMPLED_STORAGE','BATCH_VENDOR_LD_ORDER',
    'BATCH_THREE_SELFCHECKS','BATCH_INSTALLED_SOURCE_OR_SELECTION_DRIFT',
    'E137_BOOTSTRAP_AUTH_CONTEXT_BOOT_NOT_FROZEN','E137_BOOTSTRAP_EXACT_PACKAGE',
    'E137_BOOTSTRAP_FROZEN_BYTES','E137_BOOTSTRAP_ACTUAL_REPLY',
    'E137_BOOTSTRAP_ORIGINAL_CLOCK','E137_BOOTSTRAP_SOURCE_LOADER',
    'E137_BOOTSTRAP_OBSERVER_ARGUMENTS','E137_ONE_BOOTSTRAP_NO_RETRY',
    'E137_BOOTSTRAP_FAILED_NO_RETRY',
    'ENGINE_VENDOR_CHAIN_MISSING','ENGINE_OBSERVED_BRANCH_NOT_VIABLE',
    'ROOT_RECEIPT_FROZEN_SOURCE_AUTH','ROOT_RECEIPT_EXACT_INPUT_BYTES',
    'ROOT_RECEIPT_GENUINE_REGISTERED_FILES_REQUIRED'))

EXCEPTION_TYPES = {ValueError:'VALUE_ERROR',TypeError:'TYPE_ERROR',
    KeyError:'KEY_ERROR',OSError:'OS_ERROR',FileNotFoundError:'FILE_NOT_FOUND',
    PermissionError:'PERMISSION_ERROR',TimeoutError:'TIMEOUT_ERROR',
    MemoryError:'MEMORY_ERROR',RuntimeError:'RUNTIME_ERROR',
    KeyboardInterrupt:'INTERRUPTED',SystemExit:'SYSTEM_EXIT'}


def safe_error(exc):
    kind=next((label for cls,label in EXCEPTION_TYPES.items() if type(exc) is cls),'OTHER_EXCEPTION')
    code='REDACTED_UNKNOWN_ERROR'
    # Exact builtin ValueError only: a subclass may override args access.
    if type(exc) is ValueError:
        args=exc.args
        if type(args) is tuple and len(args)==1 and type(args[0]) is str and len(args[0])<=96 and args[0] in ERROR_CODES:
            code=args[0]
    return dict(error_kind=kind,error_code=code)


class DiagnosticState(object):
    __slots__=('_stage','_debit','_instance','_terminal')

    def __init__(self):
        self._stage='ADMISSION';self._debit=0;self._instance=None;self._terminal=False

    def checkpoint(self,stage):
        if self._terminal or type(stage) is not str or stage not in STAGES:
            raise ValueError('E138_DIAGNOSTIC_STAGE_REJECTED')
        if STAGES.index(stage)<STAGES.index(self._stage):
            raise ValueError('E138_DIAGNOSTIC_STAGE_REGRESSION')
        self._stage=stage

    def instance_constructed(self,digest):
        if (self._terminal or self._instance is not None or self._stage!='INSTANCE_BUILD' or
                type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)):
            raise ValueError('E138_DIAGNOSTIC_INSTANCE_REJECTED')
        self._instance=digest

    def consume_launch(self):
        if self._terminal or self._debit!=0 or self._stage!='LAUNCH_DEBIT':
            raise ValueError('E138_DIAGNOSTIC_DEBIT_REJECTED')
        self._debit=1

    def failure(self,exc):
        if self._terminal:
            raise ValueError('E138_DIAGNOSTIC_ALREADY_TERMINAL')
        self._terminal=True
        value=dict(schema='e138-bounded-failure-diagnostic-v1',
            stage_attempted=self._stage,stage_completion_verified=False,
            launch_debit=self._debit,instance_sha256=self._instance,
            owned_root=None,cleanup_verified=False,evidence_durability_verified=False,
            retry_allowed=False,execution_ready=False,physical_d95_verified=False)
        value.update(safe_error(exc))
        return value
