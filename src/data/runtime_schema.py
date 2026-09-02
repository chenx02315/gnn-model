"""Shared, outcome-free schema for recovered ATPG runtime attempts."""
from __future__ import print_function

MANIFEST_V2_FIELDS = (
    "attempt_id", "adapter", "circuit", "family", "role", "cohort", "environment_cohort", "phase", "stage", "mode", "run_id",
    "run_id_source", "wall_s", "user_s", "system_s", "rss_kb", "exit_status",
    "timeout_status", "retry_order", "retry_order_status", "parse_status",
    "attempt_outcome_class", "semantics_status", "semantics_contract", "elapsed_source", "elapsed_semantics",
    "retry_group_id", "source_artifact", "source_artifact_sha256", "source_row_number", "source_log_path",
    "source_log_sha256", "inventory_manifest_sha256",
)
FORBIDDEN_OUTCOME_FIELDS = frozenset((
    "candidate", "candidate_uid", "patterns", "h_patterns", "m_patterns", "f_patterns",
    "cycles", "total_cycles", "detected_faults", "d95", "feasible_at_d95", "outcome_rank",
))
PHASE2_WALL_CONTRACT = "tessent_process_wall_seconds"
