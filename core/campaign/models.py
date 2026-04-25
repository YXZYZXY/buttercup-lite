from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields as dataclass_fields
from typing import Any


# CampaignRound 字段说明：
# 如果 runtime_state.py 新增了写入 round record 的字段，
# 直接在这里补字段定义即可；
# 反序列化时会自动过滤未知字段，不会报错。
@dataclass
class CampaignRound:
    round: int
    origin_task_id: str
    target_mode: str
    status: str
    pov_count: int = 0
    traced_crash_count: int = 0
    session_index: int = 0
    session_budget_seconds: int = 0
    crash_count: int = 0
    new_confirmed_pov_count: int = 0
    new_raw_crash_count: int = 0
    new_traced_crash_count: int = 0
    corpus_count_before: int = 0
    corpus_count_after: int = 0
    new_corpus_files: int = 0
    shared_corpus_count_before: int = 0
    shared_corpus_count_after: int = 0
    shared_corpus_new_files: int = 0
    new_signature_count: int = 0
    cumulative_distinct_signature_count: int = 0
    traced_crash_signatures: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    coverage_snapshot_path: str | None = None
    coverage_feedback_manifest_path: str | None = None
    scheduler_feedback_consumption_path: str | None = None
    seed_mode: str | None = None
    seed_task_manifest_path: str | None = None
    selected_target: str | None = None
    selected_harness: str | None = None
    selected_target_function: str | None = None
    selected_binary_slice_focus: str | None = None
    reseeding_attempted: bool = False
    reseeding_triggered: bool = False
    reseeding_target_functions: list[str] = field(default_factory=list)
    reseeding_generated_seed_count: int = 0
    stalled: bool = False
    proxy_stalled: bool = False
    coverage_stalled: bool = False
    triggered_action_type: str | None = None
    uncovered_function_count: int = 0
    low_growth_function_count: int = 0
    campaign_exact_or_partial: str | None = None
    campaign_degraded_reason: str | None = None
    campaign_coverage_queue_count: int = 0
    campaign_low_growth_queue_count: int = 0
    campaign_uncovered_queue_count: int = 0
    campaign_partial_queue_count: int = 0
    campaign_stalled_queue_count: int = 0
    system_coverage_plane_queue_count: int = 0
    trace_exact_signature_count: int = 0
    loose_cluster_count: int = 0
    confirmed_family_count: int = 0
    family_diversification_triggered: bool = False
    family_stagnation_count: int = 0
    family_confirmation_backlog_count: int = 0
    family_confirmation_selected_clusters: list[str] = field(default_factory=list)
    unresolved_loose_cluster_count: int = 0
    promotion_blocker_count: int = 0
    candidate_bridge_triggered: bool = False
    candidate_bridge_count: int = 0
    trace_worthy_candidate_count: int = 0
    system_candidate_bridge_new_count: int = 0
    system_trace_worthy_new_count: int = 0
    system_low_growth_queue_count: int = 0
    system_uncovered_queue_count: int = 0
    system_stalled_target_count: int = 0
    system_shared_corpus_new_files: int = 0
    system_fabric_root: str | None = None
    binary_feedback_queue_count: int = 0
    binary_trace_admission_count: int = 0
    binary_trace_candidate_count: int = 0
    binary_ida_focus_count: int = 0
    binary_provenance_class: str | None = None
    binary_feedback_action: str | None = None
    binary_feedback_bridge_path: str | None = None
    binary_ida_runtime_view_path: str | None = None
    binary_trace_candidate_queue_path: str | None = None
    binary_signal_lift_total: int = 0
    binary_signal_lift_reason: str | None = None
    confirmed_pov_names: list[str] = field(default_factory=list)
    session_summary_path: str | None = None
    session_continuity_mode: str | None = None
    session_workspace_reused: bool = False
    previous_session_summary_path: str | None = None
    session_archive_root: str | None = None
    session_corpus_state_reference: str | None = None
    session_coverage_snapshot_reference: str | None = None
    session_stagnation_state: dict[str, Any] = field(default_factory=dict)
    llm_request_count_total: int = 0
    llm_success_count: int = 0
    llm_failure_count: int = 0
    next_action: str | None = None
    trace_family_manifest_path: str | None = None
    repro_family_manifest_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CAMPAIGN_ROUND_FIELD_NAMES = frozenset(field_def.name for field_def in dataclass_fields(CampaignRound))


def filter_campaign_round_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key in CAMPAIGN_ROUND_FIELD_NAMES
    }


@dataclass
class CampaignManifest:
    campaign_task_id: str
    benchmark: str
    origin_task_ids: list[str]
    campaign_duration_seconds: int | None = None
    campaign_started_at: str | None = None
    campaign_deadline_at: str | None = None
    campaign_heartbeat_at: str | None = None
    campaign_last_round_finished_at: str | None = None
    campaign_finished_at: str | None = None
    iterations_total: int = 0
    fuzz_time_total_seconds: float = 0.0
    new_corpus_files_total: int = 0
    total_raw_crash_count: int = 0
    total_traced_crash_count: int = 0
    distinct_pov_count: int = 0
    distinct_signature_count: int = 0
    trace_exact_signature_count: int = 0
    loose_cluster_count: int = 0
    confirmed_family_count: int = 0
    distinct_vuln_count: int = 0
    llm_request_count_total: int = 0
    llm_request_count_by_stage: dict[str, int] = field(default_factory=dict)
    llm_success_count: int = 0
    llm_failure_count: int = 0
    api_calls_per_hour: float = 0.0
    fuzz_session_count: int = 0
    harness_switch_count: int = 0
    reseed_trigger_count: int = 0
    exact_coverage_available_ratio: float = 0.0
    shared_corpus_growth_count: int = 0
    family_diversification_trigger_count: int = 0
    generalized_candidate_bridge_count: int = 0
    trace_worthy_candidate_count: int = 0
    system_candidate_bridge_count: int = 0
    system_trace_worthy_candidate_count: int = 0
    system_low_growth_queue_count: int = 0
    system_uncovered_queue_count: int = 0
    system_stalled_target_count: int = 0
    binary_signal_lift_count: int = 0
    binary_reseed_trigger_count: int = 0
    wall_clock_utilization_ratio: float = 0.0
    idle_gap_seconds: float = 0.0
    slot_start_time: str | None = None
    slot_end_time: str | None = None
    project_sequence: list[str] = field(default_factory=list)
    campaign_continuation_count: int = 0
    campaign_runtime_state_path: str | None = None
    rounds: list[CampaignRound] = field(default_factory=list)
    pov_inventory_path: str | None = None
    vuln_coverage_path: str | None = None
    signature_index_path: str | None = None
    pov_lineage_path: str | None = None
    found_vuln_ids: list[str] = field(default_factory=list)
    missing_vuln_ids: list[str] = field(default_factory=list)
    lifecycle_state: str = "running"
    checkpoint_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["rounds"] = [round_record.to_dict() for round_record in self.rounds]
        return payload
