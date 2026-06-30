"""
FedCloud Control Router

Classifies incoming telemetry events and routes them to the appropriate
verification engine — Lean 4 for deterministic controls, Bedrock agents
for qualitative controls.

Routing logic:
  1. Inspect event metadata for control family or cluster hint
  2. If deterministic (AC, IA, SC, CM, AU, SI state data) → Lean pipeline
  3. If qualitative (PS, AT, IR, CP, SA, SR artifacts) → Bedrock agent
  4. If ambiguous → evaluate content type (JSON config = Lean, PDF/text = Bedrock)
"""

import json
from dataclasses import dataclass
from typing import Optional

from agents.config import AgentConfig
from agents.clusters.personnel import PersonnelSecurityAgent
from agents.clusters.training import CybersecurityEducationAgent
from agents.clusters.incident_response import IncidentResponseAgent
from agents.clusters.recovery import RecoveryPlanningAgent
from agents.clusters.supply_chain import SupplyChainAgent
from agents.base_agent import AgentResult


@dataclass
class RoutingDecision:
    """Result of the routing classification."""
    engine: str          # "lean" | "bedrock"
    cluster: str         # Cluster name
    confidence: float    # 0.0 to 1.0
    reason: str          # Human-readable routing explanation


# Content type signals for routing
DETERMINISTIC_SIGNALS = {
    "sessions", "databases", "compute", "log_streams",
    "deployed_stores", "active_sessions", "nodes", "streams",
    "planned_values",  # Terraform
    "security_groups", "instances", "kms_keys",
}

QUALITATIVE_SIGNALS = {
    "background_checks", "nda_records", "personnel",
    "training_records", "certifications", "lms_completions",
    "incidents", "post_mortems", "pagerduty", "alerts",
    "dr_exercises", "backup_validations", "recovery_tests",
    "sbom", "dependencies", "vulnerabilities", "cve_analysis",
}

CLUSTER_AGENT_MAP = {
    "personnel": PersonnelSecurityAgent,
    "training": CybersecurityEducationAgent,
    "incident_response": IncidentResponseAgent,
    "recovery": RecoveryPlanningAgent,
    "supply_chain": SupplyChainAgent,
}


def classify_event(event: dict) -> RoutingDecision:
    """
    Classify an incoming telemetry event for routing.

    Args:
        event: Raw event payload with telemetry data and optional metadata.

    Returns:
        RoutingDecision indicating which engine should handle this event.
    """
    # Check for explicit routing hints in metadata
    metadata = event.get("metadata", {})
    explicit_cluster = metadata.get("cluster")
    explicit_engine = metadata.get("engine")

    if explicit_engine:
        return RoutingDecision(
            engine=explicit_engine,
            cluster=explicit_cluster or "unknown",
            confidence=1.0,
            reason=f"Explicit routing hint: engine={explicit_engine}",
        )

    if explicit_cluster:
        if explicit_cluster in AgentConfig.DETERMINISTIC_CLUSTERS:
            return RoutingDecision(
                engine="lean",
                cluster=explicit_cluster,
                confidence=0.95,
                reason=f"Cluster '{explicit_cluster}' is deterministic",
            )
        if explicit_cluster in AgentConfig.QUALITATIVE_CLUSTERS:
            return RoutingDecision(
                engine="bedrock",
                cluster=explicit_cluster,
                confidence=0.95,
                reason=f"Cluster '{explicit_cluster}' is qualitative",
            )

    # Content-based classification
    keys = set(event.keys()) - {"metadata", "timestamp", "source"}

    deterministic_matches = keys & DETERMINISTIC_SIGNALS
    qualitative_matches = keys & QUALITATIVE_SIGNALS

    if deterministic_matches and not qualitative_matches:
        # Infer cluster from content
        cluster = _infer_deterministic_cluster(event)
        return RoutingDecision(
            engine="lean",
            cluster=cluster,
            confidence=0.85,
            reason=f"Content signals [{', '.join(deterministic_matches)}] indicate deterministic verification",
        )

    if qualitative_matches and not deterministic_matches:
        cluster = _infer_qualitative_cluster(qualitative_matches)
        return RoutingDecision(
            engine="bedrock",
            cluster=cluster,
            confidence=0.85,
            reason=f"Content signals [{', '.join(qualitative_matches)}] indicate qualitative verification",
        )

    if deterministic_matches and qualitative_matches:
        # Mixed content — route based on majority
        if len(deterministic_matches) >= len(qualitative_matches):
            return RoutingDecision(
                engine="lean",
                cluster=_infer_deterministic_cluster(event),
                confidence=0.6,
                reason="Mixed signals, majority deterministic",
            )
        else:
            return RoutingDecision(
                engine="bedrock",
                cluster=_infer_qualitative_cluster(qualitative_matches),
                confidence=0.6,
                reason="Mixed signals, majority qualitative",
            )

    # Default: unknown content
    return RoutingDecision(
        engine="lean",
        cluster="unknown",
        confidence=0.3,
        reason="No recognized signals — defaulting to deterministic pipeline",
    )


def route_and_evaluate(event: dict, config: Optional[AgentConfig] = None) -> dict:
    """
    Route an event and evaluate it through the appropriate engine.

    For qualitative clusters, instantiates the correct Bedrock agent
    and runs the evaluation. For deterministic clusters, returns a
    routing decision for the Lean pipeline to handle.

    Returns a dict with routing decision and evaluation result (if qualitative).
    """
    if config is None:
        config = AgentConfig()

    decision = classify_event(event)

    result = {
        "routing": {
            "engine": decision.engine,
            "cluster": decision.cluster,
            "confidence": decision.confidence,
            "reason": decision.reason,
        }
    }

    if decision.engine == "bedrock" and decision.cluster in CLUSTER_AGENT_MAP:
        agent_class = CLUSTER_AGENT_MAP[decision.cluster]
        agent = agent_class(config)
        agent_result = agent.evaluate(event)
        result["evaluation"] = agent_result.to_dict()
    elif decision.engine == "lean":
        result["evaluation"] = {
            "status": "DEFERRED_TO_LEAN",
            "message": f"Route to Lean 4 kernel for deterministic verification of {decision.cluster} cluster",
        }

    return result


def _infer_deterministic_cluster(event: dict) -> str:
    """Infer which deterministic cluster based on event content."""
    if "sessions" in event or "active_sessions" in event:
        return "identity"
    if "databases" in event or "deployed_stores" in event or "kms_keys" in event:
        return "crypto"
    if "compute" in event or "nodes" in event or "instances" in event:
        return "architecture"
    if "log_streams" in event or "streams" in event:
        return "monitoring"
    return "unknown"


def _infer_qualitative_cluster(signals: set) -> str:
    """Infer which qualitative cluster from content signal keys."""
    personnel_signals = {"background_checks", "nda_records", "personnel"}
    training_signals = {"training_records", "certifications", "lms_completions"}
    incident_signals = {"incidents", "post_mortems", "pagerduty", "alerts"}
    recovery_signals = {"dr_exercises", "backup_validations", "recovery_tests"}
    supply_signals = {"sbom", "dependencies", "vulnerabilities", "cve_analysis"}

    overlaps = [
        ("personnel", len(signals & personnel_signals)),
        ("training", len(signals & training_signals)),
        ("incident_response", len(signals & incident_signals)),
        ("recovery", len(signals & recovery_signals)),
        ("supply_chain", len(signals & supply_signals)),
    ]

    best = max(overlaps, key=lambda x: x[1])
    return best[0] if best[1] > 0 else "unknown"
