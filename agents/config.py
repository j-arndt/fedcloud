"""
FedCloud Agent Configuration

Centralized configuration for Amazon Bedrock model endpoints,
Knowledge Base references, guardrail settings, and cluster routing.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BedrockConfig:
    """Configuration for Amazon Bedrock API access."""
    region: str = "us-gov-west-1"
    model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    max_tokens: int = 4096
    temperature: float = 0.0  # Deterministic for compliance
    knowledge_base_id: Optional[str] = None
    guardrail_id: Optional[str] = None
    guardrail_version: str = "DRAFT"


@dataclass
class AgentConfig:
    """Configuration for the hybrid verification gateway."""
    mode: str = "mock"  # "mock" or "live"
    bedrock: BedrockConfig = field(default_factory=BedrockConfig)

    # Control family routing: deterministic clusters go to Lean 4,
    # qualitative clusters go to Bedrock agents
    DETERMINISTIC_CLUSTERS = {
        "identity": ["AC-2", "AC-3", "AC-6", "AC-7", "IA-2", "IA-5", "IA-8"],
        "crypto": ["SC-8", "SC-12", "SC-13", "SC-28"],
        "architecture": ["CM-2", "CM-3", "CM-6", "CM-7", "SC-7", "SI-7"],
        "monitoring": ["AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-11", "AU-12", "SI-4"],
    }

    QUALITATIVE_CLUSTERS = {
        "personnel": {
            "controls": ["PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8"],
            "ksi": "KSI-PS",
            "description": "Personnel Security — background checks, NDAs, access provisioning",
        },
        "training": {
            "controls": ["AT-1", "AT-2", "AT-3", "AT-4"],
            "ksi": "KSI-CED",
            "description": "Cybersecurity Education — training completion, recertification",
        },
        "incident_response": {
            "controls": ["IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8"],
            "ksi": "KSI-INR",
            "description": "Incident Response — timeline reconstruction, reporting compliance",
        },
        "recovery": {
            "controls": ["CP-1", "CP-2", "CP-4", "CP-6", "CP-7", "CP-9", "CP-10"],
            "ksi": "KSI-RPL",
            "description": "Recovery Planning — DR drill validation, RTO/RPO verification",
        },
        "supply_chain": {
            "controls": ["SA-4", "SA-5", "SA-9", "SA-11", "SR-1", "SR-2", "SR-3"],
            "ksi": "KSI-TPR",
            "description": "Third-Party Resources — SBOM analysis, CVE contextualization",
        },
    }

    @classmethod
    def get_cluster_for_control(cls, control_id: str) -> tuple[str, str]:
        """
        Determine which cluster and engine handles a given control.
        Returns (cluster_name, engine_type) where engine_type is 'lean' or 'bedrock'.
        """
        prefix = control_id.split("-")[0] if "-" in control_id else control_id

        for cluster, controls in cls.DETERMINISTIC_CLUSTERS.items():
            if control_id in controls:
                return cluster, "lean"

        for cluster, meta in cls.QUALITATIVE_CLUSTERS.items():
            if control_id in meta["controls"]:
                return cluster, "bedrock"

        return "unknown", "unrouted"
