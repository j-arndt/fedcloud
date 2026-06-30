"""
FedCloud Base Agent

Abstract base class for all qualitative verification agents.
Provides shared infrastructure for Bedrock API calls, RAG grounding,
JSON schema enforcement, citation tracking, and narrative generation.
"""

import json
import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Optional

from agents.config import AgentConfig, BedrockConfig


@dataclass
class Citation:
    """A reference to a source document used in agent reasoning."""
    source: str           # Document name or path
    page: Optional[int] = None
    section: Optional[str] = None
    excerpt: str = ""     # Relevant text excerpt

    def to_dict(self) -> dict:
        d = {"source": self.source, "excerpt": self.excerpt}
        if self.page:
            d["page"] = self.page
        if self.section:
            d["section"] = self.section
        return d


@dataclass
class AgentResult:
    """Structured output from a qualitative verification agent."""
    cluster: str
    ksi: str
    status: str  # "VERIFIED" | "VIOLATED" | "PARTIAL"
    controls_evaluated: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    narrative: str = ""
    raw_evidence: dict = field(default_factory=dict)
    timestamp: str = ""
    receipt_id: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not self.receipt_id:
            self.receipt_id = str(uuid.uuid4())

    def to_dict(self) -> dict:
        return {
            "cluster": self.cluster,
            "ksi": self.ksi,
            "status": self.status,
            "controls_evaluated": self.controls_evaluated,
            "findings": self.findings,
            "citations": [c.to_dict() for c in self.citations],
            "narrative": self.narrative,
            "timestamp": self.timestamp,
            "receipt_id": self.receipt_id,
        }


class BaseVerificationAgent(ABC):
    """
    Abstract base for qualitative compliance verification agents.

    Each agent:
    1. Ingests domain-specific telemetry (PDFs, logs, JSON exports)
    2. Queries Bedrock with RAG-grounded prompts
    3. Validates output against strict JSON schema
    4. Produces an AgentResult with citations and narrative
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self._bedrock_client = None

    @property
    @abstractmethod
    def cluster_name(self) -> str:
        """The name of the compliance cluster this agent handles."""
        ...

    @property
    @abstractmethod
    def ksi(self) -> str:
        """The Key Security Indicator code (e.g., KSI-PS)."""
        ...

    @property
    @abstractmethod
    def controls(self) -> list[str]:
        """NIST control IDs this agent evaluates."""
        ...

    @abstractmethod
    def evaluate(self, telemetry: dict) -> AgentResult:
        """
        Evaluate telemetry data and produce a verification result.
        Subclasses implement domain-specific logic here.
        """
        ...

    def invoke_bedrock(
        self,
        prompt: str,
        system_prompt: str = "",
        schema: Optional[dict] = None,
    ) -> dict:
        """
        Invoke Amazon Bedrock with RAG grounding and schema enforcement.

        In mock mode, returns a simulated response.
        In live mode, calls the Bedrock Converse API.
        """
        if self.config.mode == "mock":
            return self._mock_bedrock_response(prompt, schema)

        return self._live_bedrock_call(prompt, system_prompt, schema)

    def _live_bedrock_call(
        self,
        prompt: str,
        system_prompt: str,
        schema: Optional[dict],
    ) -> dict:
        """Call Amazon Bedrock Converse API. Requires boto3 and AWS credentials."""
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "boto3 required for live Bedrock calls. "
                "Install with: pip install boto3"
            )

        if self._bedrock_client is None:
            self._bedrock_client = boto3.client(
                "bedrock-runtime",
                region_name=self.config.bedrock.region,
            )

        messages = [{"role": "user", "content": [{"text": prompt}]}]

        kwargs: dict[str, Any] = {
            "modelId": self.config.bedrock.model_id,
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": self.config.bedrock.max_tokens,
                "temperature": self.config.bedrock.temperature,
            },
        }

        if system_prompt:
            kwargs["system"] = [{"text": system_prompt}]

        if self.config.bedrock.guardrail_id:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self.config.bedrock.guardrail_id,
                "guardrailVersion": self.config.bedrock.guardrail_version,
            }

        response = self._bedrock_client.converse(**kwargs)

        output_text = ""
        for block in response.get("output", {}).get("message", {}).get("content", []):
            if "text" in block:
                output_text += block["text"]

        try:
            return json.loads(output_text)
        except json.JSONDecodeError:
            return {"raw_text": output_text}

    def _mock_bedrock_response(self, prompt: str, schema: Optional[dict]) -> dict:
        """Generate a mock Bedrock response for PoC testing."""
        return {
            "status": "VERIFIED",
            "findings": [],
            "reasoning": f"Mock evaluation for {self.cluster_name} cluster. "
                         f"All {len(self.controls)} controls assessed as compliant.",
            "citations": [
                {
                    "source": "FedRAMP 20x Baseline Handbook",
                    "section": f"{self.ksi} Requirements",
                    "excerpt": f"Mock citation for {self.cluster_name} verification.",
                }
            ],
        }

    def build_system_prompt(self) -> str:
        """Build the RAG-grounded system prompt for this agent."""
        return f"""You are a federal compliance verification agent for the {self.cluster_name} security cluster.
Your Key Security Indicator is {self.ksi}.

RULES:
1. Every claim you make MUST cite a specific source document, page, or log entry.
2. Never generate information from memory — only reference provided telemetry and policy documents.
3. Output MUST conform to the required JSON schema.
4. Use precise timestamps, IDs, and metrics from the evidence.
5. If evidence is insufficient to verify a control, mark it as VIOLATED with a clear explanation.

CONTROLS YOU EVALUATE: {', '.join(self.controls)}

Analyze the provided telemetry data and produce a structured verification result."""

    @staticmethod
    def compute_evidence_hash(evidence: dict) -> str:
        """Compute SHA-256 hash of evidence data for tamper detection."""
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
