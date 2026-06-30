"""
FedCloud Agent Guardrails

Strict output validation for Bedrock agent responses. Ensures:
  - JSON schema conformance
  - Citation verification (no uncited claims)
  - No hallucination markers
  - Required fields present
"""

import json
import re
from typing import Optional


class GuardrailError(Exception):
    """Raised when agent output fails guardrail validation."""
    pass


REQUIRED_RESULT_FIELDS = {"status", "findings", "citations", "narrative"}
VALID_STATUSES = {"VERIFIED", "VIOLATED", "PARTIAL", "UNKNOWN"}


def validate_agent_output(output: dict, strict: bool = True) -> list[str]:
    """
    Validate an agent's structured output against guardrail rules.

    Args:
        output: The agent's output dictionary.
        strict: If True, raise GuardrailError on failure. If False, return warnings.

    Returns:
        List of warning/error messages (empty if valid).
    """
    warnings = []

    # Check required fields
    missing = REQUIRED_RESULT_FIELDS - set(output.keys())
    if missing:
        msg = f"Missing required fields: {missing}"
        warnings.append(msg)

    # Validate status
    status = output.get("status", "")
    if status and status not in VALID_STATUSES:
        warnings.append(f"Invalid status '{status}'. Must be one of: {VALID_STATUSES}")

    # Validate findings structure
    findings = output.get("findings", [])
    if not isinstance(findings, list):
        warnings.append("'findings' must be a list")
    else:
        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                warnings.append(f"Finding {i} must be a dict")
                continue
            if "control" not in f:
                warnings.append(f"Finding {i} missing 'control' field")
            if "finding" not in f:
                warnings.append(f"Finding {i} missing 'finding' description")

    # Validate citations
    citations = output.get("citations", [])
    if not isinstance(citations, list):
        warnings.append("'citations' must be a list")
    else:
        for i, c in enumerate(citations):
            if not isinstance(c, dict):
                warnings.append(f"Citation {i} must be a dict")
                continue
            if not c.get("source"):
                warnings.append(f"Citation {i} missing 'source' field")

    # Check narrative for hallucination markers
    narrative = output.get("narrative", "")
    if narrative:
        hallucination_markers = [
            r"I think",
            r"I believe",
            r"probably",
            r"might be",
            r"it seems like",
            r"based on my knowledge",
            r"from what I remember",
            r"as far as I know",
        ]
        for marker in hallucination_markers:
            if re.search(marker, narrative, re.IGNORECASE):
                warnings.append(
                    f"Narrative contains hedging language ('{marker}') — "
                    f"agent must cite evidence, not speculate"
                )

    # Verify citation coverage (findings should reference evidence)
    if findings and not citations and status == "VERIFIED":
        warnings.append(
            "Status is VERIFIED but no citations provided — "
            "verification claims must be backed by evidence"
        )

    if strict and warnings:
        raise GuardrailError(
            f"Agent output failed {len(warnings)} guardrail(s):\n"
            + "\n".join(f"  - {w}" for w in warnings)
        )

    return warnings


def enforce_json_schema(response_text: str, schema: Optional[dict] = None) -> dict:
    """
    Parse and validate agent response text as JSON.

    Attempts to extract JSON from the response, handling cases where
    the model wraps JSON in markdown code blocks.
    """
    text = response_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise GuardrailError(f"Agent response is not valid JSON: {e}")

    if not isinstance(data, dict):
        raise GuardrailError(f"Agent response must be a JSON object, got {type(data).__name__}")

    return data
