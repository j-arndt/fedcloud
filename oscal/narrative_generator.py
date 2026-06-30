"""
FedCloud OSCAL Narrative Generator

Produces audit-defensive markdown documentation blocks that accompany
each qualitative assessment. Generates professional, citation-rich
narratives suitable for 3PAO review.
"""

from typing import Optional


def generate_cluster_narrative(
    cluster: str,
    ksi: str,
    status: str,
    findings: list[dict],
    citations: list[dict],
    evidence_summary: dict,
    controls: list[str],
) -> str:
    """
    Generate a comprehensive audit-ready narrative for a qualitative cluster.

    The narrative follows federal documentation standards:
    1. Executive summary with status
    2. Scope of assessment
    3. Methodology
    4. Detailed findings (if any)
    5. Evidence citations
    6. Conclusion
    """
    cluster_title = cluster.replace("_", " ").title()

    sections = []

    # Header
    sections.append(f"# {cluster_title} Verification Report")
    sections.append(f"**Key Security Indicator:** {ksi}")
    sections.append(f"**Verification Status:** {status}")
    sections.append(f"**Controls Assessed:** {', '.join(controls)}")
    sections.append("")

    # Executive Summary
    sections.append("## Executive Summary")
    if status == "VERIFIED":
        sections.append(
            f"The {cluster_title} security cluster has been verified through automated "
            f"assessment of {_summarize_evidence(evidence_summary)}. All {len(controls)} "
            f"applicable NIST SP 800-53 controls were evaluated and found to be in compliance "
            f"with FedRAMP 20x baseline requirements."
        )
    elif status == "VIOLATED":
        sections.append(
            f"The {cluster_title} security cluster assessment identified "
            f"{len(findings)} finding(s) requiring remediation. "
            f"{_summarize_evidence(evidence_summary)} were evaluated against "
            f"{len(controls)} applicable controls."
        )
    else:
        sections.append(
            f"The {cluster_title} assessment completed with status: {status}. "
            f"Further review may be required."
        )
    sections.append("")

    # Methodology
    sections.append("## Assessment Methodology")
    sections.append(
        "This assessment was performed by the FedCloud Hybrid Verification Gateway "
        "using Amazon Bedrock with RAG-grounded evaluation against approved corporate "
        "security policies and the FedRAMP 20x baseline handbook. All claims are "
        "backed by cited evidence sources. The assessment agent operates with zero "
        "temperature (deterministic mode) and strict JSON schema enforcement."
    )
    sections.append("")

    # Findings
    if findings:
        sections.append("## Findings")
        sections.append("")
        sections.append("| # | Control | Severity | Finding |")
        sections.append("|---|---------|----------|---------|")
        for i, f in enumerate(findings, 1):
            ctrl = f.get("control", "N/A")
            sev = f.get("severity", "unknown").upper()
            desc = f.get("finding", "No description")
            sections.append(f"| {i} | {ctrl} | {sev} | {desc} |")
        sections.append("")
    else:
        sections.append("## Findings")
        sections.append("No findings. All controls verified.")
        sections.append("")

    # Evidence Citations
    if citations:
        sections.append("## Evidence Citations")
        sections.append("")
        for i, c in enumerate(citations, 1):
            source = c.get("source", "Unknown Source")
            excerpt = c.get("excerpt", "")
            page = c.get("page")
            section = c.get("section")

            ref_parts = [f"**{source}**"]
            if section:
                ref_parts.append(f"Section: {section}")
            if page:
                ref_parts.append(f"Page: {page}")

            sections.append(f"{i}. {', '.join(ref_parts)}")
            if excerpt:
                sections.append(f"   > {excerpt}")
            sections.append("")

    # Conclusion
    sections.append("## Conclusion")
    if status == "VERIFIED":
        sections.append(
            f"Based on the automated analysis of all available evidence, the "
            f"{cluster_title} security cluster meets the requirements specified "
            f"in the FedRAMP 20x continuous authorization baseline. This assessment "
            f"is supported by {len(citations)} cited evidence sources."
        )
    else:
        sections.append(
            f"The {cluster_title} assessment identified {len(findings)} finding(s). "
            f"Remediation actions should be prioritized by severity and tracked "
            f"through the Plan of Action and Milestones (POA&M) process."
        )

    return "\n".join(sections)


def _summarize_evidence(evidence: dict) -> str:
    """Generate a human-readable summary of evidence quantities."""
    parts = []
    for key, value in evidence.items():
        label = key.replace("_", " ")
        parts.append(f"{value} {label}")
    return ", ".join(parts) if parts else "available telemetry"
