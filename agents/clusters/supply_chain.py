"""
Supply Chain Agent (KSI-TPR)

Analyzes Software Bill of Materials (SBOM), evaluates CVE context
within the deployment architecture, and generates risk-acceptance
or mitigation narratives for third-party components.

Telemetry Sources:
  - CycloneDX/SPDX SBOM files (JSON)
  - Container dependency scan outputs
  - CVE database cross-references

Controls: SA-4, SA-5, SA-9, SA-11, SR-1, SR-2, SR-3
"""

from agents.base_agent import BaseVerificationAgent, AgentResult, Citation
from agents.config import AgentConfig


class SupplyChainAgent(BaseVerificationAgent):

    CRITICAL_CVSS_THRESHOLD = 9.0
    HIGH_CVSS_THRESHOLD = 7.0

    @property
    def cluster_name(self) -> str:
        return "supply_chain"

    @property
    def ksi(self) -> str:
        return "KSI-TPR"

    @property
    def controls(self) -> list[str]:
        return ["SA-4", "SA-5", "SA-9", "SA-11", "SR-1", "SR-2", "SR-3"]

    def evaluate(self, telemetry: dict) -> AgentResult:
        sbom = telemetry.get("sbom", {})
        vulnerabilities = telemetry.get("vulnerabilities", [])

        if self.config.mode == "mock":
            return self._mock_evaluate(sbom, vulnerabilities)

        prompt = self._build_prompt(sbom, vulnerabilities)
        response = self.invoke_bedrock(prompt, self.build_system_prompt())
        return self._parse_response(response)

    def _mock_evaluate(self, sbom: dict, vulnerabilities: list) -> AgentResult:
        findings = []
        citations = []
        all_compliant = True

        components = sbom.get("components", [])
        if not components and not vulnerabilities:
            return AgentResult(
                cluster=self.cluster_name, ksi=self.ksi, status="VERIFIED",
                controls_evaluated=self.controls,
                narrative=f"## Supply Chain Assessment ({self.ksi})\n\n**Status: VERIFIED**\n\nNo SBOM data to evaluate.",
            )

        # Track SBOM completeness
        if components:
            components_with_version = [c for c in components if c.get("version")]
            completeness = len(components_with_version) / len(components) if components else 0

            if completeness < 0.95:
                findings.append({
                    "control": "SR-1",
                    "severity": "medium",
                    "finding": f"SBOM completeness {completeness:.0%}: "
                               f"{len(components) - len(components_with_version)} components missing versions",
                })

            citations.append(Citation(
                source="SBOM Analysis",
                excerpt=f"Analyzed {len(components)} components. "
                        f"Version completeness: {completeness:.0%}. "
                        f"Format: {sbom.get('bomFormat', 'unknown')}.",
            ))

        # Evaluate vulnerabilities
        critical_unmitigated = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "unknown")
            cvss = vuln.get("cvss_score", 0)
            package = vuln.get("package", "unknown")
            mitigated = vuln.get("mitigated", False)
            reachable = vuln.get("reachable_in_architecture", True)
            justification = vuln.get("risk_justification", "")

            if cvss >= self.CRITICAL_CVSS_THRESHOLD and not mitigated:
                if reachable:
                    findings.append({
                        "control": "SA-11",
                        "severity": "critical",
                        "finding": f"{cve_id} (CVSS {cvss}) in {package}: critical, reachable, unmitigated",
                    })
                    all_compliant = False
                    critical_unmitigated.append(cve_id)
                else:
                    citations.append(Citation(
                        source=f"CVE Assessment — {cve_id}",
                        excerpt=f"CVSS {cvss} in {package}. NOT reachable within isolated architecture. "
                                f"Risk accepted: {justification or 'architecture isolation'}.",
                    ))
            elif cvss >= self.HIGH_CVSS_THRESHOLD and not mitigated and reachable:
                findings.append({
                    "control": "SA-11",
                    "severity": "high",
                    "finding": f"{cve_id} (CVSS {cvss}) in {package}: high severity, reachable, unmitigated",
                })
                all_compliant = False
            elif mitigated:
                citations.append(Citation(
                    source=f"Vulnerability Tracker — {cve_id}",
                    excerpt=f"CVSS {cvss} in {package}. Mitigated. Justification: {justification}.",
                ))

        status = "VERIFIED" if all_compliant else "VIOLATED"

        narrative = (
            f"## Supply Chain Assessment ({self.ksi})\n\n"
            f"**Status: {status}**\n\n"
            f"Analyzed {len(components)} SBOM components and {len(vulnerabilities)} known vulnerabilities.\n\n"
        )
        if findings:
            narrative += "### Findings\n" + "\n".join(
                f"- **[{f['control']}] {f['severity'].upper()}**: {f['finding']}" for f in findings
            )
        else:
            narrative += (
                "All third-party components assessed. No unmitigated critical or reachable "
                "high-severity vulnerabilities detected within the deployment architecture."
            )

        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi, status=status,
            controls_evaluated=self.controls, findings=findings,
            citations=citations, narrative=narrative,
            raw_evidence={
                "sbom_components": len(components),
                "vulnerabilities_scanned": len(vulnerabilities),
                "critical_unmitigated": len(critical_unmitigated),
            },
        )

    def _build_prompt(self, sbom: dict, vulnerabilities: list) -> str:
        import json
        return f"""Evaluate supply chain security:

SBOM: {json.dumps(sbom, indent=2)[:3000]}
VULNERABILITIES: {json.dumps(vulnerabilities, indent=2)}

Assess: 1) SBOM completeness, 2) Critical CVE reachability within architecture,
3) Mitigation status for high-severity vulnerabilities.
Output JSON: status, findings, citations, narrative."""

    def _parse_response(self, response: dict) -> AgentResult:
        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi,
            status=response.get("status", "UNKNOWN"),
            controls_evaluated=self.controls,
            findings=response.get("findings", []),
            citations=[Citation(source=c.get("source", ""), excerpt=c.get("excerpt", ""))
                       for c in response.get("citations", [])],
            narrative=response.get("narrative", ""),
        )
