"""
Incident Response Agent (KSI-INR)

Reconstructs incident timelines from alerting and ticketing systems,
evaluates response metrics against policy thresholds, and determines
compliance with federal reporting requirements.

Telemetry Sources:
  - PagerDuty/OpsGenie alert exports
  - Jira/ServiceNow incident tickets
  - Slack/Teams compliance channel exports
  - Post-mortem documents

Controls: IR-1 through IR-8
"""

from agents.base_agent import BaseVerificationAgent, AgentResult, Citation
from agents.config import AgentConfig


class IncidentResponseAgent(BaseVerificationAgent):

    # Federal reporting thresholds (hours)
    TRIAGE_THRESHOLD_HOURS = 1.0
    FEDERAL_REPORT_THRESHOLD_HOURS = 24.0

    @property
    def cluster_name(self) -> str:
        return "incident_response"

    @property
    def ksi(self) -> str:
        return "KSI-INR"

    @property
    def controls(self) -> list[str]:
        return ["IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8"]

    def evaluate(self, telemetry: dict) -> AgentResult:
        incidents = telemetry.get("incidents", [])
        post_mortems = telemetry.get("post_mortems", [])

        if self.config.mode == "mock":
            return self._mock_evaluate(incidents, post_mortems)

        prompt = self._build_prompt(incidents, post_mortems)
        response = self.invoke_bedrock(prompt, self.build_system_prompt())
        return self._parse_response(response)

    def _mock_evaluate(self, incidents: list, post_mortems: list) -> AgentResult:
        findings = []
        citations = []
        all_compliant = True

        pm_lookup = {pm.get("incident_id"): pm for pm in post_mortems}

        for inc in incidents:
            inc_id = inc.get("incident_id", "unknown")
            severity = inc.get("severity", "unknown")
            alert_time = inc.get("alert_time", "")
            triage_time = inc.get("triage_time", "")
            time_to_triage_hours = inc.get("time_to_triage_hours", 0)
            reported_to_federal = inc.get("reported_to_federal", False)
            requires_federal_report = inc.get("requires_federal_report", False)

            # Check triage response time
            if time_to_triage_hours > self.TRIAGE_THRESHOLD_HOURS:
                findings.append({
                    "control": "IR-4",
                    "severity": "high",
                    "finding": f"Incident {inc_id}: triage took {time_to_triage_hours:.1f}h "
                               f"(threshold: {self.TRIAGE_THRESHOLD_HOURS}h)",
                })
                all_compliant = False
            else:
                citations.append(Citation(
                    source=f"Incident Log — {inc_id}",
                    excerpt=f"Alert at {alert_time}, triaged at {triage_time}. "
                            f"Response time: {time_to_triage_hours:.1f}h within {self.TRIAGE_THRESHOLD_HOURS}h threshold.",
                ))

            # Check federal reporting
            if requires_federal_report and not reported_to_federal:
                findings.append({
                    "control": "IR-6",
                    "severity": "critical",
                    "finding": f"Incident {inc_id} (severity: {severity}) meets federal reporting "
                               f"threshold but was NOT reported",
                })
                all_compliant = False

            # Check post-mortem exists
            pm = pm_lookup.get(inc_id)
            if not pm and severity in ("critical", "high", "P1", "P2"):
                findings.append({
                    "control": "IR-5",
                    "severity": "medium",
                    "finding": f"No post-mortem document found for {severity} incident {inc_id}",
                })
                all_compliant = False
            elif pm:
                citations.append(Citation(
                    source=f"Post-Mortem — {inc_id}",
                    excerpt=pm.get("summary", "Post-mortem completed."),
                ))

        status = "VERIFIED" if all_compliant else "VIOLATED"

        narrative = (
            f"## Incident Response Assessment ({self.ksi})\n\n"
            f"**Status: {status}**\n\n"
            f"Analyzed {len(incidents)} incidents and {len(post_mortems)} post-mortems.\n\n"
        )
        if findings:
            narrative += "### Findings\n" + "\n".join(
                f"- **[{f['control']}] {f['severity'].upper()}**: {f['finding']}" for f in findings
            )
        else:
            narrative += "All incident response procedures met federal thresholds. Response times verified."

        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi, status=status,
            controls_evaluated=self.controls, findings=findings,
            citations=citations, narrative=narrative,
            raw_evidence={"incidents_analyzed": len(incidents), "post_mortems": len(post_mortems)},
        )

    def _build_prompt(self, incidents: list, post_mortems: list) -> str:
        import json
        return f"""Evaluate incident response compliance:

INCIDENTS: {json.dumps(incidents, indent=2)}
POST-MORTEMS: {json.dumps(post_mortems, indent=2)}

Verify: 1) Triage within {self.TRIAGE_THRESHOLD_HOURS}h, 2) Federal reporting met,
3) Post-mortems exist for high-severity incidents.
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
