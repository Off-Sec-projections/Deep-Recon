"""Generate clear bug bounty reports from validated findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


class ProfessionalReportGenerator:
    """Create structured reports that are ready for platform submission."""

    BASE_PAYOUT = 250.0
    # CVSS ranges from 0-10; dividing by 5 keeps payout multipliers bounded.
    CVSS_NORMALIZER = 5.0
    MIN_CVSS_MULTIPLIER = 1.0

    async def generate_winning_report(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        payout = await self.calculate_payout_estimate(finding)
        return {
            "title": finding.get("title", "Security issue in authorized scope"),
            "summary": finding.get("summary", "Validated vulnerability candidate."),
            "steps_to_reproduce": finding.get("steps_to_reproduce", []),
            "business_impact": finding.get("business_impact", "Security impact requires triage."),
            "severity": finding.get("severity", "medium"),
            "evidence": finding.get("evidence", []),
            "payout_estimate": payout["estimated_payout"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def calculate_payout_estimate(self, finding: Dict[str, Any]) -> Dict[str, float]:
        severity_weights = {"low": 1.0, "medium": 2.0, "high": 5.0, "critical": 10.0}
        severity = str(finding.get("severity", "medium")).lower()
        cvss_score = float(finding.get("cvss_score", 0))
        company_multiplier = float(finding.get("company_multiplier", 1.0))

        payout = (
            self.BASE_PAYOUT
            * severity_weights.get(severity, 2.0)
            * max(cvss_score / self.CVSS_NORMALIZER, self.MIN_CVSS_MULTIPLIER)
            * company_multiplier
        )
        return {"estimated_payout": round(payout, 2)}
