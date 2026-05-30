"""Program intelligence for authorized bug bounty workflows."""

from __future__ import annotations

from typing import Any, Dict, List


class BugBountyIntelligence:
    """Analyze authorized bug bounty program data and rank opportunities."""

    def __init__(self, programs: List[Dict[str, Any]] | None = None):
        self.programs = programs or []

    async def find_profitable_programs(self) -> List[Dict[str, Any]]:
        """Rank programs by payout potential and low competition."""
        scored: List[Dict[str, Any]] = []

        for program in self.programs:
            average_payout = float(program.get("average_payout", 0))
            active_hunters = max(float(program.get("active_hunters", 0)), 1.0)
            response_days = max(float(program.get("response_days", 14)), 1.0)
            maturity = float(program.get("maturity_score", 1))

            score = ((average_payout * maturity) / active_hunters) * (7 / response_days)
            scored.append({**program, "profitability_score": round(score, 2)})

        return sorted(scored, key=lambda p: p["profitability_score"], reverse=True)

    async def predict_vulnerability_types(self, program: Dict[str, Any]) -> List[str]:
        """Return likely vulnerability classes from known stack and history."""
        stack = {value.lower() for value in program.get("tech_stack", [])}
        history = " ".join(program.get("historical_findings", [])).lower()
        predictions: List[str] = []

        if {"node", "javascript", "typescript"} & stack:
            predictions.append("access-control-logic")
        if {"go", "java", "dotnet", "python"} & stack:
            predictions.append("authorization-flows")
        if "api" in history or "rest" in stack:
            predictions.append("idor-and-api-authorization")
        if "payment" in history or "ecommerce" in stack:
            predictions.append("race-conditions")

        if not predictions:
            predictions.append("business-logic-validation")

        return predictions

    async def estimate_monthly_potential(self, program: Dict[str, Any]) -> Dict[str, float]:
        """Estimate monthly revenue from expected findings and payout data."""
        expected_findings = float(program.get("expected_findings_per_month", 0))
        average_payout = float(program.get("average_payout", 0))
        success_rate = float(program.get("success_rate", 0))
        monthly = expected_findings * average_payout * success_rate
        return {
            "expected_findings_per_month": expected_findings,
            "average_payout": average_payout,
            "success_rate": success_rate,
            "estimated_monthly_revenue": round(monthly, 2),
        }
