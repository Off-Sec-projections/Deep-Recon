"""Track payouts and forecast bug bounty revenue."""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Any, Dict, List


class EarningsTracker:
    """Track submission outcomes and compute earnings summaries."""

    def __init__(self):
        self.records: List[Dict[str, Any]] = []

    async def track_submission(self, submission: Dict[str, Any], payout: float = 0.0) -> None:
        self.records.append(
            {
                "submission_id": submission["submission_id"],
                "date": date.today().isoformat(),
                "status": submission.get("status", "submitted"),
                "payout": float(payout),
            }
        )

    async def track_daily_earnings(self) -> Dict[str, float]:
        today = date.today().isoformat()
        today_records = [r for r in self.records if r["date"] == today]
        received = sum(r["payout"] for r in today_records if r["status"] == "paid")
        pending = sum(r["payout"] for r in today_records if r["status"] != "paid")
        return {"received_today": round(received, 2), "pending_today": round(pending, 2)}

    async def monthly_summary(self) -> Dict[str, Any]:
        current_month = date.today().strftime("%Y-%m")
        month_records = [r for r in self.records if r["date"].startswith(current_month)]
        total = sum(r["payout"] for r in month_records)
        by_status: Dict[str, float] = defaultdict(float)
        for record in month_records:
            by_status[record["status"]] += record["payout"]
        return {"month": current_month, "total": round(total, 2), "by_status": dict(by_status)}

    async def predict_monthly_revenue(self) -> Dict[str, float]:
        summary = await self.monthly_summary()
        current_month_total = summary["total"]
        return {
            "projected_month_total": round(current_month_total, 2),
            "annualized_projection": round(current_month_total * 12, 2),
        }
