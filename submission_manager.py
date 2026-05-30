"""Submission and lifecycle tracking for bug bounty reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4


class SubmissionManager:
    """Manage report submissions to platforms and track status."""

    def __init__(self):
        self.submissions: List[Dict[str, Any]] = []

    async def submit_to_hackerone(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return await self._record_submission("hackerone", report)

    async def submit_to_bugcrowd(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return await self._record_submission("bugcrowd", report)

    async def auto_submit(self, report: Dict[str, Any], program: Dict[str, Any]) -> Dict[str, Any]:
        platform = str(program.get("platform", "hackerone")).lower()
        if platform == "bugcrowd":
            return await self.submit_to_bugcrowd(report)
        return await self.submit_to_hackerone(report)

    async def track_payment_status(self) -> List[Dict[str, Any]]:
        return [
            {
                "submission_id": item["submission_id"],
                "platform": item["platform"],
                "status": item["status"],
                "payment_status": item.get("payment_status", "pending"),
            }
            for item in self.submissions
        ]

    async def handle_interactions(self) -> List[Dict[str, Any]]:
        return [
            {
                "submission_id": item["submission_id"],
                "action": "awaiting-triage-response" if item["status"] == "submitted" else "none",
            }
            for item in self.submissions
        ]

    async def _record_submission(self, platform: str, report: Dict[str, Any]) -> Dict[str, Any]:
        submission = {
            "submission_id": f"{platform}-{uuid4().hex}",
            "platform": platform,
            "status": "submitted",
            "payment_status": "pending",
            "report_title": report.get("title", "Untitled report"),
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }
        self.submissions.append(submission)
        return submission
