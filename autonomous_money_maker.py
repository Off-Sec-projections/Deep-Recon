"""Authorized bug bounty orchestration workflow."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from bug_bounty_intelligence import BugBountyIntelligence
from earnings_tracker import EarningsTracker
from professional_report_generator import ProfessionalReportGenerator
from professional_vulnerability_finder import ProfessionalVulnerabilityFinder
from submission_manager import SubmissionManager


class AutonomousMoneyMaker:
    """Coordinate target selection, finding triage, reporting, and tracking."""

    def __init__(
        self,
        intelligence: BugBountyIntelligence,
        finder: ProfessionalVulnerabilityFinder,
        reporter: ProfessionalReportGenerator,
        submitter: SubmissionManager,
        earnings: EarningsTracker,
    ):
        self.intelligence = intelligence
        self.finder = finder
        self.reporter = reporter
        self.submitter = submitter
        self.earnings = earnings

    async def hunt_and_earn(self, run_once: bool = True, sleep_seconds: int = 86400) -> List[Dict[str, Any]]:
        """Run one or more authorized bug bounty workflow cycles."""
        cycle_submissions: List[Dict[str, Any]] = []

        while True:
            best_programs = await self.intelligence.find_profitable_programs()

            for program in best_programs[:5]:
                findings = await self.finder.find_vulnerabilities(program)
                for finding in findings:
                    report = await self.reporter.generate_winning_report(finding)
                    submission = await self.submitter.auto_submit(report, program)
                    payout_estimate = float(report.get("payout_estimate", 0.0))
                    await self.earnings.track_submission(submission, payout_estimate)
                    cycle_submissions.append(submission)

            if run_once:
                break
            await asyncio.sleep(sleep_seconds)

        return cycle_submissions


async def _example_main() -> None:
    programs = [
        {
            "name": "Example Program",
            "platform": "hackerone",
            "average_payout": 2500,
            "active_hunters": 120,
            "response_days": 5,
            "maturity_score": 2.5,
            "behavior_checks": [{"category": "authorization", "path": "/api/orders/1"}],
            "concurrency_findings": [{"duplicate_processing": True, "endpoint": "/checkout"}],
            "api_findings": [{"kind": "idor", "path": "/api/users/2"}],
        }
    ]
    maker = AutonomousMoneyMaker(
        intelligence=BugBountyIntelligence(programs),
        finder=ProfessionalVulnerabilityFinder(),
        reporter=ProfessionalReportGenerator(),
        submitter=SubmissionManager(),
        earnings=EarningsTracker(),
    )
    await maker.hunt_and_earn(run_once=True)


if __name__ == "__main__":
    asyncio.run(_example_main())
