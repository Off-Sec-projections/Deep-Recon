import unittest

from autonomous_money_maker import AutonomousMoneyMaker
from bug_bounty_intelligence import BugBountyIntelligence
from earnings_tracker import EarningsTracker
from professional_report_generator import ProfessionalReportGenerator
from professional_vulnerability_finder import ProfessionalVulnerabilityFinder
from submission_manager import SubmissionManager


class AutonomousMoneyMakerTests(unittest.IsolatedAsyncioTestCase):
    EXPECTED_SUBMISSIONS = 3

    async def test_hunt_and_earn_submits_findings(self):
        programs = [
            {
                "name": "Program A",
                "platform": "hackerone",
                "average_payout": 2000,
                "active_hunters": 50,
                "response_days": 4,
                "maturity_score": 2,
                "behavior_checks": [{"category": "authorization"}],
                "concurrency_findings": [{"duplicate_processing": True}],
                "api_findings": [{"kind": "idor"}],
            }
        ]
        maker = AutonomousMoneyMaker(
            intelligence=BugBountyIntelligence(programs),
            finder=ProfessionalVulnerabilityFinder(),
            reporter=ProfessionalReportGenerator(),
            submitter=SubmissionManager(),
            earnings=EarningsTracker(),
        )

        submissions = await maker.hunt_and_earn(run_once=True)

        self.assertEqual(len(submissions), self.EXPECTED_SUBMISSIONS)
        payment_state = await maker.submitter.track_payment_status()
        self.assertEqual(len(payment_state), self.EXPECTED_SUBMISSIONS)


if __name__ == "__main__":
    unittest.main()
