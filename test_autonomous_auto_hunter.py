import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from autonomous_auto_hunter import AutoTargetSelector, AutonomousAutoHunter


class AutoTargetSelectorTests(unittest.TestCase):
    def test_program_score_rewards_bounty_and_low_competition(self):
        selector = AutoTargetSelector("user", "token")
        strong = {
            "maximum_bounty": 60000,
            "average_bounty": 10000,
            "active_hackers_count": 20,
            "average_response_time": "12 hours",
        }
        weak = {
            "maximum_bounty": 2000,
            "average_bounty": 1000,
            "active_hackers_count": 300,
            "average_response_time": "7 days",
        }
        self.assertGreater(selector._calculate_program_score(strong), selector._calculate_program_score(weak))

    def test_get_best_targets_filters_closed_programs(self):
        selector = AutoTargetSelector("user", "token")
        fake_programs = [
            {"name": "OpenA", "submission_state": "open", "maximum_bounty": 10000},
            {"name": "ClosedB", "submission_state": "closed", "maximum_bounty": 100000},
        ]
        mock_client = MagicMock()
        mock_client.search_programs = AsyncMock(return_value=fake_programs)

        with patch("autonomous_auto_hunter._hackerone_client_cls", return_value=lambda *_: mock_client):
            targets = asyncio.run(selector.get_best_targets())

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["name"], "OpenA")


class AutonomousAutoHunterTests(unittest.TestCase):
    def test_hunt_once_keeps_draft_status_without_auto_submit(self):
        hunter = AutonomousAutoHunter(auto_submit=False)
        hunter.h1_username = "user"
        hunter.h1_token = "token"
        hunter.target_selector = MagicMock()
        hunter.target_selector.get_best_targets = AsyncMock(
            return_value=[{"name": "Prog", "handle": "prog-handle"}]
        )

        mock_client = MagicMock()
        mock_client.get_program_scope = AsyncMock(
            return_value=[{"asset_identifier": "https://example.com"}]
        )

        mock_finder = MagicMock()
        mock_finder.hunt_vulnerabilities = AsyncMock(
            return_value=[{"type": "SQL Injection", "severity": "HIGH", "bounty_estimate": 1000}]
        )

        with patch("autonomous_auto_hunter._hackerone_client_cls", return_value=lambda *_: mock_client), patch(
            "autonomous_auto_hunter._finder_cls", return_value=lambda *_: mock_finder
        ):
            asyncio.run(hunter.hunt_once(target_limit=1, assets_per_target=1))

        self.assertEqual(len(hunter.submissions), 1)
        self.assertEqual(hunter.submissions[0]["status"], "drafted")


if __name__ == "__main__":
    unittest.main()
