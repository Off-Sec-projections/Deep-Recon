"""Autonomous target selection and hunting orchestration for authorized programs."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency in test environments
    DOTENV_AVAILABLE = False

    def load_dotenv() -> bool:
        return False

logger = logging.getLogger(__name__)
load_dotenv()
if not DOTENV_AVAILABLE:
    logger.debug("python-dotenv is unavailable; environment variables must be provided directly.")

DEFAULT_ACTIVE_HACKERS = 100


def _build_hackerone_client(username: str, token: str):
    from hackerone_client import HackerOneClient

    return HackerOneClient(username, token)


def _build_finder(target_url: str):
    from advanced_vulnerability_finder import AdvancedVulnerabilityFinder

    return AdvancedVulnerabilityFinder(target_url)


class AutoTargetSelector:
    """Select high-value targets from available bug bounty programs."""

    def __init__(self, h1_username: str, h1_token: str):
        self.h1_username = h1_username
        self.h1_token = h1_token

    async def get_best_targets(self, limit: int = 10) -> List[Dict[str, Any]]:
        client = _build_hackerone_client(self.h1_username, self.h1_token)
        programs = await client.search_programs()
        if not programs:
            return []

        scored: List[Dict[str, Any]] = []
        for program in programs:
            if program.get("submission_state") not in (None, "open"):
                continue
            scored_program = dict(program)
            scored_program["profit_score"] = self._calculate_program_score(program)
            scored.append(scored_program)

        return sorted(scored, key=lambda item: item["profit_score"], reverse=True)[:limit]

    def _calculate_program_score(self, program: Dict[str, Any]) -> float:
        score = 0.0

        max_bounty = self._as_number(program.get("maximum_bounty"))
        if max_bounty >= 50000:
            score += 10
        elif max_bounty >= 20000:
            score += 7
        elif max_bounty >= 10000:
            score += 4
        elif max_bounty >= 5000:
            score += 2

        avg_bounty = self._as_number(program.get("average_bounty"))
        score += min(avg_bounty / 5000, 5)

        active_hackers = self._as_int(program.get("active_hackers_count"), default=DEFAULT_ACTIVE_HACKERS)
        if active_hackers < 50:
            score += 3
        elif active_hackers < 100:
            score += 1

        response_metric = program.get("average_response_time")
        response_hours = self._response_to_hours(response_metric)
        if response_hours is not None:
            if response_hours <= 24:
                score += 2
            elif response_hours <= 72:
                score += 1

        return round(score, 2)

    @staticmethod
    def _as_number(value: Any, default: float = 0.0) -> float:
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            cleaned = "".join(ch for ch in value if ch.isdigit() or ch == ".")
            try:
                return float(cleaned) if cleaned else default
            except ValueError:
                return default
        return default

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        return int(AutoTargetSelector._as_number(value, default=default))

    @staticmethod
    def _response_to_hours(value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        number = AutoTargetSelector._as_number(normalized, default=-1)
        if number < 0:
            return None
        if "day" in normalized:
            return number * 24
        if "minute" in normalized:
            return number / 60
        return number


class AutonomousAutoHunter:
    """Run recurring target selection and vulnerability hunting."""

    def __init__(self, *, auto_submit: bool = False):
        self.h1_username = os.getenv("H1_USERNAME", "")
        self.h1_token = os.getenv("H1_API_TOKEN", "")
        self.target_selector = AutoTargetSelector(self.h1_username, self.h1_token)
        self.total_vulns_found = 0
        self.total_bounty_earned = 0
        self.submissions: List[Dict[str, Any]] = []
        self.auto_submit = auto_submit

    async def hunt_once(self, *, target_limit: int = 10, assets_per_target: int = 3) -> Dict[str, Any]:
        if not self.h1_username or not self.h1_token:
            raise RuntimeError("H1_USERNAME and H1_API_TOKEN must be set")

        targets = await self.target_selector.get_best_targets(limit=target_limit)
        if not targets:
            return {"targets": [], "submissions": []}

        await self._hunt_all_targets(targets, assets_per_target=assets_per_target)
        stats = self._save_statistics()
        return {"targets": targets, "submissions": list(self.submissions), "stats": stats}

    async def _hunt_all_targets(self, targets: List[Dict[str, Any]], *, assets_per_target: int) -> None:
        client = _build_hackerone_client(self.h1_username, self.h1_token)

        for target in targets:
            handle = target.get("handle")
            if not handle:
                continue

            scope = await client.get_program_scope(handle)
            if not scope:
                continue

            for asset in scope[:assets_per_target]:
                asset_target = asset.get("asset_identifier", "")
                if not isinstance(asset_target, str) or not asset_target.startswith(("http://", "https://")):
                    continue

                finder = _build_finder(asset_target)
                vulns = await finder.hunt_vulnerabilities()
                for vuln in vulns:
                    bounty = int(vuln.get("bounty_estimate", 0))
                    self.total_vulns_found += 1
                    self.total_bounty_earned += bounty
                    record = {
                        "program": target.get("name"),
                        "program_handle": handle,
                        "type": vuln.get("type", "Unknown"),
                        "severity": vuln.get("severity", "MEDIUM"),
                        "bounty": bounty,
                        "timestamp": datetime.now().isoformat(),
                        "status": "draft",
                        "evidence": vuln.get("evidence", vuln.get("description", "")),
                    }
                    if self.auto_submit:
                        report_id = await self._submit_to_hackerone(client, handle, vuln)
                        record["status"] = "submitted" if report_id else "submission_failed"
                        record["report_id"] = report_id
                    self.submissions.append(record)

    async def _submit_to_hackerone(
        self,
        client: Any,
        program_handle: str,
        vuln: Dict[str, Any],
    ) -> Optional[str]:
        report_data = {
            "title": vuln.get("type", "Security issue"),
            "description": vuln.get("evidence", vuln.get("description", "")),
            "weakness_id": self._map_vuln_to_weakness(vuln.get("type", "")),
            "severity_rating": self._map_severity(vuln.get("severity", "MEDIUM")),
            "impact": vuln.get("description", "Potential security impact."),
        }
        return await client.submit_report(program_handle, report_data)

    @staticmethod
    def _map_vuln_to_weakness(vuln_type: str) -> str:
        mapping = {
            "SQL Injection": "sql_injection",
            "Authentication Bypass": "authentication_bypass",
            "Insecure Direct Object Reference (IDOR)": "insecure_direct_object_reference",
            "Server-Side Request Forgery (SSRF)": "server_side_request_forgery",
            "XML External Entity (XXE)": "xml_external_entity",
            "Path Traversal": "path_traversal",
            "Cross-Site Scripting (XSS)": "cross_site_scripting",
        }
        return mapping.get(vuln_type, "other")

    @staticmethod
    def _map_severity(severity: str) -> str:
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        return mapping.get((severity or "").upper(), "medium")

    def _save_statistics(self, path: str = "hunting_stats.json") -> Dict[str, Any]:
        stats = {
            "timestamp": datetime.now().isoformat(),
            "total_vulns_found": self.total_vulns_found,
            "total_bounty_earned": self.total_bounty_earned,
            "recent_submissions": self.submissions[-10:],
        }
        with open(path, "w", encoding="utf-8") as file_obj:
            json.dump(stats, file_obj, indent=2)
        return stats


async def _run(cycles: int, interval_seconds: int, target_limit: int, assets_per_target: int, auto_submit: bool) -> None:
    hunter = AutonomousAutoHunter(auto_submit=auto_submit)
    for cycle in range(1, cycles + 1):
        result = await hunter.hunt_once(target_limit=target_limit, assets_per_target=assets_per_target)
        print(
            json.dumps(
                {
                    "cycle": cycle,
                    "selected_targets": len(result.get("targets", [])),
                    "total_vulns_found": hunter.total_vulns_found,
                    "total_bounty_earned": hunter.total_bounty_earned,
                },
                indent=2,
            )
        )
        if cycle < cycles:
            await asyncio.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous target selection and hunting runner")
    parser.add_argument("--cycles", type=int, default=1, help="Number of hunting cycles to run")
    parser.add_argument("--interval-seconds", type=int, default=3600, help="Delay between cycles in seconds")
    parser.add_argument("--target-limit", type=int, default=10, help="Maximum number of selected programs per cycle")
    parser.add_argument("--assets-per-target", type=int, default=3, help="Maximum scoped assets scanned per program")
    parser.add_argument("--auto-submit", action="store_true", help="Submit reports automatically to HackerOne")
    args = parser.parse_args()

    asyncio.run(
        _run(
            cycles=max(args.cycles, 1),
            interval_seconds=max(args.interval_seconds, 1),
            target_limit=max(args.target_limit, 1),
            assets_per_target=max(args.assets_per_target, 1),
            auto_submit=args.auto_submit,
        )
    )


if __name__ == "__main__":
    main()
