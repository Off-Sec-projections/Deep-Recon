"""
HackerOne API client.
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import Any, Dict, List, Optional

import aiohttp


class HackerOneClient:
    """Async HackerOne API client."""

    def __init__(self, username: str, api_token: str) -> None:
        self.username = username
        self.api_token = api_token
        self.base_url = "https://api.hackerone.com"
        self.headers = self._get_auth_headers()

    def _get_auth_headers(self) -> Dict[str, str]:
        credentials = f"{self.username}:{self.api_token}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        return {
            "Authorization": f"Basic {encoded}",
            "Accept": "application/json",
        }

    async def search_programs(self, query: str = "") -> List[Dict[str, Any]]:
        url = f"{self.base_url}/v1/hackers/programs"
        params = {
            "filter[offers_bounties]": "true",
            "page[size]": 100,
        }
        if query:
            params["filter[search]"] = query

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError):
                return []

        programs = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            programs.append(
                {
                    "id": item.get("id"),
                    "name": attrs.get("name"),
                    "handle": attrs.get("handle"),
                    "submission_state": attrs.get("submission_state"),
                    "launched_at": attrs.get("launched_at"),
                    "average_bounty": attrs.get("average_bounty_lower_amount"),
                    "minimum_bounty": attrs.get("minimum_bounty"),
                    "maximum_bounty": attrs.get("maximum_bounty"),
                    "average_response_time": attrs.get("average_time_to_triage"),
                    "active_hackers_count": attrs.get("active_hackers_count"),
                }
            )
        return programs

    async def get_program_details(self, program_handle: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/hackers/programs/{program_handle}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return {}
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError):
                return {}

        attrs = data.get("data", {}).get("attributes", {})
        return {
            "id": data.get("data", {}).get("id"),
            "name": attrs.get("name"),
            "handle": attrs.get("handle"),
            "overview": attrs.get("policy"),
            "submission_state": attrs.get("submission_state"),
            "average_bounty": attrs.get("average_bounty_lower_amount"),
            "maximum_bounty": attrs.get("maximum_bounty"),
            "minimum_bounty": attrs.get("minimum_bounty"),
        }

    async def get_program_scope(self, program_handle: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/v1/hackers/programs/{program_handle}/structured_scopes"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError):
                return []

        scopes = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            scopes.append(
                {
                    "id": item.get("id"),
                    "asset_type": attrs.get("asset_type"),
                    "asset_identifier": attrs.get("asset_identifier"),
                    "eligible_for_submission": attrs.get("eligible_for_submission"),
                    "eligible_for_bounty": attrs.get("eligible_for_bounty"),
                    "instruction": attrs.get("instruction"),
                }
            )
        return scopes

    async def submit_report(self, program_handle: str, report_data: Dict[str, Any]) -> Optional[str]:
        url = f"{self.base_url}/v1/reports"
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": report_data.get("title"),
                    "vulnerability_information": report_data.get("description"),
                    "impact": report_data.get("impact"),
                    "severity_rating": report_data.get("severity_rating"),
                    "weakness_name": report_data.get("weakness_id", "Other"),
                },
                "relationships": {
                    "program": {"data": {"type": "program", "id": program_handle}}
                },
            }
        }
        headers = {**self.headers, "Content-Type": "application/json"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status not in (200, 201):
                        return None
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError):
                return None
        return data.get("data", {}).get("id")

    async def get_submissions(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/v1/reports"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError):
                return []

        submissions = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            submissions.append(
                {
                    "id": item.get("id"),
                    "title": attrs.get("title"),
                    "state": attrs.get("state"),
                    "bounty_awarded": attrs.get("bounty_awarded"),
                    "bounty_amount": attrs.get("bounty_amount"),
                    "severity_rating": attrs.get("severity_rating"),
                    "created_at": attrs.get("created_at"),
                }
            )
        return submissions


async def demo_hackerone() -> None:
    username = os.getenv("H1_USERNAME")
    api_token = os.getenv("H1_API_TOKEN")
    if not username or not api_token:
        print("ERROR: Set H1_USERNAME and H1_API_TOKEN")
        return

    client = HackerOneClient(username, api_token)
    programs = await client.search_programs(query="web")
    print(f"Found {len(programs)} programs")
    for program in programs[:5]:
        print(f"- {program.get('name')} ({program.get('handle')})")


if __name__ == "__main__":
    asyncio.run(demo_hackerone())
