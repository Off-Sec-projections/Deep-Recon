"""Main orchestration for advanced vulnerability hunting."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Dict, List

from advanced_vulnerability_finder import AdvancedVulnerabilityFinder


async def complete_hunt(targets: List[str]) -> Dict[str, List[dict]]:
    """Run advanced vulnerability hunting for each target URL."""
    results: Dict[str, List[dict]] = {}

    for target in targets:
        finder = AdvancedVulnerabilityFinder(target)
        results[target] = await finder.hunt_vulnerabilities()

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run advanced vulnerability hunting against target URLs")
    parser.add_argument("targets", nargs="+", help="Target URLs to scan (for example: https://example.com)")
    args = parser.parse_args()

    results = asyncio.run(complete_hunt(args.targets))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
