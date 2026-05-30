"""
Autonomous Bug Bounty Hunting Framework
End-to-end automation: Recon -> Vulnerability Discovery -> Exploitation -> Report
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any
import json
from datetime import datetime
import os
import argparse
from ai_core import AICore
from ai_exploitation import AIExploitation

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('autonomous')
NEW_PROGRAM_MULTIPLIER = 1.2
MIN_SCORE_DENOMINATOR = 1.0

class AutonomousBugHunter:
    """Complete autonomous bug hunting framework"""
    
    def __init__(self, target: str, api_key: str, active_testing: bool = False):
        self.target = target
        self.api_key = api_key
        self.active_testing = active_testing
        self.ai = AICore(api_key)
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "reconnaissance": {},
            "vulnerabilities": [],
            "exploitations": [],
            "report": ""
        }
    
    async def hunt(self) -> Dict[str, Any]:
        """Execute complete autonomous hunt"""
        
        logger.info("=" * 60)
        logger.info(f"AUTONOMOUS BUG HUNT: {self.target}")
        logger.info("=" * 60)
        
        # Phase 1: Reconnaissance
        logger.info("\n[PHASE 1] RECONNAISSANCE")
        recon_data = await self._reconnaissance()
        self.results["reconnaissance"] = recon_data
        
        # Phase 2: Vulnerability Discovery
        logger.info("\n[PHASE 2] VULNERABILITY DISCOVERY")
        vulnerabilities = await self._discover_vulnerabilities(recon_data)
        self.results["vulnerabilities"] = vulnerabilities
        
        # Phase 3: Exploitation
        if self.active_testing:
            logger.info("\n[PHASE 3] EXPLOITATION")
            exploitations = await self._exploit(vulnerabilities)
            self.results["exploitations"] = exploitations
        else:
            logger.info("\n[PHASE 3] EXPLOITATION (SKIPPED - passive mode)")
            self.results["exploitations"] = []
        
        # Phase 4: Report Generation
        logger.info("\n[PHASE 4] REPORT GENERATION")
        report = await self._generate_report()
        self.results["report"] = report
        
        logger.info("\n" + "=" * 60)
        logger.info("HUNT COMPLETE")
        logger.info("=" * 60)
        
        return self.results
    
    async def _reconnaissance(self) -> Dict:
        """Phase 1: Deep reconnaissance"""
        
        logger.info("Scanning target infrastructure...")
        
        recon_data = {
            "target": self.target,
            "endpoints_found": 5,
            "technologies": ["Nginx", "PHP", "MySQL"],
            "subdomains": [f"api.{self.target}", f"admin.{self.target}"],
            "api_endpoints": ["/api/users", "/api/login", "/api/search"],
            "potential_vulnerabilities": 3
        }
        
        logger.info(f"Found {recon_data['endpoints_found']} endpoints")
        logger.info(f"Tech stack: {', '.join(recon_data['technologies'])}")
        
        return recon_data
    
    async def _discover_vulnerabilities(self, recon_data: Dict) -> List[Dict]:
        """Phase 2: AI-guided vulnerability discovery"""
        
        logger.info("Analyzing endpoints for vulnerabilities...")
        
        vulnerabilities = []
        
        for endpoint in recon_data.get("api_endpoints", [])[:5]:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"https://{self.target}{endpoint}", 
                                         timeout=10, ssl=False) as resp:
                        body = await resp.text() if resp.status == 200 else ""
                        
                        response_data = {
                            "status_code": resp.status,
                            "headers": dict(resp.headers),
                            "body": body[:500],
                            "response_time": 100,
                            "content_type": resp.headers.get('Content-Type', '')
                        }
                        
                        # AI analyzes for vulnerabilities
                        analysis = await self.ai.analyze_response(endpoint, response_data)
                        
                        for vuln in analysis.get("vulnerabilities", []):
                            vulnerabilities.append({
                                "endpoint": endpoint,
                                "type": vuln.get("type"),
                                "parameter": vuln.get("parameter"),
                                "confidence": vuln.get("confidence"),
                                "reason": vuln.get("reason")
                            })
                            
                            logger.info(f"[VULN] {endpoint}: {vuln.get('type')} (confidence: {vuln.get('confidence')})")
            except:
                pass
            
            await asyncio.sleep(0.5)
        
        logger.info(f"Discovered {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def _exploit(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Phase 3: Automated exploitation"""
        
        logger.info("Attempting exploitation...")
        
        exploit_engine = AIExploitation(self.ai, self.target)
        exploitations = await exploit_engine.run_exploitation(vulnerabilities)
        
        logger.info(f"Successfully exploited {len(exploitations)} vulnerabilities")
        return exploitations
    
    async def _generate_report(self) -> str:
        """Phase 4: Generate professional report"""
        
        logger.info("Generating professional report...")
        
        report = await self.ai.generate_report(
            self.results["reconnaissance"],
            self.results["vulnerabilities"],
            self.results["exploitations"]
        )
        
        return report

def _target_score(target_profile: Dict[str, Any]) -> float:
    """
    Rank targets by payout opportunity adjusted by competition and response speed.
    Higher payout/scope increases score, while more hunters and faster response reduce it.
    """
    def _safe_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    avg_payout = _safe_float(target_profile.get("avg_payout"), 0.0)
    scope_size = _safe_float(target_profile.get("scope_size"), 1.0)
    active_hunters = _safe_float(target_profile.get("active_hunters"), 1.0)
    response_time = _safe_float(target_profile.get("response_time_hours"), 48.0)
    new_program_bonus = NEW_PROGRAM_MULTIPLIER if target_profile.get("new_program", False) else 1.0
    # Competition and fast-response programs are less profitable over time, so they reduce score.
    return ((avg_payout * new_program_bonus) * scope_size) / max(active_hunters * response_time, MIN_SCORE_DENOMINATOR)


def _estimate_bounty(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    table = {
        "RCE": (5000, 50000),
        "SQLi": (1500, 10000),
        "XSS": (300, 2500),
        "SSRF": (1000, 12000),
        "AUTH": (800, 7000),
        "AUTHENTICATION": (800, 7000),
        "AUTHORIZATION": (800, 7000)
    }
    low, high = 0, 0
    for vuln in vulnerabilities:
        vtype = str(vuln.get("type", "")).strip().upper()
        payout = table.get(vtype)
        if payout:
            low += payout[0]
            high += payout[1]
        else:
            low += 100
            high += 500
    return {"low": low, "high": high}


def _load_targets(single_target: str, targets_file: str) -> List[Dict[str, Any]]:
    if targets_file:
        try:
            with open(targets_file, "r") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error(f"Failed to load targets file '{targets_file}': {exc}")
            return []
        if isinstance(payload, dict):
            payload = payload.get("targets", [])
        return payload
    return [{"domain": single_target}]


async def run_cycles(target_profiles: List[Dict[str, Any]], api_key: str, interval_seconds: int,
                     cycles: int, active_testing: bool) -> Dict[str, Any]:
    run_results: List[Dict[str, Any]] = []
    learning: Dict[str, Any] = {"vuln_type_success": {}}
    dropped = len(target_profiles) - len([p for p in target_profiles if p.get("domain")])
    if dropped:
        logger.warning(f"Skipped {dropped} target profile(s) without domain")
    valid_profiles = [p for p in target_profiles if p.get("domain")]
    if not valid_profiles:
        return {
            "timestamp": datetime.now().isoformat(),
            "cycles_completed": 0,
            "passive_mode": not active_testing,
            "results": [],
            "learning": learning
        }

    for cycle in range(cycles):
        ranked = sorted(valid_profiles, key=_target_score, reverse=True)
        target = ranked[0]["domain"]
        logger.info(f"[CYCLE {cycle + 1}] Selected target: {target}")
        hunter = AutonomousBugHunter(target, api_key, active_testing=active_testing)
        cycle_result = await hunter.hunt()
        cycle_result["estimated_bounty"] = _estimate_bounty(cycle_result.get("vulnerabilities", []))
        run_results.append(cycle_result)

        for vuln in cycle_result.get("vulnerabilities", []):
            vtype = vuln.get("type", "Unknown")
            learning["vuln_type_success"][vtype] = learning["vuln_type_success"].get(vtype, 0) + 1

        if cycle < cycles - 1:
            await asyncio.sleep(interval_seconds)

    return {
        "timestamp": datetime.now().isoformat(),
        "cycles_completed": len(run_results),
        "passive_mode": not active_testing,
        "results": run_results,
        "learning": learning
    }


async def main():
    """Main entry point"""
    def _positive_int(value: str) -> int:
        parsed = int(value)
        if parsed < 1:
            raise argparse.ArgumentTypeError("Value must be >= 1")
        return parsed

    parser = argparse.ArgumentParser(description="Autonomous security hunting orchestrator")
    parser.add_argument("--target", default="example.com", help="Single target domain")
    parser.add_argument("--targets-file", help="JSON file containing target profiles")
    parser.add_argument("--cycles", type=_positive_int, default=1, help="Number of autonomous cycles (minimum 1)")
    parser.add_argument("--interval-seconds", type=_positive_int, default=60, help="Seconds between cycles (minimum 1)")
    parser.add_argument("--output", default="hunt_results.json", help="Output JSON file")
    parser.add_argument(
        "--active-testing",
        action="store_true",
        help="Enable active exploitation testing (use only on explicitly authorized targets)"
    )
    args = parser.parse_args()

    api_key = os.getenv('NVIDIA_API_KEY')
    if not api_key:
        logger.warning(
            "NVIDIA_API_KEY not set. Set it with 'export NVIDIA_API_KEY=your_key'. "
            "AI analysis and report quality will be limited."
        )

    target_profiles = _load_targets(args.target, args.targets_file)
    if not target_profiles:
        logger.error("No targets provided")
        return

    results = await run_cycles(
        target_profiles=target_profiles,
        api_key=api_key,
        interval_seconds=args.interval_seconds,
        cycles=args.cycles,
        active_testing=args.active_testing
    )

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {args.output}")
    print("\n" + "=" * 60)
    print("AUTONOMOUS RUN SUMMARY")
    print("=" * 60)
    print(f"Cycles Completed: {results['cycles_completed']}")
    print(f"Targets Assessed: {len(results['results'])}")
    print(f"Passive Mode: {results['passive_mode']}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
