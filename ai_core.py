"""
AI Core Engine - Powers autonomous vulnerability discovery and exploitation
Uses NVIDIA NIM API for intelligent decision-making
"""

import os
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
import aiohttp
import re
from datetime import datetime

logger = logging.getLogger('ai_core')

class AICore:
    """Main AI intelligence for autonomous bug hunting"""
    
    def __init__(self, api_key: str = None, model: str = "meta/llama-2-70b-chat"):
        """Initialize AI Core with NVIDIA NIM API"""
        self.api_key = api_key or os.getenv('NVIDIA_API_KEY')
        self.model = model
        self.base_url = "https://integrate.api.nvidia.com/v1"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.conversation_history = []
        self.target_context = {}
        self.vulnerability_cache = {}
        
    async def analyze_response(self, endpoint: str, response_data: Dict) -> Dict[str, Any]:
        """
        AI analyzes HTTP response for vulnerabilities
        Returns: list of hypothesized vulnerabilities with confidence scores
        """
        
        analysis_prompt = f"""
You are an expert penetration tester analyzing an HTTP response for vulnerabilities.

TARGET ENDPOINT: {endpoint}

RESPONSE DATA:
- Status Code: {response_data.get('status_code')}
- Headers: {json.dumps(response_data.get('headers', {}))}
- Body Length: {len(response_data.get('body', ''))}
- Body Sample: {response_data.get('body', '')[:500]}
- Response Time: {response_data.get('response_time')}ms
- Content-Type: {response_data.get('content_type')}

ANALYZE AND IDENTIFY:
1. What vulnerabilities might exist in this endpoint?
2. Which parameters look exploitable?
3. What error messages reveal information?
4. What encoding/serialization is used?
5. Are there any authentication bypasses?

RESPOND IN JSON FORMAT:
{{
    "vulnerabilities": [
        {{"type": "SQLi", "confidence": 0.8, "parameter": "id", "reason": "..."}},
        {{"type": "XSS", "confidence": 0.6, "parameter": "search", "reason": "..."}},
    ],
    "tech_stack": ["PHP", "Apache"],
    "attack_vectors": ["Parameter tampering", "Error-based SQLi"],
    "next_tests": ["Try SQL union-based injection", "Test XSS with different payloads"]
}}
"""
        
        result = await self._call_ai(analysis_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                return analysis
        except:
            logger.warning(f"Failed to parse AI analysis: {result}")
        
        return {"vulnerabilities": [], "tech_stack": [], "attack_vectors": []}
    
    async def generate_payload(self, vulnerability_type: str, target_context: Dict, 
                              filter_patterns: List[str] = None) -> List[str]:
        """
        AI generates target-specific payloads
        Adapts based on detected filters and WAF rules
        """
        
        payload_prompt = f"""
You are an expert exploit developer. Generate payloads for this vulnerability.

VULNERABILITY TYPE: {vulnerability_type}
TARGET CONTEXT:
- Technology: {target_context.get('tech_stack', [])}
- Database: {target_context.get('database', 'unknown')}
- Parameter: {target_context.get('parameter')}
- Previous Blocked Payloads: {filter_patterns or []}

REQUIREMENTS:
1. Generate 5 DIFFERENT payload variations
2. Each variation should try a different bypass technique
3. Consider the tech stack when generating
4. Avoid patterns from 'Previous Blocked Payloads'
5. For SQLi: Try union-based, time-based blind, error-based
6. For XSS: Try different event handlers and encoding
7. Include commentary on why each payload should work

RESPOND IN JSON FORMAT:
{{
    "payloads": [
        {{"payload": "...", "technique": "union-based", "likelihood": 0.9, "reason": "..."}},
        {{"payload": "...", "technique": "url-encoded double", "likelihood": 0.7, "reason": "..."}},
    ],
    "payload_ranking": ["Best", "Second", ...],
    "bypass_strategies": ["Use /* */ comments", "Try encoding variations"]
}}
"""
        
        result = await self._call_ai(payload_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                payload_data = json.loads(json_match.group())
                payloads = [p["payload"] for p in payload_data.get("payloads", [])]
                return payloads
        except:
            logger.warning(f"Failed to parse payloads: {result}")
        
        return []
    
    async def detect_waf(self, blocked_responses: List[Dict]) -> Dict[str, Any]:
        """
        AI fingerprints WAF from blocked responses
        Returns WAF type and bypass techniques
        """
        
        waf_prompt = f"""
You are a WAF fingerprinting expert. Analyze these blocked responses to identify the WAF.

BLOCKED RESPONSES:
{json.dumps(blocked_responses[:5], indent=2)}

IDENTIFY:
1. What WAF is likely running? (Cloudflare, AWS WAF, Imperva, etc.)
2. What patterns trigger blocking?
3. What encodings might bypass it?
4. What false positive vectors exist?

RESPOND IN JSON FORMAT:
{{
    "waf_type": "Cloudflare",
    "confidence": 0.85,
    "blocking_patterns": ["', 'union", "alert("],
    "bypass_techniques": [
        "URL encode spaces: %20",
        "Double URL encode",
        "UTF-8 encoding",
        "Case manipulation",
        "Comment insertion"
    ],
    "false_positive_tests": [
        "Test with legitimate SQL comments",
        "Use benign parameters"
    ]
}}
"""
        
        result = await self._call_ai(waf_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                waf_data = json.loads(json_match.group())
                return waf_data
        except:
            pass
        
        return {"waf_type": "Unknown", "bypass_techniques": []}
    
    async def decide_next_attack(self, target_data: Dict, findings_so_far: List) -> Dict[str, Any]:
        """
        AI decides what to attack next based on findings
        Prioritizes by likelihood of success and impact
        """
        
        decision_prompt = f"""
You are a strategic penetration tester. Based on reconnaissance findings, decide what to test next.

TARGET: {target_data.get('domain')}
TECH STACK: {target_data.get('tech_stack', [])}
DISCOVERED ENDPOINTS: {target_data.get('endpoints', [])[:10]}
FINDINGS SO FAR: {json.dumps(findings_so_far, indent=2)}
SUCCESSFUL EXPLOITS: {target_data.get('successful_exploits', [])}

STRATEGY:
1. What's the highest-impact vulnerability to pursue?
2. Which endpoint is most likely vulnerable?
3. What type of vulnerability should we test? (SQLi, XSS, RCE, SSRF, etc.)
4. Should we escalate to post-exploitation?
5. What's the success probability?

RESPOND IN JSON FORMAT:
{{
    "next_target": "admin_panel",
    "vulnerability_type": "SQLi",
    "parameter": "user_id",
    "reasoning": "...",
    "priority": 1,
    "estimated_success": 0.85,
    "escalation_path": "SQLi -> Database dump -> Admin access -> RCE"
}}
"""
        
        result = await self._call_ai(decision_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group())
                return decision
        except:
            pass
        
        return {
            "next_target": None,
            "vulnerability_type": "Unknown",
            "priority": 0
        }
    
    async def generate_report(self, findings: List, vulnerabilities: List, 
                             exploitations: List) -> str:
        """
        AI generates professional penetration test report
        """
        
        report_prompt = f"""
Generate a professional penetration test report in markdown format.

FINDINGS:
{json.dumps(findings, indent=2)}

VULNERABILITIES DISCOVERED:
{json.dumps(vulnerabilities, indent=2)}

SUCCESSFUL EXPLOITATIONS:
{json.dumps(exploitations, indent=2)}

INCLUDE:
1. Executive Summary
2. Reconnaissance Findings
3. Vulnerability Details (with CVSS scores)
4. Exploitation Proof-of-Concept
5. Impact Analysis
6. Remediation Recommendations
7. Timeline

MAKE IT PROFESSIONAL AND DETAILED.
"""
        
        result = await self._call_ai(report_prompt, max_tokens=2000)
        return result
    
    async def _call_ai(self, prompt: str, max_tokens: int = 1000) -> str:
        """Make API call to NVIDIA NIM"""
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": max_tokens,
                    "top_p": 0.9
                }
                
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data['choices'][0]['message']['content']
                    else:
                        logger.error(f"AI API error: {resp.status}")
                        error_text = await resp.text()
                        logger.error(f"Error: {error_text}")
                        return ""
        except Exception as e:
            logger.error(f"AI call failed: {e}")
            return ""
    
    def add_context(self, key: str, value: Any):
        """Store context for AI to reference"""
        self.target_context[key] = value
    
    def clear_context(self):
        """Reset context"""
        self.target_context = {}
