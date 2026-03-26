#!/usr/bin/env python3

import logging
from typing import Dict, List, Set, Any

logger = logging.getLogger("ScoutBehavior")

class BehaviorEngine:
    """
    Analyzes API call sequences and code patterns to identify high-level 
    application behaviors (Privacy, Security, Anti-Analysis).
    """

    def __init__(self, knowledge_base=None):
        self.kb = knowledge_base
        # Definitions of "Behavioral Fingerprints"
        self.fingerprints = {
            "DATA_EXFILTRATION": [
                "Landroid/telephony/TelephonyManager;->getDeviceId",
                "Ljava/net/HttpURLConnection;->connect",
                "Lokhttp3/OkHttpClient;->newCall",
                "Landroid/content/ContentResolver;->query"
            ],
            "CRYPTO_SENSITIVE": [
                "Ljavax/crypto/Cipher;->init",
                "Ljavax/crypto/Cipher;->doFinal",
                "Ljavax/crypto/spec/SecretKeySpec;-><init>"
            ],
            "ANTI_ANALYSIS": [
                "Landroid/os/Debug;->isDebuggerConnected",
                "Ljava/lang/System;->exit",
                "Landroid/content/pm/PackageManager;->getInstallerPackageName"
            ],
            "LOCATION_TRACKING": [
                "Landroid/location/LocationManager;->getLastKnownLocation",
                "Landroid/location/LocationListener;->onLocationChanged"
            ],
            "DANGEROUS_INFRA": [
                "malicious.com",
                "attacker.net",
                "api.evil"
            ]
        }
        
        # New high-precision flow-based fingerprints
        self.flow_fingerprints = {
            "CONFIRMED_DATA_LEAK": [
                ("TelephonyManager;->getDeviceId", "HttpURLConnection;->connect"),
                ("TelephonyManager;->getDeviceId", "OkHttpClient;->newCall"),
                ("TelephonyManager;->getSubscriberId", "URL;->connect"),
                ("URL", "OkHttpClient;->newCall")
            ],
            "UNSAFE_CRYPTO_USAGE": [
                ("B64", "Cipher;->init"),
                ("SecretKeySpec", "Cipher;->init")
            ]
        }

    def analyze(self, api_counts: Dict[str, int], taint_flows: List[Dict] = None) -> List[Dict[str, Any]]:
        """
        Cross-references found APIs and Taint Flows with known behavioral fingerprints.
        """
        findings = []
        found_apis = set(api_counts.keys())
        
        # 1. API/Pattern Based Analysis (Heuristic)
        for behavior, required_patterns in self.fingerprints.items():
            matches = []
            for req in required_patterns:
                for found in found_apis:
                    # Lenient matching: either template is in hit, or hit is in template (for class-only hits)
                    if req in found or found in req:
                        matches.append(found)
                        break
            
            if matches:
                confidence = len(matches) / len(required_patterns)
                findings.append({
                    "type": behavior if behavior != "DANGEROUS_INFRA" else "Dangerous Infrastructure",
                    "confidence": round(confidence * 100, 2),
                    "evidence": matches,
                    "method": "heuristic"
                })

        # 2. Flow-Based Analysis (High Precision)
        if taint_flows:
            for behavior, required_flows in self.flow_fingerprints.items():
                matched_flows = []
                for src_req, snk_req in required_flows:
                    for flow in taint_flows:
                        if src_req in flow["src"] and snk_req in flow["sink"]:
                            matched_flows.append(flow)
                
                if matched_flows:
                    findings.append({
                        "type": behavior,
                        "confidence": 100.0,
                        "evidence": [f"Flow: {f['src']} -> {f['sink']} in {f['method']}" for f in matched_flows],
                        "method": "taint_flow"
                    })
        
        return sorted(findings, key=lambda x: x["confidence"], reverse=True)

    def analyze_findings(self, findings: Dict, taint_flows: List[Dict] = None) -> List[Dict[str, Any]]:
        """API adapter for analyze() using a findings dictionary."""
        api_counts = {}
        scans = findings.get("scans", {})
        
        # Normalize 'apis' access
        apis = findings.get("apis", {})
        if not apis and isinstance(scans, dict):
            apis = scans.get("apis", {})
        
        for api, cl_list in apis.items():
            api_counts[api] = len(cl_list) if isinstance(cl_list, list) else int(cl_list)
        
        if isinstance(scans, dict):
            # Process crypto classes
            if "crypto" in scans:
                for crypto_cl in scans["crypto"]:
                    api_counts[crypto_cl] = 1
            # Process malicious strings
            if "strings" in scans:
                for s in scans["strings"]:
                    api_counts[s] = 1

        return self.analyze(api_counts, taint_flows)

    def synthesize_behavior(self, findings: Dict, taint_flows: List[Dict] = None) -> str:
        behaviors = self.analyze_findings(findings, taint_flows)
        return self.generate_summary(behaviors)

    def generate_summary(self, behavioral_findings: List[Dict[str, Any]]) -> str:
        """Generates a human-friendly behavioral summary."""
        if not behavioral_findings:
            return "No distinct high-level behaviors identified."
            
        summary = ["### [Scout Behavioral Profile]"]
        for f in behavioral_findings:
            method_tag = " [CONFIRMED]" if f.get("method") == "taint_flow" else ""
            level = "CRITICAL" if f["confidence"] > 60 else "SUSPICIOUS"
            summary.append(f"- **{f['type']}** ({level}: {f['confidence']}% confidence){method_tag}")
            summary.append(f"  * Evidence: {', '.join(f['evidence'][:3])}")
            
        return "\n".join(summary)
