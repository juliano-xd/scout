#!/usr/bin/env python3

import logging
from typing import Dict, List, Any

logger = logging.getLogger("ScoutReasoning")

class ReasoningEngine:
    """
    Synthesizes findings from all engines to provide high-level logical insights.
    Converts raw data into 'stories' for AI consumption.
    """

    def synthesize(self, report: Dict[str, Any]) -> List[Dict[str, str]]:
        insights = []
        findings = report.get("findings", {})
        
        # 1. Map UI interactions to sensitive actions
        ui_trace = findings.get("ui_trace", {})
        if ui_trace:
            query = ui_trace.get("query")
            handlers = ui_trace.get("handlers", [])
            for h in handlers:
                insight = {
                    "level": "INFO",
                    "source": "UI_LOGIC",
                    "text": f"UI Element '{query}' is handled by {h['class']}. Trace this for business logic."
                }
                insights.append(insight)

        # 2. Correlate API usage with UI
        api_stats = findings.get("api_stats", {})
        api_stats_str = str(api_stats).lower()
        has_crypto = any(x in api_stats_str for x in ["crypto", "cipher", "secretkey"])
        has_network = any(x in api_stats_str for x in ["net/url", "okhttp", "httpurl"])
        has_file = any(x in api_stats_str for x in ["io/file", "contentresolver", "openfile"])

        if has_crypto and ui_trace:
            insights.append({
                "level": "HIGH",
                "source": "SECURITY",
                "text": "UI interactions potentially trigger cryptographic operations. Check for sensitive data handling."
            })

        # 3. Network & Data Correlation
        if has_network and has_file:
            insights.append({
                "level": "MEDIUM",
                "source": "DATA_FLOW",
                "text": "App performs both File IO and Network operations. Monitor for data exfiltration patterns."
            })
        elif has_network:
            insights.append({
                "level": "INFO",
                "source": "NETWORK",
                "text": "Network activity detected. Use Frida to monitor endpoint communication."
            })

        return insights

    def generate_ai_summary(self, report: Dict[str, Any]) -> str:
        """Generates a markdown summary optimized for an AI agent's next steps."""
        insights = self.synthesize(report)
        summary = ["# Scout AI Reasoning Summary\n"]
        
        if not insights:
            summary.append("No critical cross-engine correlations found.")
        else:
            for opt in sorted(insights, key=lambda x: x["level"], reverse=True):
                summary.append(f"[{opt['level']}] {opt['text']}")
        
        summary.append("\n## Recommended Next Steps for AI Agent:")
        summary.append("1. Run `--brain` on identified UI handlers.")
        summary.append("2. Use Frida to intercept identified crypto/network APIs.")
        
        return "\n".join(summary)
