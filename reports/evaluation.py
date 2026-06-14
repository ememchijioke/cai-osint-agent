"""
evaluation.py

Creates simple evaluation metrics for the CAI OSINT Recon Agent.

These metrics help make the project more defensible during presentation.
"""

import json
from pathlib import Path
from datetime import datetime


def generate_evaluation_metrics(memory_data: dict, output_path: str) -> dict:
    """
    Generate and save evaluation metrics from the agent memory.
    """
    observations = memory_data.get("observations", {})
    agent_trace = memory_data.get("agent_trace", [])
    cai_analysis = memory_data.get("cai_analysis", {})

    nmap_result = observations.get("nmap_scan", {})
    open_ports = nmap_result.get("open_ports", [])

    tools_executed = [
        step.get("tool")
        for step in agent_trace
        if step.get("tool") not in ["target_validator", "stop"]
    ]

    evidence_keys = [
        "dns_lookup",
        "whois_lookup",
        "nmap_scan",
        "web_headers",
        "tls_check",
    ]

    collected_evidence = [
        key for key in evidence_keys if key in observations
    ]

    metrics = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": memory_data.get("target"),
        "total_agent_steps": len(agent_trace),
        "tools_executed": tools_executed,
        "number_of_tools_executed": len(tools_executed),
        "evidence_collected": collected_evidence,
        "evidence_coverage_count": len(collected_evidence),
        "evidence_coverage_total": len(evidence_keys),
        "evidence_coverage_percent": round(
            (len(collected_evidence) / len(evidence_keys)) * 100, 2
        ),
        "open_ports_detected": open_ports,
        "number_of_open_ports": len(open_ports),
        "ai_provider": cai_analysis.get("provider", "none"),
        "ai_mode": cai_analysis.get("mode", "none"),
        "ai_success": cai_analysis.get("success", False),
        "safety_target_allowed": observations.get("target_validation", {}).get("allowed"),
        "report_generated": True,
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    return metrics
