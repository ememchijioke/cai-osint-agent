"""
cai_runner.py

CAI integration layer for the CAI OSINT Recon Agent.

This module provides the cybersecurity AI agent reasoning layer for the project.
It uses constrained, evidence-grounded prompts and records CAI-related settings
for traceability.

Supported providers:
- OpenAI
- Gemini
- Fallback local evidence summary
"""

import os
from dotenv import load_dotenv

from agent.prompt_templates import (
    SYSTEM_PROMPT,
    build_cai_mission_prompt,
    build_evidence_summary_prompt,
)


def get_cai_environment_status() -> dict:
    """
    Collect CAI-related environment settings for traceability.
    """
    return {
        "AI_PROVIDER": os.getenv("AI_PROVIDER", "fallback"),
        "CAI_LICENSE_OFF": os.getenv("CAI_LICENSE_OFF", "not_set"),
        "CAI_TRACING": os.getenv("CAI_TRACING", "not_set"),
        "CAI_MODE": os.getenv("CAI_MODE", "not_set"),
    }


def run_cai_analysis(memory_data: dict, config: dict) -> dict:
    """
    Run the CAI-style analysis layer.

    Args:
        memory_data: full AgentMemory data
        config: project config

    Returns:
        dictionary containing CAI-style analysis result
    """
    load_dotenv()

    target = memory_data.get("target", "Unknown target")
    mission_prompt = build_cai_mission_prompt(target)
    evidence_prompt = build_evidence_summary_prompt(memory_data)
    cai_environment = get_cai_environment_status()

    provider = os.getenv("AI_PROVIDER", "fallback").strip().lower()

    result = {
        "success": False,
        "mode": "fallback",
        "provider": provider,
        "target": target,
        "framework": "CAI-compatible evidence-grounded agent layer",
        "cai_environment": cai_environment,
        "mission_prompt": mission_prompt.strip(),
        "analysis": "",
        "error": None,
    }

    if provider == "openai":
        return run_openai_analysis(result, evidence_prompt, memory_data)

    if provider == "gemini":
        return run_gemini_analysis(result, evidence_prompt, memory_data)

    result["analysis"] = build_fallback_analysis(memory_data)
    result["error"] = "AI_PROVIDER is set to fallback or unsupported provider."
    return result


def run_openai_analysis(result: dict, evidence_prompt: str, memory_data: dict) -> dict:
    """
    Run evidence analysis using OpenAI.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = os.getenv("MODEL_NAME", "gpt-4o-mini")

    if not api_key:
        result["analysis"] = build_fallback_analysis(memory_data)
        result["error"] = "OPENAI_API_KEY not found. Used fallback evidence summary."
        return result

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": evidence_prompt},
            ],
            temperature=0.2,
        )

        result["success"] = True
        result["mode"] = "llm"
        result["provider"] = "openai"
        result["analysis"] = response.choices[0].message.content
        return result

    except Exception as error:
        result["analysis"] = build_fallback_analysis(memory_data)
        result["error"] = f"OpenAI call failed. Used fallback analysis. Error: {error}"
        return result


def run_gemini_analysis(result: dict, evidence_prompt: str, memory_data: dict) -> dict:
    """
    Run evidence analysis using Google Gemini.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("GEMINI_MODEL_NAME", "gemini-2.5-flash")

    if not api_key:
        result["analysis"] = build_fallback_analysis(memory_data)
        result["error"] = "GEMINI_API_KEY not found. Used fallback evidence summary."
        return result

    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        combined_prompt = f"""
{SYSTEM_PROMPT}

{evidence_prompt}
"""

        response = client.models.generate_content(
            model=model_name,
            contents=combined_prompt,
        )

        result["success"] = True
        result["mode"] = "llm"
        result["provider"] = "gemini"
        result["analysis"] = response.text
        return result

    except Exception as error:
        result["analysis"] = build_fallback_analysis(memory_data)
        result["error"] = f"Gemini call failed. Used fallback analysis. Error: {error}"
        return result


def build_fallback_analysis(memory_data: dict) -> str:
    """
    Build a simple evidence-based summary without using an external model.

    This keeps the project working offline and avoids demo failure.
    """
    target = memory_data.get("target", "Unknown target")
    observations = memory_data.get("observations", {})

    nmap_result = observations.get("nmap_scan", {})
    open_ports = nmap_result.get("open_ports", [])

    dns_result = observations.get("dns_lookup", {})
    headers_result = observations.get("web_headers", {})
    tls_result = observations.get("tls_check", {})

    lines = []

    lines.append("## AI-Assisted Analysis")
    lines.append("")
    lines.append("### 1. Offensive Reconnaissance Summary")
    lines.append(
        f"The authorized reconnaissance workflow collected public evidence for `{target}`. "
        "The analysis is limited to DNS, WHOIS, service discovery, web headers, and TLS evidence."
    )
    lines.append("")

    lines.append("### 2. Evidence-Based Findings")

    if dns_result:
        ips = dns_result.get("ip_addresses", [])
        lines.append(f"- DNS lookup resolved the target to: `{ips}`.")

    if open_ports:
        lines.append("- The limited Nmap scan detected the following open services:")
        for port in open_ports:
            lines.append(
                f"  - `{port.get('port')}` / `{port.get('service')}` "
                f"({port.get('state')})"
            )
    else:
        lines.append("- No open ports were detected in the limited Nmap scan.")

    if headers_result:
        lines.append("- Web header collection was performed because a web service was detected.")

    if tls_result:
        if tls_result.get("success"):
            cert = tls_result.get("certificate", {})
            lines.append(
                f"- TLS certificate information was collected. Certificate expiry: "
                f"`{cert.get('not_after', 'N/A')}`."
            )
        else:
            lines.append("- TLS check was attempted but did not complete successfully.")

    lines.append("")
    lines.append("### 3. Possible Security Implications")

    if open_ports:
        lines.append(
            "- Exposed services increase attack surface and would normally be reviewed "
            "for version age, access control, patching, and logging."
        )
    else:
        lines.append(
            "- Based on the limited scan, there is not enough evidence to identify exposed network services."
        )

    for port in open_ports:
        service = port.get("service", "")
        port_value = port.get("port", "")

        if service == "ssh" or port_value == "22/tcp":
            lines.append(
                "- SSH exposure can be relevant to attackers during reconnaissance, "
                "but this evidence alone does not prove weak authentication or exploitability."
            )

        if service in ["http", "https"] or port_value in ["80/tcp", "443/tcp"]:
            lines.append(
                "- Web exposure can reveal server headers, application behavior, "
                "and TLS posture, but no exploitation was performed."
            )

    lines.append("")
    lines.append("### 4. Defensive Recommendations")
    lines.append("- Keep exposed services patched and remove unnecessary public services.")
    lines.append("- Restrict administrative services where possible.")
    lines.append("- Monitor logs for unusual connection attempts.")
    lines.append("- Review web security headers and TLS certificate validity.")
    lines.append("- Treat AI-generated interpretation as advisory and verify manually.")

    lines.append("")
    lines.append("### 5. Limitations")
    lines.append("- The scan was intentionally limited for ethical and coursework reasons.")
    lines.append("- No exploitation, brute force, credential testing, or vulnerability validation was performed.")
    lines.append("- Findings are reconnaissance indicators, not proof of compromise or exploitability.")

    return "\n".join(lines)