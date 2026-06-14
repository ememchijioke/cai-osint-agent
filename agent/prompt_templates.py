"""
prompt_templates.py

Prompt templates for the CAI OSINT Recon Agent.

These prompts are intentionally constrained. The AI assistant is only allowed
to interpret collected evidence. It must not invent vulnerabilities or suggest
unsafe actions.
"""


SYSTEM_PROMPT = """
You are a cybersecurity AI agent supporting an authorized student project.

Your role:
- Interpret reconnaissance evidence.
- Explain findings from an offensive security perspective.
- Recommend defensive mitigations.
- Stay strictly grounded in the provided evidence.

Hard safety rules:
- Do not suggest exploitation.
- Do not suggest brute force.
- Do not suggest credential attacks.
- Do not suggest denial-of-service.
- Do not suggest stealth, evasion, persistence, or payload delivery.
- Do not invent vulnerabilities that are not supported by evidence.
- If evidence is weak or missing, say so clearly.

The project scope is authorized OSINT and basic reconnaissance only.
"""


def build_cai_mission_prompt(target: str) -> str:
    """
    Build the mission prompt for the CAI-style agent layer.
    """
    return f"""
Mission:
Perform an authorized AI-assisted reconnaissance analysis for the target: {target}

The agent should:
1. Review collected DNS, WHOIS, Nmap, HTTP header, and TLS evidence.
2. Explain what the evidence suggests from an attacker reconnaissance perspective.
3. Identify possible exposure risks without claiming exploitation.
4. Recommend defensive mitigations.
5. Clearly state limitations and uncertainty.

The agent must remain evidence-grounded and non-destructive.
"""


def build_evidence_summary_prompt(memory_data: dict) -> str:
    """
    Build an evidence-grounded prompt using collected agent memory.
    """
    target = memory_data.get("target", "Unknown target")
    observations = memory_data.get("observations", {})
    agent_trace = memory_data.get("agent_trace", [])

    return f"""
Target:
{target}

Collected Observations:
{observations}

Agent Decision Trace:
{agent_trace}

Task:
Write a concise AI-assisted analysis with the following sections:

1. Offensive Reconnaissance Summary
2. Evidence-Based Findings
3. Possible Security Implications
4. Defensive Recommendations
5. Limitations

Rules:
- Use only the evidence provided above.
- Do not invent vulnerabilities.
- Do not provide exploitation steps.
- Do not include commands for attacking systems.
- If the evidence does not support a conclusion, say that the evidence is insufficient.
"""