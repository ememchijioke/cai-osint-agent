"""
safety_guard.py

Safety policy layer for the CAI OSINT Recon Agent.

This module blocks unsafe actions and keeps the project within an
authorized student-demo scope.
"""

from tools.target_validator import validate_target


FORBIDDEN_KEYWORDS = [
    "bruteforce",
    "brute-force",
    "password",
    "credential",
    "exploit",
    "payload",
    "reverse shell",
    "meterpreter",
    "dos",
    "ddos",
    "flood",
    "sqlmap",
    "hydra",
    "nikto aggressive",
]


ALLOWED_TOOLS = [
    "dns_lookup",
    "whois_lookup",
    "nmap_scan",
    "web_headers",
    "tls_check",
    "generate_report",
]


def check_target_safety(target: str, config: dict) -> dict:
    """
    Validate that a target is safe and authorized.
    """
    validation = validate_target(target, config)

    if not validation["allowed"]:
        return {
            "safe": False,
            "reason": validation["reason"],
            "validation": validation,
        }

    return {
        "safe": True,
        "reason": validation["reason"],
        "validation": validation,
    }


def check_tool_allowed(tool_name: str) -> tuple[bool, str]:
    """
    Check whether the requested tool is in the allowed tool registry.
    """
    if tool_name not in ALLOWED_TOOLS:
        return False, f"Tool '{tool_name}' is not allowed by safety policy."

    return True, f"Tool '{tool_name}' is allowed."


def check_action_text(action_text: str) -> tuple[bool, str]:
    """
    Check planned agent action for clearly unsafe keywords.
    """
    lowered = action_text.lower()

    for keyword in FORBIDDEN_KEYWORDS:
        if keyword in lowered:
            return False, f"Action blocked because it contains forbidden keyword: {keyword}"

    return True, "Action text passed safety check."


def safety_check(tool_name: str, action_text: str = "") -> dict:
    """
    Combined safety check before executing a tool.
    """
    tool_allowed, tool_reason = check_tool_allowed(tool_name)

    if not tool_allowed:
        return {
            "allowed": False,
            "reason": tool_reason,
        }

    if action_text:
        action_allowed, action_reason = check_action_text(action_text)

        if not action_allowed:
            return {
                "allowed": False,
                "reason": action_reason,
            }

    return {
        "allowed": True,
        "reason": "Tool and action passed safety checks.",
    }