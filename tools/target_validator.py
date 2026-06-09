"""
target_validator.py

Basic target validation for the CAI OSINT Recon Agent.

This module checks whether a target is allowed before any reconnaissance
action is performed. It is intentionally simple and student-friendly.
"""

import socket
import ipaddress
from urllib.parse import urlparse


def clean_target(target: str) -> str:
    """
    Clean user input and return only the hostname or IP address.

    Examples:
        https://scanme.nmap.org -> scanme.nmap.org
        scanme.nmap.org         -> scanme.nmap.org
    """
    target = target.strip()

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname

    return target.replace("/", "")


def is_private_ip(target: str) -> bool:
    """
    Check whether the target resolves to a private/local IP address.
    """
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(target)
        ip = ipaddress.ip_address(resolved_ip)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False


def resolve_target(target: str) -> str | None:
    """
    Resolve a hostname to an IP address.
    Returns None if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def is_allowed_target(target: str, config: dict) -> tuple[bool, str]:
    """
    Check if the target is allowed based on config.yaml.

    Returns:
        (True, reason) or (False, reason)
    """
    cleaned = clean_target(target)

    allowed_targets = config.get("target_policy", {}).get("allowed_targets", [])
    scan_policy = config.get("scan_policy", {})

    allow_private = scan_policy.get("allow_private_targets", False)
    allow_public_only_if_listed = scan_policy.get(
        "allow_public_targets_only_if_listed", True
    )

    if cleaned in allowed_targets:
        return True, f"Target '{cleaned}' is explicitly allowed."

    if is_private_ip(cleaned) and allow_private:
        return True, f"Private/local target '{cleaned}' is allowed in lab mode."

    if allow_public_only_if_listed:
        return False, (
            f"Target '{cleaned}' is not in the allowed target list. "
            "Public targets must be explicitly allowed."
        )

    return True, f"Target '{cleaned}' is allowed by current policy."


def validate_target(target: str, config: dict) -> dict:
    """
    Full target validation result used by the agent.
    """
    cleaned = clean_target(target)
    resolved_ip = resolve_target(cleaned)
    allowed, reason = is_allowed_target(cleaned, config)

    return {
        "original_target": target,
        "cleaned_target": cleaned,
        "resolved_ip": resolved_ip,
        "allowed": allowed,
        "reason": reason,
    }