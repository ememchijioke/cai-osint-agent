"""
dns_lookup.py

Performs simple DNS resolution for an authorized target.
"""

import socket


def run_dns_lookup(target: str) -> dict:
    """
    Resolve a hostname to IP information.

    Args:
        target: domain or hostname

    Returns:
        dictionary containing DNS lookup result
    """
    result = {
        "target": target,
        "success": False,
        "ip_addresses": [],
        "error": None,
    }

    try:
        hostname, aliases, ip_addresses = socket.gethostbyname_ex(target)

        result["success"] = True
        result["hostname"] = hostname
        result["aliases"] = aliases
        result["ip_addresses"] = ip_addresses

    except Exception as error:
        result["error"] = str(error)

    return result