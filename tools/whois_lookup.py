"""
whois_lookup.py

Runs a basic WHOIS lookup using the local whois command.

This is intentionally simple for a student project.
"""

import subprocess


def run_whois_lookup(target: str, timeout: int = 15) -> dict:
    """
    Run whois lookup for a target domain.

    Args:
        target: domain name
        timeout: command timeout in seconds

    Returns:
        dictionary containing WHOIS result
    """
    result = {
        "target": target,
        "success": False,
        "output": "",
        "error": None,
    }

    try:
        completed = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result["success"] = completed.returncode == 0
        result["output"] = completed.stdout.strip()

        if completed.stderr:
            result["error"] = completed.stderr.strip()

    except FileNotFoundError:
        result["error"] = "whois command not found. Install it with: sudo apt install whois"

    except subprocess.TimeoutExpired:
        result["error"] = "WHOIS lookup timed out."

    except Exception as error:
        result["error"] = str(error)

    return result