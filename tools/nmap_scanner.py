"""
nmap_scanner.py

Runs a limited Nmap scan against an authorized target.

The scan arguments come from config.yaml so the scan stays controlled.
"""

import subprocess


def run_nmap_scan(target: str, nmap_arguments: str, timeout: int = 30) -> dict:
    """
    Run a controlled Nmap scan.

    Args:
        target: authorized target
        nmap_arguments: scan options from config.yaml
        timeout: command timeout in seconds

    Returns:
        dictionary containing Nmap result
    """
    result = {
        "target": target,
        "success": False,
        "command": f"nmap {nmap_arguments} {target}",
        "output": "",
        "error": None,
        "open_ports": [],
    }

    try:
        command = ["nmap"] + nmap_arguments.split() + [target]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result["success"] = completed.returncode == 0
        result["output"] = completed.stdout.strip()

        if completed.stderr:
            result["error"] = completed.stderr.strip()

        result["open_ports"] = extract_open_ports(completed.stdout)

    except FileNotFoundError:
        result["error"] = "nmap command not found. Install it with: sudo apt install nmap"

    except subprocess.TimeoutExpired:
        result["error"] = "Nmap scan timed out."

    except Exception as error:
        result["error"] = str(error)

    return result


def extract_open_ports(nmap_output: str) -> list:
    """
    Extract open ports from normal Nmap text output.

    This is a simple parser for student-level readability.
    """
    open_ports = []

    for line in nmap_output.splitlines():
        line = line.strip()

        if "/tcp" in line and "open" in line:
            parts = line.split()

            if len(parts) >= 3:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2]

                open_ports.append(
                    {
                        "port": port_proto,
                        "state": state,
                        "service": service,
                        "raw_line": line,
                    }
                )

    return open_ports