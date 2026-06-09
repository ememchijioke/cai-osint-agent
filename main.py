"""
main.py

Phase 3 runner for the CAI OSINT Recon Agent.

This version performs:
- target safety validation
- DNS lookup
- WHOIS lookup
- limited Nmap scan
- HTTP header check
- TLS check
- memory saving
- agent trace saving

CAI integration will come in the next phase.
"""

import argparse
import yaml

from agent.memory import AgentMemory
from agent.safety_guard import check_target_safety, safety_check

from tools.dns_lookup import run_dns_lookup
from tools.whois_lookup import run_whois_lookup
from tools.nmap_scanner import run_nmap_scan
from tools.web_headers import run_web_headers
from tools.tls_checker import run_tls_check


def load_config(path: str = "config.yaml") -> dict:
    """
    Load YAML configuration file.
    """
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def run_tool_safely(tool_name: str, action_text: str) -> bool:
    """
    Check whether a tool can safely run.
    """
    check = safety_check(tool_name=tool_name, action_text=action_text)

    print(f"\n[Safety Check: {tool_name}]")
    print(f"Allowed: {check['allowed']}")
    print(f"Reason: {check['reason']}")

    return check["allowed"]


def main():
    parser = argparse.ArgumentParser(description="CAI OSINT Recon Agent")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    config = load_config()

    target_check = check_target_safety(args.target, config)

    print("\n[Target Safety Check]")
    print(f"Safe: {target_check['safe']}")
    print(f"Reason: {target_check['reason']}")

    if not target_check["safe"]:
        print("\nTarget blocked. Exiting safely.")
        return

    cleaned_target = target_check["validation"]["cleaned_target"]

    memory = AgentMemory(cleaned_target)
    memory.add_observation("target_validation", target_check["validation"])

    step = 1
    memory.add_trace(
        step=step,
        observation="Target submitted by user.",
        decision="Validate target against allowlist and safety policy.",
        tool="target_validator",
    )

    # DNS Lookup
    step += 1
    if run_tool_safely("dns_lookup", "Perform basic DNS lookup on authorized target."):
        dns_result = run_dns_lookup(cleaned_target)
        memory.add_observation("dns_lookup", dns_result)
        memory.add_trace(
            step=step,
            observation="Target passed validation and DNS information was missing.",
            decision="Run DNS lookup to resolve target IP address.",
            tool="dns_lookup",
        )
        print("\n[DNS Result]")
        print(dns_result)

    # WHOIS Lookup
    step += 1
    if run_tool_safely("whois_lookup", "Perform basic WHOIS lookup on authorized target."):
        whois_result = run_whois_lookup(cleaned_target)
        memory.add_observation("whois_lookup", whois_result)
        memory.add_trace(
            step=step,
            observation="Domain ownership and registration information was missing.",
            decision="Run WHOIS lookup.",
            tool="whois_lookup",
        )
        print("\n[WHOIS Result]")
        print("WHOIS lookup completed." if whois_result["success"] else whois_result["error"])

    # Nmap Scan
    step += 1
    scan_policy = config.get("scan_policy", {})
    nmap_arguments = scan_policy.get("nmap_arguments", "-sV -T2 --top-ports 20")
    timeout = scan_policy.get("timeout_seconds", 30)

    if run_tool_safely("nmap_scan", "Perform limited Nmap service scan on authorized target."):
        nmap_result = run_nmap_scan(cleaned_target, nmap_arguments, timeout)
        memory.add_observation("nmap_scan", nmap_result)
        memory.add_trace(
            step=step,
            observation="Open ports and services were unknown.",
            decision="Run limited Nmap scan using safe configured arguments.",
            tool="nmap_scan",
        )
        print("\n[Nmap Open Ports]")
        print(nmap_result["open_ports"])

    # Web Headers
    step += 1
    should_check_web = False
    nmap_result = memory.get_observation("nmap_scan", {})

    for port_info in nmap_result.get("open_ports", []):
        if port_info.get("service") in ["http", "https"]:
            should_check_web = True

    if should_check_web:
        if run_tool_safely("web_headers", "Collect HTTP security headers from authorized target."):
            headers_result = run_web_headers(cleaned_target)
            memory.add_observation("web_headers", headers_result)
            memory.add_trace(
                step=step,
                observation="HTTP or HTTPS service was detected.",
                decision="Collect basic web response headers.",
                tool="web_headers",
            )
            print("\n[Web Headers]")
            print("Header check completed." if headers_result["success"] else headers_result["error"])
    else:
        memory.add_trace(
            step=step,
            observation="No HTTP or HTTPS service detected in limited scan.",
            decision="Skip web header collection.",
            tool="web_headers",
        )

    # TLS Check
    step += 1
    should_check_tls = False

    for port_info in nmap_result.get("open_ports", []):
        if port_info.get("port") == "443/tcp" or port_info.get("service") == "https":
            should_check_tls = True

    if should_check_tls:
        if run_tool_safely("tls_check", "Inspect TLS certificate on authorized HTTPS service."):
            tls_result = run_tls_check(cleaned_target)
            memory.add_observation("tls_check", tls_result)
            memory.add_trace(
                step=step,
                observation="HTTPS service was detected.",
                decision="Check TLS certificate information.",
                tool="tls_check",
            )
            print("\n[TLS Check]")
            print(tls_result)
    else:
        memory.add_trace(
            step=step,
            observation="No HTTPS service detected in limited scan.",
            decision="Skip TLS certificate check.",
            tool="tls_check",
        )

    # Save outputs
    memory.save_raw_results(config["outputs"]["raw_results"])
    memory.save_agent_trace(config["outputs"]["agent_trace"])

    print("\nSaved:")
    print(f"- {config['outputs']['raw_results']}")
    print(f"- {config['outputs']['agent_trace']}")


if __name__ == "__main__":
    main()