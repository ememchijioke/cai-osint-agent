"""
planner.py

Simple rule-based planner for the CAI OSINT Recon Agent.

This planner decides the next reconnaissance action based on what the
agent already knows. It is intentionally simple, readable, and suitable
for a student project.
"""


class ReconPlanner:
    """
    Rule-based reconnaissance planner.

    The planner checks the agent memory and decides which tool should run next.
    """

    def __init__(self, max_steps: int = 6):
        self.max_steps = max_steps

    def decide_next_action(self, memory) -> dict:
        """
        Decide the next action based on existing observations.

        Returns:
            A dictionary with:
            - done: bool
            - tool: tool name or None
            - decision: explanation of decision
            - action_text: safety-checkable action description
        """

        if not memory.has_observation("dns_lookup"):
            return {
                "done": False,
                "tool": "dns_lookup",
                "decision": "DNS information is missing, so the agent should resolve the target.",
                "action_text": "Perform basic DNS lookup on authorized target.",
            }

        if not memory.has_observation("whois_lookup"):
            return {
                "done": False,
                "tool": "whois_lookup",
                "decision": "WHOIS information is missing, so the agent should collect public registration data.",
                "action_text": "Perform basic WHOIS lookup on authorized target.",
            }

        if not memory.has_observation("nmap_scan"):
            return {
                "done": False,
                "tool": "nmap_scan",
                "decision": "Open ports and service information are missing, so the agent should run a limited Nmap scan.",
                "action_text": "Perform limited Nmap service scan on authorized target.",
            }

        if self._http_service_detected(memory) and not memory.has_observation("web_headers"):
            return {
                "done": False,
                "tool": "web_headers",
                "decision": "HTTP or HTTPS service was detected, so the agent should inspect web response headers.",
                "action_text": "Collect HTTP security headers from authorized target.",
            }

        if self._https_service_detected(memory) and not memory.has_observation("tls_check"):
            return {
                "done": False,
                "tool": "tls_check",
                "decision": "HTTPS service was detected, so the agent should inspect the TLS certificate.",
                "action_text": "Inspect TLS certificate on authorized HTTPS service.",
            }

        return {
            "done": True,
            "tool": None,
            "decision": "The agent has collected enough basic reconnaissance evidence.",
            "action_text": "Stop reconnaissance and generate report.",
        }

    def _http_service_detected(self, memory) -> bool:
        """
        Check if HTTP or HTTPS was found in Nmap results.
        """
        nmap_result = memory.get_observation("nmap_scan", {})

        for port_info in nmap_result.get("open_ports", []):
            service = port_info.get("service", "")
            port = port_info.get("port", "")

            if service in ["http", "https"] or port in ["80/tcp", "443/tcp"]:
                return True

        return False

    def _https_service_detected(self, memory) -> bool:
        """
        Check if HTTPS was found in Nmap results.
        """
        nmap_result = memory.get_observation("nmap_scan", {})

        for port_info in nmap_result.get("open_ports", []):
            service = port_info.get("service", "")
            port = port_info.get("port", "")

            if service == "https" or port == "443/tcp":
                return True

        return False