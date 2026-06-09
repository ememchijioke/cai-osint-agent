"""
recon_agent.py

Main rule-based reconnaissance agent.

This file controls the agent workflow:
- validate target
- ask planner for next action
- run allowed tools
- save observations
- keep decision trace

The CAI framework will later be connected around this workflow.
"""

from agent.memory import AgentMemory
from agent.planner import ReconPlanner
from agent.safety_guard import check_target_safety, safety_check

from tools.dns_lookup import run_dns_lookup
from tools.whois_lookup import run_whois_lookup
from tools.nmap_scanner import run_nmap_scan
from tools.web_headers import run_web_headers
from tools.tls_checker import run_tls_check


class ReconAgent:
    """
    Student-level reconnaissance agent.
    """

    def __init__(self, target: str, config: dict):
        self.target = target
        self.config = config

        agent_config = config.get("agent", {})
        self.max_steps = agent_config.get("max_steps", 6)

        self.planner = ReconPlanner(max_steps=self.max_steps)
        self.memory = None
        self.cleaned_target = None

    def run(self) -> AgentMemory | None:
        """
        Run the full reconnaissance workflow.
        """
        target_check = check_target_safety(self.target, self.config)

        print("\n[Target Safety Check]")
        print(f"Safe: {target_check['safe']}")
        print(f"Reason: {target_check['reason']}")

        if not target_check["safe"]:
            print("\nTarget blocked. Exiting safely.")
            return None

        self.cleaned_target = target_check["validation"]["cleaned_target"]
        self.memory = AgentMemory(self.cleaned_target)

        self.memory.add_observation("target_validation", target_check["validation"])
        self.memory.add_trace(
            step=1,
            observation="Target submitted by user.",
            decision="Validate target against allowlist and safety policy.",
            tool="target_validator",
        )

        current_step = 2

        while current_step <= self.max_steps:
            plan = self.planner.decide_next_action(self.memory)

            if plan["done"]:
                self.memory.add_trace(
                    step=current_step,
                    observation="Planner reviewed all collected observations.",
                    decision=plan["decision"],
                    tool="stop",
                )
                break

            tool_name = plan["tool"]
            action_text = plan["action_text"]

            check = safety_check(tool_name=tool_name, action_text=action_text)

            print(f"\n[Agent Step {current_step}]")
            print(f"Selected tool: {tool_name}")
            print(f"Decision: {plan['decision']}")
            print(f"Safety allowed: {check['allowed']}")
            print(f"Safety reason: {check['reason']}")

            if not check["allowed"]:
                self.memory.add_trace(
                    step=current_step,
                    observation="Planner selected an action, but safety policy blocked it.",
                    decision=check["reason"],
                    tool=tool_name,
                )
                break

            tool_result = self.execute_tool(tool_name)
            self.memory.add_observation(tool_name, tool_result)

            self.memory.add_trace(
                step=current_step,
                observation=f"Tool '{tool_name}' was selected based on missing or relevant evidence.",
                decision=plan["decision"],
                tool=tool_name,
            )

            self.print_short_result(tool_name, tool_result)

            current_step += 1

        self.save_outputs()
        return self.memory

    def execute_tool(self, tool_name: str) -> dict:
        """
        Execute one approved tool.
        """
        scan_policy = self.config.get("scan_policy", {})
        timeout = scan_policy.get("timeout_seconds", 30)
        nmap_arguments = scan_policy.get("nmap_arguments", "-sV -T2 --top-ports 20")

        if tool_name == "dns_lookup":
            return run_dns_lookup(self.cleaned_target)

        if tool_name == "whois_lookup":
            return run_whois_lookup(self.cleaned_target)

        if tool_name == "nmap_scan":
            return run_nmap_scan(self.cleaned_target, nmap_arguments, timeout)

        if tool_name == "web_headers":
            return run_web_headers(self.cleaned_target)

        if tool_name == "tls_check":
            return run_tls_check(self.cleaned_target)

        return {
            "success": False,
            "error": f"Unknown tool requested: {tool_name}",
        }

    def print_short_result(self, tool_name: str, result: dict):
        """
        Print a simple readable summary after each tool.
        """
        print(f"\n[{tool_name} Result]")

        if tool_name == "dns_lookup":
            print(f"Success: {result.get('success')}")
            print(f"IP addresses: {result.get('ip_addresses')}")

        elif tool_name == "whois_lookup":
            print("WHOIS lookup completed." if result.get("success") else result.get("error"))

        elif tool_name == "nmap_scan":
            print(f"Open ports: {result.get('open_ports')}")

        elif tool_name == "web_headers":
            print("Header check completed." if result.get("success") else result.get("error"))

        elif tool_name == "tls_check":
            print("TLS check completed." if result.get("success") else result.get("error"))

        else:
            print(result)

    def save_outputs(self):
        """
        Save raw results and agent trace.
        """
        outputs = self.config.get("outputs", {})

        raw_results_path = outputs.get("raw_results", "outputs/raw_results.json")
        agent_trace_path = outputs.get("agent_trace", "outputs/cai_agent_trace.json")

        self.memory.save_raw_results(raw_results_path)
        self.memory.save_agent_trace(agent_trace_path)

        print("\nSaved:")
        print(f"- {raw_results_path}")
        print(f"- {agent_trace_path}")