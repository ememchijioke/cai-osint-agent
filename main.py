"""
main.py

Temporary test runner for Phase 2.
This only tests target validation, safety guard, and memory.
"""

import argparse
import yaml

from agent.memory import AgentMemory
from agent.safety_guard import check_target_safety, safety_check


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


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
    memory.add_trace(
        step=1,
        observation="Target submitted by user.",
        decision="Validate target against allowlist and safety policy.",
        tool="target_validator",
    )

    tool_check = safety_check(
        tool_name="dns_lookup",
        action_text="Perform basic DNS lookup on authorized target.",
    )

    print("\n[Tool Safety Check]")
    print(f"Allowed: {tool_check['allowed']}")
    print(f"Reason: {tool_check['reason']}")

    memory.add_trace(
        step=2,
        observation="Target passed validation.",
        decision="Check whether DNS lookup tool is allowed.",
        tool="dns_lookup",
    )

    memory.save_raw_results(config["outputs"]["raw_results"])
    memory.save_agent_trace(config["outputs"]["agent_trace"])

    print("\nSaved:")
    print(f"- {config['outputs']['raw_results']}")
    print(f"- {config['outputs']['agent_trace']}")


if __name__ == "__main__":
    main()