"""
main.py

Entry point for the CAI OSINT Recon Agent.

This version uses a simple rule-based agent loop. CAI integration will
be added after this workflow is stable.
"""

import argparse
import yaml

from agent.recon_agent import ReconAgent


def load_config(path: str = "config.yaml") -> dict:
    """
    Load YAML configuration file.
    """
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def main():
    parser = argparse.ArgumentParser(description="CAI OSINT Recon Agent")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file. Default: config.yaml",
    )

    args = parser.parse_args()

    config = load_config(args.config)

    agent = ReconAgent(target=args.target, config=config)
    agent.run()


if __name__ == "__main__":
    main()