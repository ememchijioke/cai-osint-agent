"""
memory.py

Simple memory store for the CAI OSINT Recon Agent.

The memory keeps:
- target information
- raw tool results
- agent decision trace
- final summary data

This makes the project easier to explain during presentation.
"""

import json
from datetime import datetime
from pathlib import Path


class AgentMemory:
    """
    Simple in-memory storage with JSON export.
    """

    def __init__(self, target: str):
        self.data = {
            "target": target,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "observations": {},
            "agent_trace": [],
            "final_summary": {},
        }

    def add_observation(self, key: str, value):
        """
        Store result from a tool.
        """
        self.data["observations"][key] = value

    def get_observation(self, key: str, default=None):
        """
        Retrieve a stored observation.
        """
        return self.data["observations"].get(key, default)

    def has_observation(self, key: str) -> bool:
        """
        Check whether an observation already exists.
        """
        return key in self.data["observations"]

    def add_trace(self, step: int, observation: str, decision: str, tool: str):
        """
        Add one agent decision step to the trace.
        """
        self.data["agent_trace"].append(
            {
                "step": step,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "observation": observation,
                "decision": decision,
                "tool": tool,
            }
        )

    def set_final_summary(self, summary: dict):
        """
        Store final summary.
        """
        self.data["final_summary"] = summary

    def to_dict(self) -> dict:
        """
        Return the full memory as a dictionary.
        """
        return self.data

    def save_raw_results(self, path: str):
        """
        Save all memory data to JSON.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(self.data, file, indent=4)

    def save_agent_trace(self, path: str):
        """
        Save only the agent trace to JSON.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(self.data["agent_trace"], file, indent=4)