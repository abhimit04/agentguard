"""Cricket Agent workload entry point."""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
from agent_runtime import run_agent

def cricket_workload():
    """Replace with the real cricket data and analysis workflow."""
    return os.getenv("CRICKET_AGENT_TASK", "cricket analysis cycle")

if __name__ == "__main__":
    run_agent(cricket_workload, env_file=".env.cricket-agent", interval_seconds=60)
