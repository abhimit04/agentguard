"""IPO Agent workload entry point."""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
from agent_runtime import run_agent

def ipo_workload():
    """Replace with the real IPO data and analysis workflow."""
    return os.getenv("IPO_AGENT_TASK", "IPO analysis cycle")

if __name__ == "__main__":
    run_agent(ipo_workload, env_file=".env.ipo-agent", interval_seconds=60)
