"""Stock Agent workload entry point."""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
from agent_runtime import run_agent

def stock_workload():
    """Replace with the real stock data and analysis workflow."""
    return os.getenv("STOCK_AGENT_TASK", "stock analysis cycle")

if __name__ == "__main__":
    run_agent(stock_workload, env_file=".env.stock-agent", interval_seconds=60)
