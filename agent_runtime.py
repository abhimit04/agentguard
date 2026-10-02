"""Reusable AgentGuard runtime wrapper for small Python agents.

Each agent supplies only a workload function. Configuration and lifecycle
events remain identical across Stock, IPO, Cricket, and other agents.
"""
import os
import time
from pathlib import Path
from agentguard_sdk import AgentGuard


def load_agent_env(filename=".env.agent"):
    file = Path(__file__).with_name(filename)
    if not file.exists():
        return
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'") )


def run_agent(workload, *, env_file=".env.agent", interval_seconds=60):
    load_agent_env(env_file)
    required = ("AGENTGUARD_URL", "AGENTGUARD_AGENT_ID", "AGENTGUARD_API_KEY")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError(f"Missing AgentGuard configuration: {', '.join(missing)}")
    guard = AgentGuard.from_environment(heartbeat_seconds=30).start()
    name = guard.agent.get("name", f"Agent {guard.agent['id']}")
    interval = max(1, int(os.getenv("AGENTGUARD_WORK_INTERVAL_SECONDS", interval_seconds)))
    try:
        while True:
            action_ref = f"{guard.agent['id']}-{int(time.time())}"
            guard.report("running", f"{name} started a work cycle", action_ref)
            try:
                result = workload()
                guard.report("completed", f"{name} completed a work cycle: {result}", action_ref)
            except Exception as error:
                guard.report("failed", f"{name} failed: {error}", action_ref)
            time.sleep(interval)
    except KeyboardInterrupt:
        guard.stop()
        guard.report("stopped", f"{name} stopped")
