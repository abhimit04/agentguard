"""Minimal Stock Agent connectivity test for AgentGuard."""
import sys
import time

sys.path.insert(0, "sdk/python")

from agentguard_sdk import AgentGuard


guard = AgentGuard(
    id="5497",
    url="http://localhost:3100",
    heartbeat_seconds=30,
)

guard.start()
print("Stock Agent 5497 connected. Heartbeat interval: 30 seconds")

try:
    while True:
        # Replace this loop with the real Stock Agent workload.
        time.sleep(1)
except KeyboardInterrupt:
    guard.stop()
    print("Stock Agent stopped")
