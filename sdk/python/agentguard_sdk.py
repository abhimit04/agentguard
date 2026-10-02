"""Small AgentGuard SDK for Python agents. Requires httpx."""
import os
import threading
import time
import httpx

class AgentGuard:
    @classmethod
    def from_environment(cls, **options):
        tools = [tool.strip() for tool in os.getenv("AGENTGUARD_AGENT_TOOLS", "").split(",") if tool.strip()]
        return cls(
            id=os.environ["AGENTGUARD_AGENT_ID"],
            name=os.getenv("AGENTGUARD_AGENT_NAME"),
            team=os.getenv("AGENTGUARD_AGENT_TEAM"),
            tools=tools,
            **options,
        )

    def __init__(self, *, id, name=None, team=None, tools=None, url=None, heartbeat_seconds=30):
        if not id:
            raise ValueError("AgentGuard requires an agent id")
        self.agent = {"id": id, **({"name": name, "team": team, "tools": tools or []} if name or team or tools else {})}
        self.url = (url or os.getenv("AGENTGUARD_URL", "http://localhost:3100")).rstrip("/")
        self.heartbeat_seconds = heartbeat_seconds
        self.api_key = os.getenv("AGENTGUARD_API_KEY", "")
        self.company_id = os.getenv("AGENTGUARD_COMPANY_ID", "default")
        # Local Caddy staging uses a self-signed certificate. Verification can
        # be disabled explicitly for that local-only case; production should
        # leave this enabled (the default).
        self.tls_verify = os.getenv("AGENTGUARD_TLS_VERIFY", "true").lower() not in {"0", "false", "no", "off"}
        self._stop = threading.Event()
        self._thread = None

    def _request(self, path, method="GET", payload=None, company_id=None):
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        if company_id:
            headers["X-AgentGuard-Company"] = company_id
            headers["X-AgentGuard-Agent"] = self.agent["id"]
        response = httpx.request(method, f"{self.url}{path}", json=payload, headers=headers, timeout=5, follow_redirects=True, verify=self.tls_verify)
        response.raise_for_status()
        return response.json()

    def report(self, event, message, action_ref=None):
        payload = {"agentId": self.agent["id"], "event": event, "message": message, "actionRef": action_ref}
        if "name" in self.agent and "team" in self.agent: payload["agent"] = self.agent
        # Agent credentials authenticate through the gateway endpoint. The
        # integration endpoint is reserved for platform-level API keys.
        return self._request(f"/api/gateway/agents/{self.agent['id']}/events", "POST", payload, company_id=self.company_id)

    def _heartbeat_loop(self):
        while not self._stop.is_set():
            try: self.report("heartbeat", f"{self.agent.get('name', f'Agent {self.agent["id"]}')} is online")
            except httpx.HTTPError: pass
            self._stop.wait(self.heartbeat_seconds)

    def start(self):
        label = self.agent.get("name", f"Agent {self.agent['id']}")
        self.report("started", f"{label} connected")
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def check(self, action_type, action, action_ref, resource="*"):
        return self._request("/api/guard/check", "POST", {"agentId": self.agent["id"], "agent": self.agent, "actionType": action_type, "action": action, "actionRef": action_ref, "resource": resource})

    def wait_for_approval(self, approval_id, interval_seconds=2.5):
        while True:
            result = self._request(f"/api/approvals/{approval_id}")
            if result["status"] != "pending": return result["status"]
            time.sleep(interval_seconds)

    def claim(self, action_type, action, action_ref, resource="*"):
        return self._request("/api/guard/executions/claim", "POST", {"agentId": self.agent["id"], "actionType": action_type, "action": action, "actionRef": action_ref, "resource": resource})

    def complete(self, execution_id, success=True, result=None, error=None):
        return self._request("/api/guard/executions/complete", "POST", {"agentId": self.agent["id"], "executionId": execution_id, "success": success, "result": result, "error": error})

    def authorize(self, action_type, action, action_ref, resource="*", interval_seconds=2.5):
        checked = self.check(action_type, action, action_ref, resource)
        if checked["decision"] == "block": return checked
        if checked["decision"] == "awaiting_approval":
            status = self.wait_for_approval(checked["approvalId"], interval_seconds)
            if status != "approved": return {"decision": "block", "approvalId": checked["approvalId"], "reason": f"Approval {status}"}
        elif checked["decision"] == "allow": return checked
        return self.claim(action_type, action, action_ref, resource)
