"""Agent registration and long-poll job loop."""
from __future__ import annotations

import logging
import platform
import socket
import time
import uuid
from typing import Callable

import requests

from .config import Config
from .tool_adapter import ToolAdapter

logger = logging.getLogger(__name__)

AGENT_VERSION = "0.1.0"


class AgentPoller:
    def __init__(self, config: Config, tool_adapter: ToolAdapter) -> None:
        self.config       = config
        self.tool_adapter = tool_adapter
        self._agent_id: str | None = None

    # ── Registration ────────────────────────────────────────────

    def register(self) -> str:
        available = self.tool_adapter.check_all()
        capabilities = [tool for tool, ok in available.items() if ok]

        payload = {
            "sessionId":         str(uuid.uuid4()),
            "hostname":          socket.gethostname(),
            "os":                platform.system(),
            "osVersion":         platform.version(),
            "arch":              platform.machine(),
            "agentVersion":      AGENT_VERSION,
            "capabilities":      capabilities,
            "networkInterfaces": self._get_interfaces(),
        }

        resp = requests.post(
            f"{self.config.manager_url}/api/agents/register",
            json=payload,
            headers={"Authorization": f"Bearer {self.config.agent_token}"},
            timeout=15,
        )

        if resp.status_code != 200:
            raise RuntimeError(
                f"Registration failed: HTTP {resp.status_code} — {resp.text[:200]}"
            )

        data = resp.json()
        self._agent_id = data["agentId"]
        return self._agent_id

    def _get_interfaces(self) -> list[dict]:
        try:
            hostname = socket.gethostname()
            ip       = socket.gethostbyname(hostname)
            # Best-effort CIDR: assume /24 for local IPs
            parts    = ip.rsplit(".", 1)
            cidr     = f"{parts[0]}.0/24" if len(parts) == 2 else f"{ip}/32"
            return [{"name": "eth0", "ip": ip, "cidr": cidr}]
        except Exception:
            return []

    # ── Long-poll ────────────────────────────────────────────────

    def poll_once(self) -> dict | None:
        if not self._agent_id:
            raise RuntimeError("Agent not registered yet")

        resp = requests.get(
            f"{self.config.manager_url}/api/agents/jobs/next",
            headers={"Authorization": f"Bearer {self._agent_id}"},
            timeout=35,  # longer than server's 28s hold
        )

        if resp.status_code == 204:
            return None
        if resp.status_code == 200:
            return resp.json()

        raise RuntimeError(f"Poll failed: HTTP {resp.status_code} — {resp.text[:200]}")

    def run_forever(self, job_handler: Callable[[dict], None]) -> None:
        logger.info("Polling for jobs…")
        while True:
            try:
                job = self.poll_once()
                if job:
                    logger.info("Received job %s (type=%s)", job.get("id"), job.get("type"))
                    job_handler(job)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.error("Poll error: %s", exc)
                time.sleep(5)

    # ── Status reporting ─────────────────────────────────────────

    def update_status(self, job_id: str, status: str, stage: str = "") -> None:
        if not self._agent_id:
            return
        try:
            requests.post(
                f"{self.config.manager_url}/api/agents/jobs/{job_id}/status",
                json={"status": status, "stage": stage},
                headers={"Authorization": f"Bearer {self._agent_id}"},
                timeout=5,
            )
        except Exception as exc:
            logger.debug("Status update failed: %s", exc)
