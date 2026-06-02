from __future__ import annotations

import logging
import os
from dataclasses import dataclass


@dataclass
class Config:
    manager_url: str
    agent_token: str
    log_level: str

    @classmethod
    def load(
        cls,
        *,
        manager_url: str | None = None,
        agent_token: str | None = None,
        log_level: str | None = None,
    ) -> "Config":
        url   = manager_url  or os.environ.get("ADVERSA_MANAGER_URL", "")
        token = agent_token  or os.environ.get("ADVERSA_AGENT_TOKEN", "")
        level = log_level    or os.environ.get("ADVERSA_LOG_LEVEL", "INFO")

        missing = []
        if not url:
            missing.append("ADVERSA_MANAGER_URL")
        if not token:
            missing.append("ADVERSA_AGENT_TOKEN")
        if missing:
            raise ValueError(
                f"Missing required config: {', '.join(missing)}. "
                "Set via env vars or --manager / --token CLI flags."
            )

        return cls(
            manager_url=url.rstrip("/"),
            agent_token=token,
            log_level=level.upper(),
        )

    def configure_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.log_level, logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
