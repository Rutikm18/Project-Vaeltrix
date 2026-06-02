"""ADVERSA CLI Agent — entry point."""
from __future__ import annotations

import logging
import sys

import click

from .config import Config

logger = logging.getLogger(__name__)


class AdversaAgent:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._log = logging.getLogger(self.__class__.__name__)

    def start(self) -> None:
        from .tool_adapter import ToolAdapter
        from .poll_loop import AgentPoller
        from .result_buffer import ResultBuffer
        from .scope_verifier import ScopeVerifier
        from .scan_executor import ScanExecutor

        self._log.info("Starting ADVERSA agent → %s", self.config.manager_url)

        adapter  = ToolAdapter()
        tools    = adapter.check_all()
        self._log.info("Tool availability: %s", tools)

        poller   = AgentPoller(self.config, adapter)
        verifier = ScopeVerifier(self.config.agent_token)

        agent_id = poller.register()
        self._log.info("Registered as %s", agent_id)

        def handle_job(job: dict) -> None:
            scan_id = job.get("payload", {}).get("scanId", job.get("id", "unknown"))
            buffer  = ResultBuffer(scan_id, self.config.manager_url, agent_id)
            executor = ScanExecutor(adapter, buffer, verifier, poller)
            executor.execute(job)

        poller.run_forever(handle_job)


@click.command()
@click.option("--manager", envvar="ADVERSA_MANAGER_URL", default=None, help="Manager server URL")
@click.option("--token",   envvar="ADVERSA_AGENT_TOKEN",  default=None, help="Agent bearer token")
@click.option("--log-level", envvar="ADVERSA_LOG_LEVEL", default=None, help="Log level (INFO/DEBUG/…)")
def cli(manager: str | None, token: str | None, log_level: str | None) -> None:
    """ADVERSA network VAPT agent — polls manager for scan jobs and executes them."""
    try:
        config = Config.load(
            manager_url=manager,
            agent_token=token,
            log_level=log_level,
        )
    except ValueError as exc:
        click.echo(f"[ERR] {exc}", err=True)
        sys.exit(1)

    config.configure_logging()

    agent = AdversaAgent(config)
    try:
        agent.start()
    except KeyboardInterrupt:
        click.echo("\nAgent stopped.")


if __name__ == "__main__":
    cli()
