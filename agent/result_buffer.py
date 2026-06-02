"""Local-first findings buffer with network shipping."""
from __future__ import annotations

import json
import logging
import platform
from pathlib import Path
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ResultBuffer:
    def __init__(self, scan_id: str, manager_url: str, token: str) -> None:
        self.scan_id     = scan_id
        self.manager_url = manager_url.rstrip("/")
        self.token       = token

        if platform.system().lower() == "windows":
            import tempfile
            base = Path(tempfile.gettempdir()) / "adversa"
        else:
            base = Path("/tmp/adversa")

        base.mkdir(parents=True, exist_ok=True)
        self._file = base / f"{scan_id}.jsonl"

    def write(self, finding: dict) -> None:
        with self._file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding) + "\n")
        try:
            self._try_ship(finding)
        except Exception:
            pass

    def write_batch(self, findings: list[dict]) -> None:
        with self._file.open("a", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
        self._ship_batch(findings)

    def _try_ship(self, finding: dict) -> bool:
        return self._ship_batch([finding])

    def _ship_batch(self, findings: list[dict]) -> bool:
        try:
            resp = requests.post(
                f"{self.manager_url}/api/findings/ingest",
                json={"scanId": self.scan_id, "findings": findings},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=5,
            )
            return resp.status_code == 200
        except Exception as exc:
            logger.debug("Ship failed (%s): %s", type(exc).__name__, exc)
            return False

    def flush_pending(self) -> int:
        if not self._file.exists():
            return 0

        lines = self._file.read_text(encoding="utf-8").splitlines()
        flushed = 0
        failed: list[str] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                if self._try_ship(finding):
                    flushed += 1
                else:
                    failed.append(line)
            except json.JSONDecodeError:
                failed.append(line)

        if failed:
            self._file.write_text("\n".join(failed) + "\n", encoding="utf-8")
        else:
            self._file.unlink(missing_ok=True)

        return flushed

    def cleanup(self) -> None:
        self._file.unlink(missing_ok=True)
