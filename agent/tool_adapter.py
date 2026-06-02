"""Cross-platform tool execution adapter."""
from __future__ import annotations

import platform
import shutil
import subprocess
import threading
from typing import Callable


class ToolNotAvailableError(Exception):
    pass


class ToolAdapter:
    TOOLS: dict[str, dict[str, str]] = {
        "nmap":    {"windows": "nmap.exe",    "linux": "nmap",    "darwin": "nmap"},
        "naabu":   {"windows": "naabu.exe",   "linux": "naabu",   "darwin": "naabu"},
        "nuclei":  {"windows": "nuclei.exe",  "linux": "nuclei",  "darwin": "nuclei"},
        "testssl": {"windows": "testssl.sh",  "linux": "testssl.sh", "darwin": "testssl.sh"},
    }

    def get_platform_key(self) -> str:
        sys = platform.system().lower()
        if sys == "windows":
            return "windows"
        if sys == "darwin":
            return "darwin"
        return "linux"

    def _bin(self, tool: str) -> str:
        platform_key = self.get_platform_key()
        names = self.TOOLS.get(tool, {})
        return names.get(platform_key, tool)

    def is_available(self, tool: str) -> bool:
        return shutil.which(self._bin(tool)) is not None

    def check_all(self) -> dict[str, bool]:
        return {tool: self.is_available(tool) for tool in self.TOOLS}

    def run(
        self,
        tool: str,
        args: list[str],
        on_line: Callable[[str], None],
        timeout: int = 300,
    ) -> int:
        binary = self._bin(tool)
        if not shutil.which(binary):
            raise ToolNotAvailableError(f"{tool} ({binary}) not found in PATH")

        is_windows = self.get_platform_key() == "windows"

        kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "text":   True,
        }
        if is_windows:
            kwargs["shell"]            = True
            kwargs["creationflags"]    = 0x08000000  # CREATE_NO_WINDOW
        else:
            kwargs["shell"] = False

        cmd = [binary] + args

        proc = subprocess.Popen(cmd, **kwargs)

        # Kill after timeout in a background thread
        timer = threading.Timer(timeout, proc.kill)
        timer.start()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                if stripped:
                    on_line(stripped)
            proc.wait()
        finally:
            timer.cancel()

        return proc.returncode if proc.returncode is not None else -1
