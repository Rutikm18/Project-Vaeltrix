"""Full scan execution orchestrator — ties together tool_adapter, result_buffer, scope_verifier."""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .tool_adapter import ToolAdapter
    from .result_buffer import ResultBuffer
    from .scope_verifier import ScopeVerifier
    from .poll_loop import AgentPoller

logger = logging.getLogger(__name__)

# Mirrors the TypeScript engine stealth mappings
NAABU_RATES  = [0, 50, 100, 300, 500, 1000, 2000, 3000, 5000]
NMAP_TIMING  = [0,  1,   1,   2,   2,    3,    3,    4,    4, 5]


class ScanExecutor:
    def __init__(
        self,
        tool_adapter: "ToolAdapter",
        result_buffer: "ResultBuffer",
        scope_verifier: "ScopeVerifier",
        poller: "AgentPoller",
    ) -> None:
        self.adapter  = tool_adapter
        self.buffer   = result_buffer
        self.verifier = scope_verifier
        self.poller   = poller

    # ── Entry point ──────────────────────────────────────────────

    def execute(self, job: dict) -> None:
        job_id      = job.get("id", "unknown")
        payload     = job.get("payload", {})
        scope_token = job.get("scopeToken", "")
        targets: list[str] = payload.get("targets", [])
        stealth: int       = int(payload.get("stealth", 5))
        profile: str       = payload.get("profile", "standard")

        # 1. Verify scope for every target
        for target in targets:
            if not self.verifier.verify(scope_token, target):
                logger.error("Scope violation: %s not authorised — aborting job %s", target, job_id)
                self.poller.update_status(job_id, "FAILED", "scope_violation")
                return

        # 2. Port scan (naabu)
        self.poller.update_status(job_id, "RUNNING", "port_scan")
        open_ports = self._run_naabu(targets, stealth)
        logger.info("naabu found %d open ports across %d hosts", len(open_ports), len({r["ip"] for r in open_ports}))

        # 3. Service probe (nmap)
        self.poller.update_status(job_id, "RUNNING", "service_probe")
        hosts_by_ip = self._run_nmap(open_ports, stealth)

        # 4. CVE scan (nuclei) + TLS check (testssl) in parallel
        self.poller.update_status(job_id, "RUNNING", "cve_scan")
        nuclei_results: list[dict] = []
        testssl_results: list[dict] = []

        t_nuclei  = threading.Thread(target=lambda: nuclei_results.extend(self._run_nuclei(hosts_by_ip)), daemon=True)
        t_testssl = threading.Thread(target=lambda: testssl_results.extend(self._run_testssl(hosts_by_ip)), daemon=True)
        t_nuclei.start()
        t_testssl.start()
        t_nuclei.join()
        t_testssl.join()

        # 5. Flush any buffered findings that failed to ship during scan
        flushed = self.buffer.flush_pending()
        if flushed:
            logger.info("Flushed %d pending findings", flushed)

        self.poller.update_status(job_id, "COMPLETE", "done")
        logger.info("Job %s complete — nuclei: %d, testssl: %d", job_id, len(nuclei_results), len(testssl_results))

    # ── naabu ────────────────────────────────────────────────────

    def _run_naabu(self, targets: list[str], stealth: int) -> list[dict]:
        idx  = min(stealth, len(NAABU_RATES) - 1)
        rate = NAABU_RATES[idx]
        results: list[dict] = []

        def on_line(line: str) -> None:
            r = self._parse_naabu_line(line)
            if r:
                results.append(r)

        try:
            self.adapter.run(
                "naabu",
                ["-host", ",".join(targets), "-rate", str(rate), "-s", "c", "-json", "-silent"],
                on_line,
            )
        except Exception as exc:
            logger.warning("naabu error: %s", exc)

        return results

    # ── nmap ─────────────────────────────────────────────────────

    def _run_nmap(self, open_ports: list[dict], stealth: int) -> dict[str, list[int]]:
        if not open_ports:
            return {}

        idx    = min(stealth, len(NMAP_TIMING) - 1)
        timing = NMAP_TIMING[idx]
        ips    = list({r["ip"] for r in open_ports})
        ports  = list({r["port"] for r in open_ports})
        port_str = ",".join(str(p) for p in sorted(ports)) if ports else "1-1000"

        hosts_by_ip: dict[str, list[int]] = {ip: [] for ip in ips}
        for r in open_ports:
            hosts_by_ip.setdefault(r["ip"], []).append(r["port"])

        lines: list[str] = []

        try:
            self.adapter.run(
                "nmap",
                ["-sT", "-sV", f"-T{timing}", "-p", port_str,
                 "--script", "banner,ssl-cert,http-title", "-oG", "-"] + ips,
                lines.append,
            )
        except Exception as exc:
            logger.warning("nmap error: %s", exc)

        return hosts_by_ip

    # ── nuclei ───────────────────────────────────────────────────

    def _run_nuclei(self, hosts_by_ip: dict[str, list[int]]) -> list[dict]:
        WEB_PROTO = {80: "http", 443: "https", 8080: "http", 8443: "https", 8000: "http", 3000: "http", 5000: "http"}
        urls = [
            f"{WEB_PROTO[port]}://{ip}:{port}"
            for ip, ports in hosts_by_ip.items()
            for port in ports
            if port in WEB_PROTO
        ]
        if not urls:
            return []

        results: list[dict] = []

        def on_line(line: str) -> None:
            f = self._parse_nuclei_line(line)
            if f:
                results.append(f)
                self.buffer.write(f)

        url_args = []
        for u in urls:
            url_args += ["-u", u]

        try:
            self.adapter.run("nuclei", ["-json", "-silent", "-no-color"] + url_args, on_line)
        except Exception as exc:
            logger.warning("nuclei error: %s", exc)

        return results

    # ── testssl ──────────────────────────────────────────────────

    def _run_testssl(self, hosts_by_ip: dict[str, list[int]]) -> list[dict]:
        import tempfile, os
        TLS_PORTS = {443, 8443}
        results: list[dict] = []

        for ip, ports in hosts_by_ip.items():
            tls_ports = [p for p in ports if p in TLS_PORTS]
            if not tls_ports:
                continue
            port = tls_ports[0]

            tmp_file = os.path.join(tempfile.gettempdir(), f"adversa-testssl-{ip}-{int(time.time())}.json")

            try:
                self.adapter.run(
                    "testssl",
                    ["--fast", "--jsonfile", tmp_file, "--color", "0", "--quiet", f"{ip}:{port}"],
                    lambda _: None,
                )
            except Exception as exc:
                logger.warning("testssl error: %s", exc)
                continue

            if os.path.exists(tmp_file):
                try:
                    with open(tmp_file, encoding="utf-8") as fh:
                        issues = json.load(fh)
                    for issue in issues:
                        sev = issue.get("severity", "")
                        if sev in ("OK", "INFO", "DEBUG"):
                            continue
                        f = self._build_finding(
                            source="testssl",
                            host=ip,
                            port=port,
                            severity=self._map_testssl_severity(sev),
                            title=f"{issue.get('id', 'TLS')}: {issue.get('finding', '')[:60]}",
                            evidence=issue.get("finding", ""),
                            cve_ids=[issue["cve"]] if issue.get("cve") else None,
                        )
                        results.append(f)
                        self.buffer.write(f)
                except Exception as exc:
                    logger.warning("testssl parse error for %s: %s", ip, exc)
                finally:
                    try:
                        os.unlink(tmp_file)
                    except OSError:
                        pass

        return results

    # ── Finding builders ─────────────────────────────────────────

    def _build_finding(
        self,
        source: str,
        host: str,
        port: int,
        severity: str,
        title: str,
        evidence: str,
        cve_ids: list[str] | None = None,
    ) -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return {
            "id":        f"VAPT-{severity[:4]}-{uuid.uuid4().hex[:6].upper()}",
            "title":     title,
            "severity":  severity,
            "host":      host,
            "port":      port,
            "source":    source,
            "cveIds":    cve_ids or [],
            "evidence":  [{"label": f"{source} output", "content": evidence, "timestamp": now}],
            "status":    "OPEN",
            "timestamp": now,
        }

    def _parse_naabu_line(self, line: str) -> dict | None:
        try:
            obj = json.loads(line)
            ip   = obj.get("ip") or obj.get("host")
            port = obj.get("port")
            if not ip or not port:
                return None
            return {"ip": str(ip), "port": int(port), "protocol": obj.get("protocol", "tcp")}
        except (json.JSONDecodeError, ValueError):
            return None

    def _parse_nuclei_line(self, line: str) -> dict | None:
        try:
            obj = json.loads(line)
            if not obj.get("template-id"):
                return None
            info     = obj.get("info", {})
            sev_raw  = info.get("severity", "info").lower()
            sev_map  = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
            severity = sev_map.get(sev_raw, "INFO")
            cve_ids: list[str] = []
            clf = info.get("classification", {})
            raw_cve = clf.get("cve-id", [])
            if isinstance(raw_cve, list):
                cve_ids = raw_cve
            elif isinstance(raw_cve, str):
                cve_ids = [raw_cve]
            host = obj.get("ip") or obj.get("host", "")
            port_val = obj.get("port")
            port = int(port_val) if port_val else 0
            return self._build_finding(
                source="nuclei",
                host=host,
                port=port,
                severity=severity,
                title=info.get("name", obj.get("template-id", "Unknown")),
                evidence=obj.get("matched-at", ""),
                cve_ids=cve_ids,
            )
        except (json.JSONDecodeError, ValueError, KeyError):
            return None

    @staticmethod
    def _map_testssl_severity(sev: str) -> str:
        m = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "WARN": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        return m.get(sev.upper(), "INFO")
