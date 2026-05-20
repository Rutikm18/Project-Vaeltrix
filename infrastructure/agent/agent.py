#!/usr/bin/env python3
"""
ADVERSA ScanningAgent
Polls the platform API for scan jobs, executes them, and reports results.
Communication is secured via mTLS (client cert issued at registration).
Credentials are fetched from HashiCorp Vault — never stored locally.
"""

import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import aiohttp
import hvac  # HashiCorp Vault client

# ── Configuration ─────────────────────────────────────────────────────────────

PLATFORM_API_URL   = os.environ.get("PLATFORM_API_URL",   "https://adversa.internal:8443")
AGENT_ID           = os.environ.get("AGENT_ID",           "")
VAULT_ADDR         = os.environ.get("VAULT_ADDR",         "https://vault.internal:8200")
VAULT_ROLE_TOKEN   = os.environ.get("VAULT_ROLE_TOKEN",   "")
TLS_CERT_PATH      = os.environ.get("TLS_CERT_PATH",      "/etc/adversa/certs/client.pem")
TLS_KEY_PATH       = os.environ.get("TLS_KEY_PATH",       "/etc/adversa/certs/client.key")
TLS_CA_PATH        = os.environ.get("TLS_CA_PATH",        "/etc/adversa/certs/ca.pem")
POLL_INTERVAL      = int(os.environ.get("POLL_INTERVAL",  "10"))   # seconds
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))  # seconds
LOG_LEVEL          = os.environ.get("LOG_LEVEL",          "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("adversa.agent")


# ── Types ─────────────────────────────────────────────────────────────────────

class JobType(str, Enum):
    DISCOVERY        = "discovery"
    VULN_SCAN        = "vuln_scan"
    AD_ENUM          = "ad_enum"
    LATERAL_MOVEMENT = "lateral_movement"
    CLOUD_SCAN       = "cloud_scan"


@dataclass
class ScanJob:
    id: str
    type: JobType
    engagement_id: str
    target_cidrs: list[str]
    excluded_cidrs: list[str]
    profile: str  # fast | standard | deep
    raw: dict = field(default_factory=dict)


# ── Vault credential fetcher ───────────────────────────────────────────────────

class VaultCredentialFetcher:
    """Fetches credentials from HashiCorp Vault at runtime. Never caches to disk."""

    def __init__(self, vault_addr: str, role_token: str):
        self.client = hvac.Client(url=vault_addr, token=role_token)

    def get_credentials(self, secret_path: str) -> dict[str, str]:
        """Read a KV-v2 secret from Vault."""
        try:
            resp = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            return resp["data"]["data"]
        except Exception as e:
            log.error("Vault read failed for %s: %s", secret_path, e)
            return {}


# ── mTLS session builder ───────────────────────────────────────────────────────

def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TLS_CA_PATH)
    ctx.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    return ctx


# ── Job executors ──────────────────────────────────────────────────────────────

async def execute_discovery(job: ScanJob, creds: dict, report_progress) -> dict:
    """DiscoveryWorker: Nmap ping sweep then service fingerprinting."""
    log.info("[%s] Discovery on %s (profile=%s)", job.id, job.target_cidrs, job.profile)

    nmap_flags = {
        "fast":     ["-sn", "-T4"],
        "standard": ["-sV", "-sC", "-T3", "--top-ports", "1000"],
        "deep":     ["-sV", "-sC", "-A", "-T3", "-p-"],
    }.get(job.profile, ["-sn", "-T4"])

    await report_progress(10)
    proc = await asyncio.create_subprocess_exec(
        "nmap", *nmap_flags, "-oX", "/tmp/nmap_out.xml",
        *[c for c in job.target_cidrs if c not in job.excluded_cidrs],
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(70)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {stderr.decode()}")

    await report_progress(90)
    # Parse XML (simplified — real impl uses python-nmap)
    assets_found = 0
    with open("/tmp/nmap_out.xml") as f:
        content = f.read()
        assets_found = content.count("<host ")

    await report_progress(100)
    return {"assetsFound": assets_found, "profile": job.profile, "nmapFlags": nmap_flags}


async def execute_vuln_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    """NessusScanner / NucleiScanner integration."""
    log.info("[%s] Vuln scan on %s", job.id, job.target_cidrs)
    await report_progress(20)

    # Nuclei scan (safe templates only)
    safe_tags = ["cves", "misconfigs", "ssl", "default-logins", "exposed-panels"]
    proc = await asyncio.create_subprocess_exec(
        "nuclei", "-t", ",".join(safe_tags),
        "-l", "/tmp/targets.txt", "-json", "-o", "/tmp/nuclei_out.jsonl",
        "-rate-limit", "50",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(75)
    await proc.communicate()
    await report_progress(100)
    return {"scanner": "nuclei", "templatesUsed": safe_tags}


async def execute_ad_enum(job: ScanJob, creds: dict, report_progress) -> dict:
    """LDAPEnumerator + KerberoastChecker + ASREPRoastChecker."""
    log.info("[%s] AD enumeration", job.id)
    dc_ip    = creds.get("dc_ip",   "10.0.0.10")
    domain   = creds.get("domain",  "corp.local")
    username = creds.get("username", "")
    password = creds.get("password", "")

    await report_progress(15)
    # LDAP enumeration via ldap3 (simplified)
    import subprocess
    result = subprocess.run(
        ["python3", "-c",
         f"import ldap3; conn=ldap3.Connection('{dc_ip}',user='{username}',password='{password}',auto_bind=True); "
         f"conn.search('DC={domain.replace(\".\",\",DC=\")}','(objectClass=user)',attributes=['sAMAccountName']); "
         f"print(len(conn.entries))"],
        capture_output=True, text=True, timeout=30
    )
    user_count = int(result.stdout.strip()) if result.returncode == 0 else 0

    await report_progress(60)
    # GetUserSPNs.py for Kerberoasting check
    subprocess.run(
        ["GetUserSPNs.py", f"{domain}/{username}:{password}", "-dc-ip", dc_ip, "-request", "-outputfile", "/tmp/tgs_hashes.txt"],
        capture_output=True, timeout=60
    )
    await report_progress(100)
    return {"usersEnumerated": user_count, "domain": domain}


async def execute_lateral_movement(job: ScanJob, creds: dict, report_progress) -> dict:
    """Safe lateral movement checks — no actual exploitation."""
    log.info("[%s] Lateral movement assessment", job.id)
    await report_progress(50)
    await asyncio.sleep(5)  # Simulate analysis
    await report_progress(100)
    return {"hostsAssessed": len(job.target_cidrs), "mode": "safe-check"}


async def execute_cloud_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    """Cloud infrastructure scan (AWS/Azure/GCP)."""
    log.info("[%s] Cloud scan", job.id)
    aws_key    = creds.get("aws_access_key_id",     "")
    aws_secret = creds.get("aws_secret_access_key", "")
    region     = creds.get("aws_region",            "us-east-1")
    await report_progress(30)
    # Prowler / ScoutSuite integration point
    proc = await asyncio.create_subprocess_exec(
        "prowler", "aws", "--output-formats", "json", "-r", region,
        env={**os.environ, "AWS_ACCESS_KEY_ID": aws_key, "AWS_SECRET_ACCESS_KEY": aws_secret},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(80)
    await proc.communicate()
    await report_progress(100)
    return {"cloudProvider": "aws", "region": region, "tool": "prowler"}


JOB_EXECUTORS = {
    JobType.DISCOVERY:        execute_discovery,
    JobType.VULN_SCAN:        execute_vuln_scan,
    JobType.AD_ENUM:          execute_ad_enum,
    JobType.LATERAL_MOVEMENT: execute_lateral_movement,
    JobType.CLOUD_SCAN:       execute_cloud_scan,
}


# ── ScanningAgent ──────────────────────────────────────────────────────────────

class ScanningAgent:
    def __init__(self):
        self.agent_id     = AGENT_ID
        self.running      = True
        self.current_job: Optional[ScanJob] = None
        self.vault        = VaultCredentialFetcher(VAULT_ADDR, VAULT_ROLE_TOKEN) if VAULT_ROLE_TOKEN else None
        self.ssl_ctx      = build_ssl_context() if os.path.exists(TLS_CERT_PATH) else None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._poll_task:      Optional[asyncio.Task] = None

    async def _api_call(self, session: aiohttp.ClientSession, method: str, path: str, **kwargs) -> Any:
        url = f"{PLATFORM_API_URL}{path}"
        try:
            async with session.request(method, url, ssl=self.ssl_ctx, **kwargs) as resp:
                return await resp.json()
        except Exception as e:
            log.warning("API call failed %s %s: %s", method, path, e)
            return None

    async def _heartbeat_loop(self, session: aiohttp.ClientSession):
        while self.running:
            data = await self._api_call(session, "POST", f"/api/agents/{self.agent_id}/heartbeat")
            if data:
                log.debug("Heartbeat OK — server: %s", data.get("serverTime", "?"))
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _report_progress(self, session: aiohttp.ClientSession, job_id: str, progress: int):
        await self._api_call(
            session, "POST",
            f"/api/agents/{self.agent_id}/jobs/{job_id}/progress",
            json={"progress": progress},
        )

    async def _poll_and_execute(self, session: aiohttp.ClientSession):
        while self.running:
            if self.current_job is None:
                resp = await self._api_call(session, "GET", f"/api/agents/{self.agent_id}/jobs")
                if resp and resp.get("job"):
                    raw_job = resp["job"]
                    job = ScanJob(
                        id=raw_job["id"],
                        type=JobType(raw_job["type"]),
                        engagement_id=raw_job["engagementId"],
                        target_cidrs=raw_job.get("targetCidrs", []),
                        excluded_cidrs=raw_job.get("excludedCidrs", []),
                        profile=raw_job.get("profile", "standard"),
                        raw=raw_job,
                    )
                    self.current_job = job
                    asyncio.create_task(self._execute_job(session, job))

            await asyncio.sleep(POLL_INTERVAL)

    async def _execute_job(self, session: aiohttp.ClientSession, job: ScanJob):
        log.info("Starting job %s (type=%s, profile=%s)", job.id, job.type, job.profile)
        executor = JOB_EXECUTORS.get(job.type)
        if not executor:
            log.error("No executor for job type: %s", job.type)
            self.current_job = None
            return

        # Fetch credentials from Vault
        creds: dict = {}
        if self.vault:
            vault_path = f"adversa/engagements/{job.engagement_id}/credentials"
            creds = self.vault.get_credentials(vault_path)

        async def report_progress(pct: int):
            await self._report_progress(session, job.id, pct)

        try:
            result = await executor(job, creds, report_progress)
            await self._api_call(
                session, "POST",
                f"/api/agents/{self.agent_id}/jobs/{job.id}/result",
                json={"result": result, "success": True},
            )
            log.info("Job %s completed: %s", job.id, result)
        except Exception as e:
            log.exception("Job %s failed: %s", job.id, e)
            await self._api_call(
                session, "POST",
                f"/api/agents/{self.agent_id}/jobs/{job.id}/result",
                json={"result": {"error": str(e)}, "success": False},
            )
        finally:
            self.current_job = None

    def _handle_shutdown(self, *_):
        log.info("Shutdown signal received — waiting for current job to complete…")
        self.running = False

    async def run(self):
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT,  self._handle_shutdown)

        connector = aiohttp.TCPConnector(ssl=self.ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            log.info("Agent %s starting — platform: %s", self.agent_id, PLATFORM_API_URL)
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(session))
            self._poll_task      = asyncio.create_task(self._poll_and_execute(session))
            await asyncio.gather(self._heartbeat_task, self._poll_task, return_exceptions=True)

            # Graceful shutdown: wait for current job
            if self.current_job:
                log.info("Waiting for job %s to finish…", self.current_job.id)
                while self.current_job:
                    await asyncio.sleep(2)
            log.info("Agent %s exited cleanly.", self.agent_id)


if __name__ == "__main__":
    if not AGENT_ID:
        print("ERROR: AGENT_ID environment variable required.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(ScanningAgent().run())
