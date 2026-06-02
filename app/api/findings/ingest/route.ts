import { NextResponse }              from "next/server";
import { getAgent }                  from "../../../../lib/agents-store";
import { saveFindings }              from "../../../../lib/findings-store";
import { broadcastToScan }           from "../../../../lib/scan-events";
import type { LiveFinding }          from "../../../../lib/engine/types";

// POST /api/findings/ingest — called by Python agent during live scan
export async function POST(request: Request) {
  const auth    = request.headers.get("Authorization") ?? "";
  const agentId = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  if (!agentId || !getAgent(agentId)) {
    return NextResponse.json({ error: "Unauthorized — unknown agentId" }, { status: 401 });
  }

  const body = await request.json().catch(() => null) as {
    scanId?: string;
    agentId?: string;
    findings?: unknown[];
  } | null;

  if (!body || !body.scanId || !Array.isArray(body.findings) || body.findings.length === 0) {
    return NextResponse.json(
      { error: "scanId and non-empty findings[] are required" },
      { status: 400 },
    );
  }

  const findings = body.findings as LiveFinding[];
  const before   = findings.length;
  const saved    = saveFindings(findings, body.scanId);
  const dups     = before - saved;

  // Broadcast each new finding to any live SSE subscribers for this scan
  for (const f of findings) {
    broadcastToScan(body.scanId, "finding", f);
  }

  return NextResponse.json({ saved, duplicates: dups });
}
