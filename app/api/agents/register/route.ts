import { NextResponse }                              from "next/server";
import { agentsStore, type JobType }                 from "../../../../lib/agents-store";
import { registerAgent }                             from "../../../../lib/agents-store";

// POST /api/agents/register — Python CLI agent self-registration
export async function POST(request: Request) {
  // Validate Bearer token against AGENT_SECRET
  const auth   = request.headers.get("Authorization") ?? "";
  const token  = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const secret = process.env.AGENT_SECRET;

  if (!secret || !token || token !== secret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  const { sessionId, hostname, os, osVersion, arch, agentVersion, capabilities, networkInterfaces } = body;
  if (!sessionId || !hostname || !os) {
    return NextResponse.json(
      { error: "sessionId, hostname, and os are required" },
      { status: 400 },
    );
  }

  const agent = registerAgent({
    sessionId:         String(sessionId),
    hostname:          String(hostname),
    os:                String(os),
    osVersion:         osVersion != null ? String(osVersion) : "",
    arch:              arch != null ? String(arch) : "",
    agentVersion:      agentVersion != null ? String(agentVersion) : "0.1.0",
    capabilities:      Array.isArray(capabilities) ? (capabilities as string[]) : [],
    networkInterfaces: Array.isArray(networkInterfaces)
      ? (networkInterfaces as { name: string; ip: string; cidr: string }[])
      : [],
  });

  return NextResponse.json({ agentId: agent.id, registeredAt: agent.registeredAt });
}

// GET /api/agents/register — dashboard agent + job + kafka overview
export async function GET() {
  return NextResponse.json({
    agents: agentsStore.listAgents(),
    stats:  agentsStore.stats(),
    jobs:   agentsStore.listJobs(),
    topics: agentsStore.listTopics(),
  });
}
