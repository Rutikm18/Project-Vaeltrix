import { NextResponse } from "next/server";
import { agentsStore, type JobType } from "../../../../lib/agents-store";

// POST /agents/register
export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const { agentName, location, capabilities, networkSegments, ip, version } = body;

  if (!agentName || !location || !Array.isArray(capabilities)) {
    return NextResponse.json({ error: "agentName, location, and capabilities[] are required" }, { status: 400 });
  }

  const agent = agentsStore.register({ agentName, location, capabilities: capabilities as JobType[], networkSegments: networkSegments ?? [], ip, version });

  // Simulate issuing mTLS cert and Vault role token
  return NextResponse.json({
    agentId:        agent.id,
    vaultRoleToken: agent.vaultRoleToken,
    tlsCert: `-----BEGIN CERTIFICATE-----\n[mTLS client cert for ${agent.id} — issued by ADVERSA CA]\n-----END CERTIFICATE-----`,
    tlsCertExpiry:  agent.tlsCertExpiry,
    platformApiUrl: "https://adversa.internal:8443",
    instructions: [
      "Store the tlsCert in your local secure keystore (e.g. /etc/adversa/certs/client.pem)",
      "Use vaultRoleToken to authenticate with Vault and fetch credentials at runtime",
      "Send heartbeats every 30s to POST /agents/{agentId}/heartbeat",
      "Poll GET /agents/{agentId}/jobs for pending work every 10s",
    ],
  }, { status: 201 });
}

// GET /agents/register — list all agents
export async function GET() {
  const agents = agentsStore.listAgents();
  const stats  = agentsStore.stats();
  const jobs   = agentsStore.listJobs();
  const topics = agentsStore.listTopics();
  return NextResponse.json({ agents, stats, jobs, topics });
}
