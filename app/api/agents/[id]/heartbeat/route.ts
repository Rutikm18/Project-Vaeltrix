import { NextResponse } from "next/server";
import { agentsStore } from "../../../../../lib/agents-store";

// POST /agents/{id}/heartbeat
export async function POST(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const agent = agentsStore.heartbeat(id);
  if (!agent) return NextResponse.json({ error: "Agent not found" }, { status: 404 });
  const pending = agentsStore.getPendingJob(id);
  return NextResponse.json({
    status: "ok",
    agentStatus: agent.status,
    serverTime: new Date().toISOString(),
    pendingJobAvailable: !!pending,
  });
}
