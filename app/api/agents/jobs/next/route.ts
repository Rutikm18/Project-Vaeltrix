import { NextResponse }                              from "next/server";
import { getAgent, updateAgentLastSeen }             from "../../../../../lib/agents-store";
import { getNextJobForAgent, markDispatched }        from "../../../../../lib/job-store";

const POLL_INTERVAL_MS = 500;
const POLL_TIMEOUT_MS  = 28_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// GET /api/agents/jobs/next — long-poll for a pending job
export async function GET(request: Request) {
  const auth    = request.headers.get("Authorization") ?? "";
  const agentId = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const agent = agentId ? getAgent(agentId) : undefined;
  if (!agent) {
    return NextResponse.json({ error: "Unauthorized — unknown agentId" }, { status: 401 });
  }

  updateAgentLastSeen(agentId);

  const deadline = Date.now() + POLL_TIMEOUT_MS;

  while (Date.now() < deadline) {
    const job = getNextJobForAgent(agentId, agent.capabilities);
    if (job) {
      markDispatched(job.id, agentId);
      return NextResponse.json(job);
    }
    await sleep(POLL_INTERVAL_MS);
  }

  // 28 seconds elapsed — no job available
  return new NextResponse(null, { status: 204 });
}
