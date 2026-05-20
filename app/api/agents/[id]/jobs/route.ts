import { NextResponse } from "next/server";
import { agentsStore } from "../../../../../lib/agents-store";

// GET /agents/{id}/jobs — agent polls for pending job
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  agentsStore.heartbeat(id); // treat poll as implicit heartbeat
  const job = agentsStore.getPendingJob(id);
  if (!job) return NextResponse.json({ job: null, message: "No pending jobs" });
  return NextResponse.json({ job });
}
