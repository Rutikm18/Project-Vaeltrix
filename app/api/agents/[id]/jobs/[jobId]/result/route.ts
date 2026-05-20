import { NextResponse } from "next/server";
import { agentsStore } from "../../../../../../../lib/agents-store";

// POST /agents/{id}/jobs/{jobId}/result
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string; jobId: string }> }
) {
  const { jobId } = await params;
  const body = await request.json().catch(() => ({}));
  const { result = {}, success = true } = body;
  const job = agentsStore.submitResult(jobId, result, success);
  if (!job) return NextResponse.json({ error: "Job not found" }, { status: 404 });
  return NextResponse.json({ jobId: job.id, status: job.status, completedAt: job.completedAt });
}
