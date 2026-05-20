import { NextResponse } from "next/server";
import { agentsStore } from "../../../../../../../lib/agents-store";

// POST /agents/{id}/jobs/{jobId}/progress
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string; jobId: string }> }
) {
  const { jobId } = await params;
  const body = await request.json().catch(() => ({}));
  const { progress } = body;
  if (typeof progress !== "number") {
    return NextResponse.json({ error: "progress (number 0-100) is required" }, { status: 400 });
  }
  const job = agentsStore.updateProgress(jobId, progress);
  if (!job) return NextResponse.json({ error: "Job not found" }, { status: 404 });
  return NextResponse.json({ jobId: job.id, progress: job.progress, status: job.status });
}
