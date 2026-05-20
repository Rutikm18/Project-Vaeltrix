import { NextResponse } from "next/server";
import { engagementsStore } from "../../../../lib/engagements-store";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const engagement = engagementsStore.get(id);
  if (!engagement) return NextResponse.json({ error: "Not found" }, { status: 404 });
  const activity = engagementsStore.listActivity(id);
  return NextResponse.json({ engagement, activity });
}

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();
  const updated = engagementsStore.update(id, body);
  if (!updated) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ engagement: updated });
}
