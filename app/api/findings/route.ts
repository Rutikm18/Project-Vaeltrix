import { NextRequest, NextResponse } from "next/server";
import { readFindings, createFinding } from "../../../lib/findings-store";

export async function GET() {
  const findings = readFindings();
  return NextResponse.json(findings);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const finding = createFinding(body);
    return NextResponse.json(finding, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 400 });
  }
}
