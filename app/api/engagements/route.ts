import { NextResponse }      from "next/server";
import { withAuth }          from "../../../lib/auth-middleware";
import { engagementsStore }  from "../../../lib/engagements-store";

export const GET = withAuth(async () => {
  const engagements = engagementsStore.list();
  const activity    = engagementsStore.listActivity();
  const timeline    = engagementsStore.getTimeline();
  const totalFindings     = engagements.reduce((s, e) => s + e.findingCount, 0);
  const activeEngagements = engagements.filter((e) => e.status === "ACTIVE").length;
  const totalAssets       = engagements.reduce((s, e) => s + e.assetCount, 0);
  return NextResponse.json({
    engagements,
    activity,
    timeline,
    stats: { totalFindings, activeEngagements, totalAssets },
  });
});

export const POST = withAuth(async (request) => {
  const body = await request.json();
  const {
    name, client, startDate, endDate,
    scopeCidrs, excludedCidrs, credentials,
    assessor, description, tags,
  } = body;
  if (!name || !client || !startDate || !endDate) {
    return NextResponse.json(
      { error: "name, client, startDate, endDate are required" },
      { status: 400 },
    );
  }
  const eng = engagementsStore.create({
    name, client, status: "PLANNING",
    startDate, endDate,
    scopeCidrs:    scopeCidrs    ?? [],
    excludedCidrs: excludedCidrs ?? [],
    credentials:   credentials   ?? [],
    assessor:      assessor      ?? "analyst@adversa.io",
    description,
    tags:          tags          ?? [],
  });
  return NextResponse.json({ engagement: eng }, { status: 201 });
});
