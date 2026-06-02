import { NextRequest, NextResponse } from 'next/server';
import { withAuth }                  from '../../../../lib/auth-middleware';
import { getUser }                   from '../../../../lib/permissions-store';

// GET /api/auth/me  →  { email, role, allowedScopes }
export const GET = withAuth((_req: NextRequest, ctx) => {
  const user = getUser(ctx.email);
  return NextResponse.json({
    email:         ctx.email,
    role:          user?.role ?? 'operator',
    allowedScopes: user?.allowedScopes ?? [],
  });
});
