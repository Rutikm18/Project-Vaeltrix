# ─────────────────────────────────────────────────────────────────────────────
# ADVERSA Platform — Dockerfile
# Multi-stage build:  deps → builder → runner
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: install production + dev deps ───────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app

# Install libc compat for Alpine + build tools for native modules
RUN apk add --no-cache libc6-compat

COPY package.json package-lock.json* ./

# ci install is reproducible; uses lockfile exactly
RUN npm ci

# ── Stage 2: build Next.js standalone bundle ─────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

# Copy deps from previous stage
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

RUN npm run build

# ── Stage 3: minimal production runner ───────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Non-root user for security
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

# Writable data directory for findings/cases JSON stores
RUN mkdir -p /app/data && chown nextjs:nodejs /app/data

# Copy the standalone output (self-contained Node server)
COPY --from=builder /app/public                           ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static     ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
