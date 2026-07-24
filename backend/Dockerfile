# ==============================================================================
# Project Parewa — Auth Service Dockerfile (Multi-Stage)
# Base: Node 20 Alpine | Exposes port 8080
# ==============================================================================

# ---- Stage 1: Build ----------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (layer caching)
COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts

# Copy source and compile TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ---- Stage 2: Production Runtime --------------------------------------------
FROM node:20-alpine AS runtime

WORKDIR /app

# Security: run as non-root user
RUN addgroup -S parewa && adduser -S parewa -G parewa

# Install production dependencies only
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --ignore-scripts && npm cache clean --force

# Copy compiled JS from builder stage
COPY --from=builder /app/dist ./dist

# Switch to non-root user
USER parewa

# Expose the API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["node", "dist/index.js"]
