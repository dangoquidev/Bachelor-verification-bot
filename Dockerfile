# syntax=docker/dockerfile:1

# Build stage
FROM node:20-bookworm AS build
WORKDIR /app

# Install dependencies first (better layer caching)
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund

# Copy sources
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript
RUN npm run build

# Copy non-TS assets needed at runtime into dist
COPY src/ascii ./dist/ascii

# Runtime stage
FROM node:20-bookworm AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Only copy the minimal runtime artifacts
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist

# Create a non-root user for security
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

# Expose the auth server port
EXPOSE 8000

# Default env file location can be overridden via docker-compose
ENV PORT=8000

# Start the bot
CMD ["node", "dist/index.js"]
