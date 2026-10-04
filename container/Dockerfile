# Scanner container for Cloudflare Containers. Built and pushed by `wrangler deploy` (see wrangler.jsonc).
# Build context is the repo root so the scanner can reuse src/lib.
FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --include=dev --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
COPY container ./container
USER node
EXPOSE 8080
CMD ["npx", "tsx", "container/server.ts"]
