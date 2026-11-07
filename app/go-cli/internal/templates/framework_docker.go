package templates

import "strings"

// Image placeholders are resolved at generation, not fixed at compile time.
const frameworkBunImage = "__SHUTTLE_BUN_IMAGE__"
const frameworkNodeImage = "__SHUTTLE_NODE_IMAGE__"
const frameworkPythonImage = "__SHUTTLE_PYTHON_IMAGE__"
const frameworkUVImage = "__SHUTTLE_UV_IMAGE__"

// FrameworkDockerfiles returns production and development Dockerfile templates
// for the supported JavaScript and Python frameworks. The development template
// is empty when the framework has no dedicated development image.
func FrameworkDockerfiles(framework string) (prod string, dev string, ok bool) {
	switch normalizeFramework(framework) {
	case "laravel":
		return DockerfileLaravel(ModeAPI), DockerfileLaravelDev(), true
	case "symfony":
		return DockerfileSymfony(ModeAPI, false), DockerfileSymfonyDev(), true
	case "hono":
		return honoDockerfile(), honoDevDockerfile(), true
	case "fastify":
		return fastifyDockerfile(), fastifyDevDockerfile(), true
	case "nextjs":
		return nextJSDockerfile(), "", true
	case "tanstack-start":
		return tanStackStartDockerfile(), "", true
	case "fastapi":
		return fastAPIDockerfile(), fastAPIDevDockerfile(), true
	default:
		return "", "", false
	}
}

// FrameworkDockerignore returns a framework-specific .dockerignore. It keeps
// local dependency and build output directories out of Docker build contexts.
func FrameworkDockerignore(framework string) (string, bool) {
	base := `.git
.gitignore
.env
.env.*
docker-compose*.yml
shuttle.yml
config.json
.shuttle/
`
	switch normalizeFramework(framework) {
	case "laravel", "symfony":
		return Dockerignore(normalizeFramework(framework)), true
	case "hono", "fastify", "nextjs", "tanstack-start":
		return base + `node_modules/
dist/
.next/
.output/
coverage/
`, true
	case "fastapi":
		return base + `__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.venv/
dist/
build/
`, true
	default:
		return "", false
	}
}

func normalizeFramework(framework string) string {
	framework = strings.ToLower(strings.TrimSpace(framework))
	if framework == "tanstack_start" {
		return "tanstack-start"
	}
	return framework
}

func honoDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + ` AS deps
WORKDIR /app

# Copy dependency manifests first so source edits keep this layer cached.
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

FROM deps AS builder
COPY . .
# create-hono's Bun starter uses src/index.ts. A small root-level starter is
# also common, so reject unsupported layouts explicitly instead of emitting a
# successfully built image that exits immediately at runtime.
RUN if [ -f src/index.ts ]; then bun build src/index.ts --target node --format esm --outfile dist/application.mjs; \
    elif [ -f index.ts ]; then bun build index.ts --target node --format esm --outfile dist/application.mjs; \
    else echo 'Expected src/index.ts or index.ts for the Hono Bun entrypoint' >&2; exit 1; fi

FROM ` + frameworkNodeImage + ` AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
COPY --from=builder --chown=node:node /app/dist ./dist
RUN <<'EOF'
cat > server.mjs <<'SERVER'
import { createServer } from 'node:http'
import { Readable } from 'node:stream'
import application from './dist/application.mjs'

const fetchHandler = application?.fetch?.bind(application)
if (!fetchHandler) throw new TypeError('The Hono entrypoint must export a default fetch handler')

createServer(async (request, response) => {
  try {
    const body = ['GET', 'HEAD'].includes(request.method) ? undefined : request
    const appResponse = await fetchHandler(new Request(
      'http://' + (request.headers.host || '127.0.0.1') + request.url,
      { method: request.method, headers: request.headers, body, duplex: 'half' },
    ))
    const headers = Object.fromEntries(
      [...appResponse.headers].filter(([name]) => name.toLowerCase() !== 'set-cookie'),
    )
    const cookies = appResponse.headers.getSetCookie()
    if (cookies.length) headers['set-cookie'] = cookies
    response.writeHead(appResponse.status, headers)
    if (appResponse.body) {
      const stream = Readable.fromWeb(appResponse.body)
      stream.on('error', (error) => {
        console.error('Hono response stream failed', error instanceof Error ? error.message : 'unknown error')
        response.destroy()
      })
      stream.pipe(response)
    } else response.end()
  } catch (error) {
    console.error('Hono request failed', error instanceof Error ? error.message : 'unknown error')
    if (!response.headersSent) response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
    response.end('Internal Server Error')
  }
}).listen(Number(process.env.PORT || 3000), '0.0.0.0')
SERVER
chown node:node server.mjs
EOF
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["node", "server.mjs"]
`
}

func honoDevDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + `
WORKDIR /app
RUN chown bun:bun /app
COPY --chown=bun:bun package.json bun.lock ./
USER bun
RUN --mount=type=cache,target=/home/bun/.bun/install/cache,uid=1000,gid=1000 \
    bun install --frozen-lockfile
COPY --chown=bun:bun . .
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD bun -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["sh", "-c", "if [ -f src/index.ts ]; then exec bun --watch src/index.ts; elif [ -f index.ts ]; then exec bun --watch index.ts; else echo 'Expected src/index.ts or index.ts for the Hono Bun entrypoint' >&2; exit 1; fi"]
`
}

func fastifyDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + ` AS deps
WORKDIR /app

# Copy dependency manifests first so source edits keep this layer cached.
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

FROM deps AS builder
COPY . .
RUN bun build server.ts --target node --format esm --outfile dist/server.js

FROM ` + frameworkNodeImage + ` AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder --chown=node:node /app/dist ./dist
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["node", "dist/server.js"]
`
}

func fastifyDevDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + `
WORKDIR /app
RUN chown bun:bun /app
COPY --chown=bun:bun package.json bun.lock ./
USER bun
RUN bun install --frozen-lockfile
COPY --chown=bun:bun . .
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD bun -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["bun", "--watch", "server.ts"]
`
}

func nextJSDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + ` AS deps
WORKDIR /app

# A committed Bun lockfile is required for deterministic dependency resolution.
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

FROM ` + frameworkNodeImage + ` AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_PRIVATE_STANDALONE=1
RUN node node_modules/next/dist/bin/next build && \
    if [ -d public ]; then cp -a public .next/standalone/public; fi && \
    cp -a .next/static .next/standalone/.next/static

FROM ` + frameworkNodeImage + ` AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nextjs && adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
USER nextjs
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["node", "server.js"]
`
}

func tanStackStartDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkBunImage + ` AS deps
WORKDIR /app

# Copy dependency manifests first so source edits keep this layer cached.
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

FROM ` + frameworkBunImage + ` AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun node_modules/vite/bin/vite.js build && \
    mkdir /runtime && \
    if [ -f .output/server/index.mjs ]; then \
      cp -a .output /runtime/.output; \
    elif [ -f dist/server/server.js ]; then \
      cp -a dist /runtime/; \
      bun install --frozen-lockfile --production; \
      cp -a node_modules /runtime/node_modules; \
    else \
      echo 'Expected TanStack Start output at .output/server/index.mjs or dist/server/server.js' >&2; exit 1; \
    fi

FROM ` + frameworkNodeImage + ` AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
RUN addgroup --system --gid 1001 tanstack && adduser --system --uid 1001 tanstack
COPY --from=builder --chown=tanstack:tanstack /runtime ./
RUN <<'EOF'
cat > server.mjs <<'SERVER'
import { createServer } from 'node:http'
import { Readable } from 'node:stream'
import application from './dist/server/server.js'

createServer(async (request, response) => {
  try {
    const body = ['GET', 'HEAD'].includes(request.method) ? undefined : request
    const appResponse = await application.fetch(new Request(
      'http://' + request.headers.host + request.url,
      { method: request.method, headers: request.headers, body, duplex: 'half' },
    ))
    const headers = Object.fromEntries(
      [...appResponse.headers].filter(([name]) => name.toLowerCase() !== 'set-cookie'),
    )
    const cookies = appResponse.headers.getSetCookie()
    if (cookies.length) headers['set-cookie'] = cookies
    response.writeHead(appResponse.status, headers)
    if (appResponse.body) {
      const stream = Readable.fromWeb(appResponse.body)
      stream.on('error', (error) => {
        console.error('TanStack response stream failed', error instanceof Error ? error.message : 'unknown error')
        response.destroy()
      })
      stream.pipe(response)
    } else response.end()
  } catch (error) {
    console.error('TanStack request failed', error instanceof Error ? error.message : 'unknown error')
    if (!response.headersSent) response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
    response.end('Internal Server Error')
  }
}).listen(Number(process.env.PORT || 3000), '0.0.0.0')
SERVER
chown tanstack:tanstack server.mjs
EOF
USER tanstack
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e 'fetch("http://127.0.0.1:3000/").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))'
CMD ["sh", "-c", "if [ -f .output/server/index.mjs ]; then exec node .output/server/index.mjs; else exec node server.mjs; fi"]
`
}

func fastAPIDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkUVImage + ` AS builder
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PROJECT_ENVIRONMENT=/app/.venv

# The lockfile layer is reusable until Python dependencies change.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

FROM ` + frameworkPythonImage + ` AS runtime
WORKDIR /app
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.2"
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
RUN groupadd --system app && useradd --system --gid app --home-dir /app app && chown app:app /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/app /app/app
USER app
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c 'from urllib.request import urlopen; urlopen("http://127.0.0.1:8000/", timeout=2).close()'
CMD ["fastapi", "run", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
`
}

func fastAPIDevDockerfile() string {
	return `# syntax=docker/dockerfile:1.7
FROM ` + frameworkUVImage + `
WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
ENV UV_CACHE_DIR=/tmp/uv-cache
ENV PATH="/app/.venv/bin:$PATH"
RUN groupadd --system app && useradd --system --gid app --home-dir /app app && chown app:app /app
COPY --chown=app:app pyproject.toml uv.lock ./
USER app
RUN uv sync --frozen --no-install-project
COPY --chown=app:app . .
RUN uv sync --frozen
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c 'from urllib.request import urlopen; urlopen("http://127.0.0.1:8000/", timeout=2).close()'
CMD ["fastapi", "dev", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
`
}
