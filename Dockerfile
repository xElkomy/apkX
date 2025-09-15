# apkX Web - Docker image (v3.2)
# Builds the server and bundles optional tools (apk-mitm, apkeep)

FROM golang:1.22-bullseye as builder

# System deps for build and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl git ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Optional tools
RUN pip3 install --no-cache-dir apkeep
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache go mod first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build web server
RUN go build -o apkx-web ./cmd/server/main.go

# Final image
FROM debian:bullseye-slim

ENV PORT=9090

# Runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Optional: apkeep + apk-mitm for download/MITM features
RUN pip3 install --no-cache-dir apkeep \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# App files
COPY --from=builder /app/apkx-web /usr/local/bin/apkx-web
COPY web-data /app/web-data

EXPOSE 9090

# Default command: start server with MITM enabled; override at runtime if desired
CMD ["/usr/local/bin/apkx-web", "-addr", ":9090", "-mitm"]
