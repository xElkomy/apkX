# apkX Web - Docker image (v3.2)
# Builds the server and bundles optional tools (apk-mitm, apkeep)

FROM --platform=$BUILDPLATFORM golang:1.22-bullseye as builder

# System deps for build and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl git ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Optional tools: install apk-mitm (Node) and apkeep binary
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

# Install apkeep by downloading prebuilt binary (no PyPI package)
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      "amd64")  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/v0.17.0/apkeep-v0.17.0-x86_64-unknown-linux-gnu.tar.gz" ;; \
      "arm64")  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/v0.17.0/apkeep-v0.17.0-aarch64-unknown-linux-gnu.tar.gz" ;; \
      *) echo "Unsupported arch: $TARGETARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /tmp/apkeep.tgz; \
    tar -xzf /tmp/apkeep.tgz -C /usr/local/bin apkeep; \
    chmod +x /usr/local/bin/apkeep; \
    rm -f /tmp/apkeep.tgz

WORKDIR /app

# Cache go mod first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build web server
RUN go build -o apkx-web ./cmd/server/main.go

# Final image
FROM --platform=$TARGETPLATFORM debian:bullseye-slim

ENV PORT=9090

# Runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Optional: apk-mitm for download/MITM features and apkeep binary
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

# Install apkeep binary matching target arch
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      "amd64")  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/v0.17.0/apkeep-v0.17.0-x86_64-unknown-linux-gnu.tar.gz" ;; \
      "arm64")  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/v0.17.0/apkeep-v0.17.0-aarch64-unknown-linux-gnu.tar.gz" ;; \
      *) echo "Unsupported arch: $TARGETARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /tmp/apkeep.tgz; \
    tar -xzf /tmp/apkeep.tgz -C /usr/local/bin apkeep; \
    chmod +x /usr/local/bin/apkeep; \
    rm -f /tmp/apkeep.tgz

WORKDIR /app

# App files
COPY --from=builder /app/apkx-web /usr/local/bin/apkx-web
COPY web-data /app/web-data

EXPOSE 9090

# Default command: start server with MITM enabled; override at runtime if desired
CMD ["/usr/local/bin/apkx-web", "-addr", ":9090", "-mitm"]
