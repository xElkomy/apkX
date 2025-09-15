# apkX Web - Docker image (v3.2)
# Builds the server and bundles optional tools (apk-mitm, apkeep)

FROM golang:1.22-bullseye as builder

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
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-x86_64-unknown-linux-gnu" ;; \
      arm64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep; \
    chmod +x /usr/local/bin/apkeep

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

# Optional: apk-mitm for download/MITM features and apkeep binary
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

# Install apkeep binary matching target arch (no buildx needed)
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-x86_64-unknown-linux-gnu" ;; \
      arm64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep; \
    chmod +x /usr/local/bin/apkeep

WORKDIR /app

# App files
COPY --from=builder /app/apkx-web /usr/local/bin/apkx-web
# Ensure runtime data directories exist inside the image
RUN mkdir -p /app/web-data/uploads /app/web-data/downloads /app/web-data/reports

EXPOSE 9090

# Default command: start server with MITM enabled; override at runtime if desired
CMD ["/usr/local/bin/apkx-web", "-addr", ":9090", "-mitm"]
