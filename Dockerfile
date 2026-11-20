# Build stage
FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/probe-worker ./cmd/probe-worker

# Runtime stage: ghostscript rebuilds PDF, poppler-utils provides pdfinfo,
# unzip lists OOXML parts, and file classifies those parts. Verification
# cannot be skipped, so a missing tool stops the image rather than degrading it.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
      ghostscript \
      poppler-utils \
      unzip \
      file \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/probe-worker /usr/local/bin/probe-worker
RUN gs --version && file --version | head -1 && unzip -v | head -1
USER nobody
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/probe-worker"]
