# go-as4 Multi-Tenant AS4 Server
# Build: docker build -t go-as4-server:latest .
# Run:   docker run -p 8080:8080 -v ./config.yaml:/etc/as4/config.yaml go-as4-server:latest

FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install git for go mod (some dependencies may need it)
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /as4-server \
    ./cmd/as4-server/

# Runtime stage
FROM alpine:3.19

# Install CA certificates and curl for healthchecks
RUN apk --no-cache add ca-certificates curl tzdata

# Create non-root user
RUN addgroup -g 1000 as4 && adduser -u 1000 -G as4 -s /bin/sh -D as4

WORKDIR /app

# Copy binary
COPY --from=builder /as4-server /app/as4-server

# Copy default config
COPY cmd/as4-server/config.example.yaml /etc/as4/config.yaml

# Create directories for keys and data
RUN mkdir -p /etc/as4/keys /var/lib/as4 && \
    chown -R as4:as4 /etc/as4 /var/lib/as4 /app

USER as4

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/app/as4-server"]
CMD ["-config", "/etc/as4/config.yaml"]
