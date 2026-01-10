# go-as4 Dockerfile for Interop Testing
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build test binary
RUN go build -o /go-as4-test ./tests/interop/cmd/

FROM alpine:latest
RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Copy test binary
COPY --from=builder /go-as4-test .

EXPOSE 9090

CMD ["./go-as4-test"]
