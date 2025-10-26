# ---------- STAGE 1: Build ----------
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy and download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy all source code
COPY . .

# Generate Swagger docs (optional for prod)
RUN go install github.com/swaggo/swag/cmd/swag@latest && swag init -g cmd/main.go -o docs

# Build the Go binary
RUN go build -o sbom-service ./cmd/main.go


# ---------- STAGE 2: Production Image ----------
FROM alpine:3.20

WORKDIR /app

# Install syft CLI
RUN apk add --no-cache curl bash ca-certificates \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && syft version

# Copy binary from builder
COPY --from=builder /app/sbom-service .

# Add non-root user for security
RUN adduser -D appuser
USER appuser

EXPOSE 8003

CMD ["./sbom-service"]
