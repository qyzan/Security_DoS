# Build Stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o securitydos .

# Run Stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /app/securitydos .

# Copy assets and configs
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/dashboard ./dashboard

# Create logs directory
RUN mkdir -p logs && chmod 777 logs

# Expose the dashboard port
EXPOSE 8090

# Default command (Safe-by-Default)
ENTRYPOINT ["./securitydos"]
CMD ["-config", "configs/config.yaml", "--guard"]
