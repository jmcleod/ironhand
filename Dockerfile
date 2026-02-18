# Multi-stage Dockerfile for IronHand

# Stage 1: Build the Go application
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o /ironhand ./cmd/ironhand/main.go

# Stage 2: Create a minimal image
FROM alpine:latest

WORKDIR /

COPY --from=builder /ironhand /ironhand

# Persistent storage volume
VOLUME /data

# Expose the port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/ironhand"]
CMD ["server", "--port", "8080", "--data-dir", "/data"]
