# syntax=docker/dockerfile:1.3

FROM golang:1.22-alpine AS builder

# Install git
RUN apk update && apk add --no-cache git

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum to leverage Docker cache
COPY go.mod go.sum ./

# Copy the rest of the application code
COPY . .

# Set the working directory to the server directory
WORKDIR /app/cmd/server

# Build the Go application (specify the main.go as the entry point)
RUN go build -o /enclave-server main.go

# Final Stage
FROM alpine:latest

# Copy the built binary from the builder stage
COPY --from=builder /enclave-server /enclave-server

# Copy the configuration file
COPY cmd/server/config.yaml /config.yaml

# Set the entry point to run the server
CMD ["/enclave-server"]
