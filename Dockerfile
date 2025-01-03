# syntax=docker/dockerfile:1.3

FROM golang:1.23-alpine AS builder

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

# Install upx
RUN apk add --no-cache upx

# Compress the compiled binary
RUN upx -q -9 /enclave-server

# Final Stage
FROM alpine:latest

# Install curl
RUN apk add --no-cache curl

# Copy the built binary from the builder stage
COPY --from=builder /enclave-server /enclave-server

# Expose the port your service listens on
EXPOSE 80
EXPOSE 50051

# Set the entry point to run the server
ENTRYPOINT ["/enclave-server"]
