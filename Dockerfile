# syntax=docker/dockerfile:1.3

FROM golang:1.22-alpine AS builder

# Install git
RUN apk update && apk add --no-cache git

# Set the working directory
WORKDIR /app

# Define build-time variable for GitHub token
ARG GITHUB_TOKEN

# Configure Git to use the token for GitHub URLs
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

# Copy go.mod and go.sum to leverage Docker cache
COPY go.mod go.sum ./

# Download Go modules
RUN go mod download

# Remove Git credentials to prevent them from being cached in image layers
RUN git config --global --unset url."https://${GITHUB_TOKEN}@github.com/".insteadOf

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
