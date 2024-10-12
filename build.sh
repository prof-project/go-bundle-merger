#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

# Load environment variables from .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo ".env file not found. Exiting."
  exit 1
fi

# Check if GITHUB_TOKEN is set
if [ -z "$GITHUB_TOKEN" ]; then
  echo "GITHUB_TOKEN is not set. Exiting."
  exit 1
fi

# Build the Docker image
docker build --build-arg GITHUB_TOKEN="$GITHUB_TOKEN" -t bundle_merger .

