#!/usr/bin/env bash
set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR"

export PATH="/opt/homebrew/opt/go@1.22/bin:$PATH"
go build -o bin/server server/main.go
