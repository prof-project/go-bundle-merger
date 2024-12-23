#!/bin/bash
cd "$(dirname "$0")"

export PATH="/opt/homebrew/opt/go@1.22/bin:$PATH"
go build -o bin/server server/main.go
