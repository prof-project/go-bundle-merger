#!/bin/bash
cd "$(dirname "$0")"

export DOCKER_HOST="$(docker context inspect --format '{{ .Endpoints.docker.Host }}')"
kurtosis enclave rm -f prof-test
kurtosis engine stop
