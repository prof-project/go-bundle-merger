#!/bin/bash
cd "$(dirname "$0")"

export DOCKER_HOST="$(docker context inspect --format '{{ .Endpoints.docker.Host }}')"
kurtosis run --enclave prof-test github.com/ethpandaops/ethereum-package --args-file ./network_params.yaml
