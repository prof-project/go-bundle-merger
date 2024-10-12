Implementation of the PROF bundle merger service.

## Running tests for the bundle-merger

```
cd api
go test -timeout 30s -run ^TestEnrichBlock$ -v  
```

## Running the bundle-merger inside an AWS Nitro Enclave

Build the bundle-merger image:

```
./build.sh
```

Build the enclave image and run it:

```
sudo nitro-cli build-enclave --docker-uri bundle_merger --output-file bundle-merger-enclave.eif
sudo nitro-cli run-enclave --eif-path bundle-merger-enclave.eif --memory 2000 --cpu-count 2 --enclave-cid 16 --debug-mode
```

Check the enclave terminal
```
sudo nitro-cli console --enclave-id <enclave-id>
```

Now, one needs to run the client. For this, we need to run Socat to Forward TCP to VSOCK (Note that the enclave-cid might be different depending on the configuration).
```
sudo socat TCP-LISTEN:50051,reuseaddr,fork VSOCK-CONNECT:16:50051
```