Implementation of the PROF bundle merger service.

## Building the bundle merger gRPC spec in /profpb 

```
make
```

## Running tests

```
cd api
go test -timeout 30s -run ^TestEnrichBlock$ -v  
```