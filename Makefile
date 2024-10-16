all:
	@echo "This is a dummy to prevent running make without explicit target!"

docker-build:
	./build.sh

docker-run:
	docker run --rm -it -p 50051:50051 --name go-bundle-merger-container bundle_merger
