all:
	@echo "This is a dummy to prevent running make without explicit target!"

build:
	go mod tidy
	$(MAKE) -C cmd/ _build

rebuild: build

run:
	$(MAKE) -C cmd/ _run

docker-build:
	./build.sh

docker-run:
	docker run --rm -it -p 50051:50051 --name go-bundle-merger-container bundle_merger

profenv-start:
	$(MAKE) -C test/ _profenv-start

profenv-stop:
	$(MAKE) -C test/ _profenv-stop
