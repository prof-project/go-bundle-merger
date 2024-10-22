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

# TODO: Add support for other environments, currently configured for kurtosis
docker-run:
	docker run --rm -it -e ENVIRONMENT=kurtosis -p 50051:50051 --name prof-merger-container prof-project/prof-merger

profenv-start:
	$(MAKE) -C test/ _profenv-start

profenv-stop:
	$(MAKE) -C test/ _profenv-stop
