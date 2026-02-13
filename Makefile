.PHONY: build test vet run clean docker

build:
	go build -o bin/ironhand ./cmd/ironhand

test:
	go test ./... -count=1

vet:
	go vet ./...

run: build
	./bin/ironhand server --port 8080

clean:
	rm -rf bin/

docker:
	docker build -t ironhand -f build/docker/Dockerfile .
