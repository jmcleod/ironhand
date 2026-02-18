.PHONY: build test test-postgres vet run clean docker

build:
	go build -o bin/ironhand ./cmd/ironhand

test:
	go test ./... -count=1

test-postgres:
	docker compose -f docker-compose.test.yml up -d --wait
	IRONHAND_TEST_POSTGRES_DSN="postgres://ironhand:testpass@localhost:5433/ironhand_test?sslmode=disable" \
		go test ./storage/postgres/... -count=1 -v
	docker compose -f docker-compose.test.yml down

vet:
	go vet ./...

run: build
	./bin/ironhand server --port 8080

clean:
	rm -rf bin/

docker:
	docker build -t ironhand .
