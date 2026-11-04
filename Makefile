.PHONY: build test vet install clean

BIN=bin/ari-demo

build:
	go build -o $(BIN) ./cmd/ari-demo

test:
	go test -race ./...

vet:
	go vet ./...

install:
	go install ./cmd/ari-demo

clean:
	rm -rf bin _acme
