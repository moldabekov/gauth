lint:
	# format go source code ('s'implify, 'l'ist, and 'w'rite)
	@# goimports can't "simplify", so we run gofmt _and_ goimports, there's a golang ticket open for that
	@# https://github.com/golang/go/issues/21476
	gofmt -s -l -w .

	golangci-lint run
	# cleanup modules
	go mod tidy

test:
	go test ./...

compile:
	go build -o build/_output/bin/gauth .
	chmod +x build/_output/bin/gauth

build: compile test lint

