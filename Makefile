build: build-wasm get-wasm
build-tinygo: build-tinygo-wasm get-tinygo-wasm run-server

GOROOT := $(shell dirname $(shell dirname $(shell which go)))

get-wasm:
	@echo "Using GOROOT: $(GOROOT)"
	rm -rf ./static/wasm_exec.js && cp $(GOROOT)/lib/wasm/wasm_exec.js ./static/

build-wasm:
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o static/fetch.wasm ./client/frontend/

run-server:
	go run ./server

get-tinygo-wasm:
	rm -rf ./static/wasm_exec.js && cp $$(tinygo env TINYGOROOT)/targets/wasm_exec.js ./static/

build-tinygo-wasm:
	tinygo build -o static/fetch.wasm -target wasm -opt=z -no-debug ./client/frontend/
