BINARY_NAME  = zrecon
BUILD_DIR    = bin
INSTALL_PATH = /usr/local/bin/$(BINARY_NAME)
MODULE       = github.com/ZIAD_USERNAME/zrecon

.PHONY: build install uninstall test race clean fmt vet tidy

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)
	@echo "Installed: $(INSTALL_PATH)"

uninstall:
	rm -f $(INSTALL_PATH)
	@echo "Removed: $(INSTALL_PATH)"

test:
	go test ./...

race:
	go test -race ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BUILD_DIR)

all: fmt vet tidy test build
