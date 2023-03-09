.PHONY: all build-linux 


UNAME_ARCH = $(shell uname -m)
ARCH = $(lastword $(subst :, ,$(filter $(UNAME_ARCH):%,x86_64:amd64 aarch64:arm64)))


BUILD_MODE ?= -buildmode=pie
build-linux: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w'
build-linux:    ## Build the VPC CNI plugin agent using the host's Go toolchain.
	go build $(BUILD_FLAGS) -o bpf-sdk  ./pkg/elfparser

format:       ## Format all Go source code files.
	@command -v goimports >/dev/null || { echo "ERROR: goimports not installed"; exit 1; }
	@exit $(shell find ./* \
	  -type f \
	  -name '*.go' \
	  -print0 | sort -z | xargs -0 -- goimports $(or $(FORMAT_FLAGS),-w) | wc -l | bc)

# Build BPF
CLANG := clang
CLANG_INCLUDE := -I../../..
EBPF_SOURCE := test/xdp_prog/xdp_fw.c
EBPF_BINARY := test/xdp_prog/xdp_fw.elf
build-bpf: ## Build BPF
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE) -o $(EBPF_BINARY)

##@ Run Unit Tests
# Run unit tests
unit-test: build-bpf
unit-test: export AWS_EBPF_SDK_LOG_FILE=stdout
unit-test:    ## Run unit tests
	go test -v -coverprofile=coverage.txt -covermode=atomic ./pkg/...
