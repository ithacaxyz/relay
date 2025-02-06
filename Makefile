# Heavily inspired by Lighthouse: https://github.com/sigp/lighthouse/blob/693886b94176faa4cb450f024696cb69cda2fe58/Makefile
.DEFAULT_GOAL := help

GIT_SHA ?= $(shell git rev-parse HEAD)
GIT_TAG ?= $(shell git describe --tags --abbrev=0)
BIN_DIR = "dist/bin"

CARGO_TARGET_DIR ?= target

# List of features to use when building. Can be overridden via the environment.
FEATURES :=

# Cargo profile for builds. Default is for local builds, CI uses an override.
PROFILE ?= profiling

# Extra flags for Cargo
CARGO_INSTALL_EXTRA_FLAGS ?=

# Other features incrate
BIN_OTHER_FEATURES :=

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: install
install: ## Build and install the relay binary under `~/.cargo/bin`.
	cargo install --bin relay --force --locked \
		--features "$(FEATURES)" \
		--profile "$(PROFILE)" \
		$(CARGO_INSTALL_EXTRA_FLAGS)

.PHONY: build
build: ## Build the relay binary into `target` directory.
	cargo build --bin relay --features "$(FEATURES)" --profile "$(PROFILE)"

# Environment variables for reproducible builds
# Initialize RUSTFLAGS
RUST_BUILD_FLAGS =
# Enable static linking to ensure reproducibility across builds
RUST_BUILD_FLAGS += --C target-feature=+crt-static
# Set the linker to use static libgcc to ensure reproducibility across builds
RUST_BUILD_FLAGS += -Clink-arg=-static-libgcc
# Remove build ID from the binary to ensure reproducibility across builds
RUST_BUILD_FLAGS += -C link-arg=-Wl,--build-id=none
# Remove metadata hash from symbol names to ensure reproducible builds
RUST_BUILD_FLAGS += -C metadata=''
# Set timestamp from last git commit for reproducible builds
SOURCE_DATE ?= $(shell git log -1 --pretty=%ct)
# Disable incremental compilation to avoid non-deterministic artifacts
CARGO_INCREMENTAL_VAL = 0
# Set C locale for consistent string handling and sorting
LOCALE_VAL = C
# Set UTC timezone for consistent time handling across builds
TZ_VAL = UTC

.PHONY: build-reproducible
build-reproducible: ## Build the relay binary into `target` directory with reproducible builds. Only works for x86_64-unknown-linux-gnu currently
	SOURCE_DATE_EPOCH=$(SOURCE_DATE) \
	RUSTFLAGS="${RUST_BUILD_FLAGS} --remap-path-prefix $$(pwd)=." \
	CARGO_INCREMENTAL=${CARGO_INCREMENTAL_VAL} \
	LC_ALL=${LOCALE_VAL} \
	TZ=${TZ_VAL} \
	cargo build --bin relay --features "$(FEATURES)" --profile "release" --locked --target x86_64-unknown-linux-gnu

.PHONY: build-debug
build-debug: ## Build the relay binary into `target/debug` directory.
	cargo build --bin relay --features "$(FEATURES)"

# Builds the relay binary natively.
build-native-%:
	cargo build --bin relay --target $* --features "$(FEATURES)" --profile "$(PROFILE)"

# Note: The additional rustc compiler flags are for intrinsics needed by MDBX.
# See: https://github.com/cross-rs/cross/wiki/FAQ#undefined-reference-with-build-std
build-%:
	cross build --bin relay --target $* --features "$(FEATURES)" --profile "$(PROFILE)"

# Unfortunately we can't easily use cross to build for Darwin because of licensing issues.
# If we wanted to, we would need to build a custom Docker image with the SDK available.
#
# Note: You must set `SDKROOT` and `MACOSX_DEPLOYMENT_TARGET`. These can be found using `xcrun`.
#
# `SDKROOT=$(xcrun -sdk macosx --show-sdk-path) MACOSX_DEPLOYMENT_TARGET=$(xcrun -sdk macosx --show-sdk-platform-version)`
build-x86_64-apple-darwin:
	$(MAKE) build-native-x86_64-apple-darwin
build-aarch64-apple-darwin:
	$(MAKE) build-native-aarch64-apple-darwin

# Create a `.tar.gz` containing a binary for a specific target.
define tarball_release_binary
	cp $(CARGO_TARGET_DIR)/$(1)/$(PROFILE)/$(2) $(BIN_DIR)/$(2)
	cd $(BIN_DIR) && \
		tar -czf relay-$(GIT_TAG)-$(1)$(3).tar.gz $(2) && \
		rm $(2)
endef

# The current git tag will be used as the version in the output file names. You
# will likely need to use `git tag` and create a semver tag (e.g., `v0.2.3`).
#
# Note: This excludes macOS tarballs because of SDK licensing issues.
.PHONY: build-release-tarballs
build-release-tarballs: ## Create a series of `.tar.gz` files in the BIN_DIR directory, each containing a `relay` binary for a different target.
	[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(MAKE) build-x86_64-unknown-linux-gnu
	$(call tarball_release_binary,"x86_64-unknown-linux-gnu","relay","")
	$(MAKE) build-aarch64-unknown-linux-gnu
	$(call tarball_release_binary,"aarch64-unknown-linux-gnu","relay","")

##@ Test

UNIT_TEST_ARGS := --locked --workspace -E 'kind(lib)' -E 'kind(bin)' -E 'kind(proc-macro)'
COV_FILE := lcov.info

.PHONY: test-unit
test-unit: ## Run unit tests.
	cargo install cargo-nextest --locked
	cargo nextest run $(UNIT_TEST_ARGS)

.PHONY: cov-unit
cov-unit: ## Run unit tests with coverage.
	rm -f $(COV_FILE)
	cargo llvm-cov nextest --lcov --output-path $(COV_FILE) $(UNIT_TEST_ARGS)

.PHONY: cov-report-html
cov-report-html: cov-unit ## Generate a HTML coverage report and open it in the browser.
	cargo llvm-cov report --html
	open target/llvm-cov/html/index.html

.PHONY: clean
clean: ## Perform a `cargo` clean and remove the binary and test vectors directories.
	cargo clean
	rm -rf $(BIN_DIR)
	rm -rf $(EF_TESTS_DIR)


.PHONY: profiling
profiling: ## Builds `relay` with optimisations, but also symbols.
	RUSTFLAGS="-C target-cpu=native" cargo build --profile profiling

.PHONY: maxperf
maxperf: ## Builds `relay` with the most aggressive optimisations.
	RUSTFLAGS="-C target-cpu=native" cargo build --profile maxperf

fmt:
	cargo +nightly fmt


lint-codespell: ensure-codespell
	codespell --skip "*.json" --skip "./target/*"

ensure-codespell:
	@if ! command -v codespell &> /dev/null; then \
		echo "codespell not found. Please install it by running the command `pip install codespell` or refer to the following link for more information: https://github.com/codespell-project/codespell" \
		exit 1; \
    fi

CLIPPY_COMMON = cargo +nightly clippy \
	--bin "relay" \
	--examples \
	--tests \
	--benches \

fix-lint:
	$(CLIPPY_COMMON) --fix --allow-staged --allow-dirty -- -D warnings
	make fmt

lint:
	$(CLIPPY_COMMON) -- -D warnings

test:
	cargo test

pr:
	make lint && make test

check-features:
	cargo hack check --feature-powerset
