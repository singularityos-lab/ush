BINARY_USH     := ush
BINARY_BROKER  := ush-broker
INSTALL_DIR    := $(HOME)/.local/bin
SYSTEMD_DIR    := $(HOME)/.config/systemd/user

VERSION        := 0.1.0
LDFLAGS        := -X github.com/singularityos-lab/ush/internal/config.AppVersion=$(VERSION)

.PHONY: all build build-shim build-ush build-broker install uninstall test redteam test-dsh clean fmt vet kill

all: build

build: build-shim build-ush build-broker

CC ?= cc
SHIM_SRC := internal/preload/csrc/ush-chown-shim.c
SHIM_SO  := internal/preload/ush-chown-shim.so

build-shim:
	@echo "-> build LD_PRELOAD shim"
	@$(CC) -shared -fPIC -O2 -o $(SHIM_SO) $(SHIM_SRC)

build-ush:
	@echo "-> build ush"
	@go build -ldflags "$(LDFLAGS)" -o $(BINARY_USH) ./cmd/ush

build-broker:
	@echo "-> build ush-broker"
	@go build -ldflags "$(LDFLAGS)" -o $(BINARY_BROKER) ./cmd/ush-broker

install: build
	@echo "-> install binaries to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@install -m 755 $(BINARY_USH) $(INSTALL_DIR)/$(BINARY_USH)
	@install -m 755 $(BINARY_BROKER) $(INSTALL_DIR)/$(BINARY_BROKER)
	@echo "  link dsh (developer profile) to ush"
	@ln -sf $(BINARY_USH) $(INSTALL_DIR)/dsh
	@echo "  install prebuilt LD_PRELOAD shim to $(INSTALL_DIR)/../lib/ush"
	@mkdir -p $(INSTALL_DIR)/../lib/ush
	@install -m 644 $(SHIM_SO) $(INSTALL_DIR)/../lib/ush/ush-chown-shim.so
	@echo "-> install systemd unit to $(SYSTEMD_DIR)"
	@mkdir -p $(SYSTEMD_DIR)
	@install -m 644 systemd/ush-broker.service $(SYSTEMD_DIR)/ush-broker.service
	@echo "-> reloading systemd daemon (--user)"
	@systemctl --user daemon-reload
	@echo "-> enabling and restarting ush-broker.service (--user)"
	@systemctl --user enable ush-broker.service
	@systemctl --user restart ush-broker.service
	@echo "OK USH installed and broker service is active"

uninstall:
	@echo "-> stopping and disabling ush-broker.service"
	@systemctl --user stop ush-broker.service 2>/dev/null || true
	@systemctl --user disable ush-broker.service 2>/dev/null || true
	@echo "-> removing binaries and service unit"
	@rm -f $(INSTALL_DIR)/$(BINARY_USH) $(INSTALL_DIR)/$(BINARY_BROKER)
	@rm -f $(SYSTEMD_DIR)/ush-broker.service
	@systemctl --user daemon-reload
	@echo "OK removed"

test:
	@echo "-> test"
	@go test ./...

# Adversarial end-to-end harness: drives ush non-interactively and answers
# broker prompts via AUTO mode, replaying breach scenarios. See test/redteam.
redteam: build
	@bash test/redteam/run.sh

# Nested-container smoke test for the dsh developer profile. Must run inside a
# dsh session (podman/distrobox live there).
test-dsh:
	@dsh -c "bash $(CURDIR)/test/dsh/podman-test.sh"

kill:
	@echo "-> killing ush processes"
	@systemctl --user stop ush-broker.service 2>/dev/null || true
	@pkill -TERM -x $(BINARY_USH) 2>/dev/null || true
	@pkill -TERM -x $(BINARY_BROKER) 2>/dev/null || true
	@sleep 1
	@pkill -KILL -x $(BINARY_USH) 2>/dev/null || true
	@pkill -KILL -x $(BINARY_BROKER) 2>/dev/null || true
	@echo "OK killed"

clean:
	@rm -f $(BINARY_USH) $(BINARY_BROKER)

fmt:
	@gofmt -w .

vet:
	@go vet ./...
