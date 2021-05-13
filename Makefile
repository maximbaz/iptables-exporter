BIN := iptables-exporter
VERSION = 1.0.0

.PHONY: release
release: build
	rm -rf dist
	mkdir -p dist
	cp "target/release/$(BIN)" "dist/$(BIN)-$(VERSION)"
	git archive -o "dist/$(BIN)-$(VERSION).tar.gz" --format tar.gz --prefix "$(BIN)-$(VERSION)/" "$(VERSION)"
	for file in dist/*; do gpg --detach-sign --armor "$$file"; done
	rm "dist/$(BIN)-$(VERSION).tar.gz"

.PHONY: build
build:
	cargo build --release --locked
