#!/bin/sh
set -eu

source_root=${1:?source root required}
overlay_root=${2:?overlay root required}
router_make="$source_root/release/src/router/Makefile"
httpd_make="$source_root/release/src/router/httpd/Makefile"
repack_make="$overlay_root/rust-repack.mk"

grep -Fq 'httpd-rust-install:' "$router_make"
grep -Fq 'INSTALLDIR=$(INSTALLDIR)/httpd rust-install' "$router_make"
grep -Fq 'rust-relink: $(RUST_HTTPD_LIB)' "$httpd_make"
grep -Fq 'Missing cached httpd object' "$httpd_make"
grep -Fq 'rust-install: rust-relink' "$httpd_make"
grep -Fq 'httpd-rust-install' "$repack_make"

if grep -Eq '(^|[[:space:]])httpd-install([[:space:]]|$)' "$repack_make"; then
	echo 'rust-fast must not enter the generic httpd install target' >&2
	exit 1
fi
