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
grep -Fq '@$(SIZE) httpd' "$httpd_make"
grep -Fq 'cp httpd $(TOP)/dbgshare/' "$httpd_make"
grep -Fq 'rust-install: rust-relink' "$httpd_make"
grep -Fq 'httpd-rust-install' "$repack_make"
grep -Fq 'source_mode="$$(stat -c '\''%a'\'' "$$source_file")"' "$repack_make"
grep -Fq 'install -D -m "$$source_mode" "$$source_file" "$$target_file"' "$repack_make"
grep -Fq -- '-rmdir \' "$repack_make"
grep -Fq '$(PROFILE_DIR)/fs.install/rom/rom/modules' "$repack_make"
grep -Fq '$(PROFILE_DIR)/fs.install/rom/rom/scripts' "$repack_make"

if sed -n '/^rust-relink:/,/^rust-install:/p' "$httpd_make" |
	grep -Eq '\$\((SIZECHECK|CPTMP)\)'; then
	echo 'rust relink must not use automatic-target macros for the phony target' >&2
	exit 1
fi

if grep -Eq '(^|[[:space:]])httpd-install([[:space:]]|$)' "$repack_make"; then
	echo 'rust-fast must not enter the generic httpd install target' >&2
	exit 1
fi
