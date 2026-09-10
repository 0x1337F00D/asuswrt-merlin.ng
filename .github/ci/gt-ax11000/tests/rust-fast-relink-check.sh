#!/bin/sh
set -eu

source_root=${1:?source root required}
overlay_root=${2:?overlay root required}
router_make="$source_root/release/src/router/Makefile"
httpd_make="$source_root/release/src/router/httpd/Makefile"
repack_make="$overlay_root/rust-repack.mk"

# The shared install target rebuilds all, not just a cached copy. Every new
# Rust consumer must also be promoted and included in the image manifest.
grep -Fq '$(MAKE) -C router shared-install' "$repack_make"
grep -Eq '^install:.*all' "$source_root/release/src/router/shared/Makefile"
grep -Fq '$(PROFILE_DIR)/fs.install/shared/usr/lib/libshared.so' "$repack_make"
grep -Fq 'usr/lib/libshared.so' "$overlay_root/build.sh"
grep -Fq 'usr/lib/libshared.so' "$repack_make"

grep -Fq 'httpd-rust-install:' "$router_make"
grep -Fq 'INSTALLDIR=$(INSTALLDIR)/httpd rust-install' "$router_make"
grep -Fq 'rust-relink: $(RUST_HTTPD_LIB)' "$httpd_make"
grep -Fq 'Missing cached httpd object' "$httpd_make"
grep -Fq '@$(SIZE) httpd' "$httpd_make"
grep -Fq 'cp httpd $(TOP)/dbgshare/' "$httpd_make"
grep -Fq 'rust-install: rust-relink' "$httpd_make"
grep -Fq 'httpd-rust-install' "$repack_make"
grep -Fq 'httpd-ui-c-rebuild:' "$repack_make"
grep -Fq 'rc-c-rebuild:' "$repack_make"
grep -Fq 'networkmap-rust-compat-rebuild:' "$repack_make"
grep -Fq '$(MAKE) -C router httpd-install' "$repack_make"
grep -Fq '$(MAKE) -C router rc-install' "$repack_make"
grep -Fq '$(MAKE) -C router networkmap-install' "$repack_make"
# libz.so.1 is reinstalled, never relinked: consumers bind it by SONAME, so a
# rust-fast build only has to replace the shared object itself.
grep -Fq '$(MAKE) -C router zlib-install' "$repack_make"
grep -Fq '$(PROFILE_DIR)/fs.install/zlib/usr/lib/libz.so.1' "$repack_make"
grep -Fq 'usr/sbin/lld2d > $(RUST_CONSUMER_MANIFEST)' "$repack_make"
# The LLTD responder is a standalone package, so rust-fast relinks it the
# same way it relinks infosvr rather than carrying the previous binary.
grep -Fq '$(MAKE) -C router lltd.arm-install' "$repack_make"
grep -Fq '$(PROFILE_DIR)/fs.install/lltd.arm/usr/sbin/lld2d' "$repack_make"
grep -Fq 'zlib-install: $(RUST_ZLIB_SHARED_DEPS)' "$router_make"
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

if sed -n '/^rust-ui-httpd-relink:/,/^httpd-ui-c-rebuild:/p' "$repack_make" |
	grep -Eq '(^|[[:space:]])httpd-install([[:space:]]|$)'; then
	echo 'rust-fast must not enter the generic httpd install target' >&2
	exit 1
fi
