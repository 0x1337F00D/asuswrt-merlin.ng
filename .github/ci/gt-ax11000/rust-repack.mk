.PHONY: rust-components-relink rust-ui-httpd-relink httpd-ui-c-rebuild rc-c-rebuild networkmap-rust-compat-rebuild rust-firmware-repack

rust-components-relink:
	# shared-install enters shared's install: all, rebuilding the wlif archive
	# and libshared before any dependent consumer is refreshed.
	+$(MAKE) -C router shared-install
	# AUTODICT rewrites the complete compressed Web tree and its dictionaries as
	# one versioned set.  Generate that set before rebuilding httpd consumers.
	+$(MAKE) -C router www-install
	+$(MAKE) -C router \
		infosvr-install rstats-install nt_center-install httpd-rust-install rc-install networkmap-install
	# libz.so.1 is the one Rust artifact nothing has to be relinked against:
	# every consumer resolves it by SONAME at run time, so reinstalling the
	# shared object alone makes a zlib-rs change effective for the whole
	# rootfs.  zlib-install rebuilds the crate and relinks the object.
	+$(MAKE) -C router zlib-install
	# wget's ordinary target rebuilds the Rust archive and refreshes the link.
	+$(MAKE) -C router wget
	+$(MAKE) -C router wget-install

# Short iteration path for changes confined to the authenticated HTTP boundary
# and its Web UI. Invoking this through the platform Makefile preserves all HND
# exports that a direct `make -C router` call would miss.
rust-ui-httpd-relink:
	+$(MAKE) -C router www-install
	+$(MAKE) -C router httpd-rust-install

# Changes to web.c or another C object need the normal package target so Make
# can refresh the affected objects before linking.  Keep that explicit: the
# Rust-only path above intentionally preserves every cached C object.
httpd-ui-c-rebuild:
	+$(MAKE) -C router www-install
	+$(MAKE) -C router httpd
	+$(MAKE) -C router httpd-install

# Preserve the platform exports while refreshing a C change in rc.  A direct
# make -C router invocation lacks the HND platform definitions.
rc-c-rebuild:
	+$(MAKE) -C router rc
	+$(MAKE) -C router rc-install

# Reinstall the prebuilt Network Map together with its proprietary-free Rust
# ABI provider after changing only the compatibility crate.
networkmap-rust-compat-rebuild:
	+$(MAKE) -C router networkmap-install

rust-firmware-repack:
	+$(MAKE) -C router strips
	# A normal full build consumes the generated nested Web tree while creating
	# its first image.  Regenerate the complete AUTODICT set immediately before
	# manifesting/repacking so this finalizer is identical for every build mode.
	+$(MAKE) -C router www-install
	# www-install produces a mutually dependent set of compressed ASP pages and
	# language dictionaries.  Never promote a single page into an older set: the
	# numeric dictionary IDs would render as unrelated words.  Move the complete
	# generated tree aside, validate its release-critical files, then replace the
	# old flat tree as one unit before buildFS observes it.
	test -d $(PROFILE_DIR)/fs.install/www/www
	test -s $(PROFILE_DIR)/fs.install/www/www/Advanced_WAdvanced_Content.asp
	test -s $(PROFILE_DIR)/fs.install/www/www/index.asp
	test -s $(PROFILE_DIR)/fs.install/www/www/EN.dict
	test -s $(PROFILE_DIR)/fs.install/www/www/DE.dict
	test ! -e $(PROFILE_DIR)/fs.install/www.generated
	mv $(PROFILE_DIR)/fs.install/www/www \
		$(PROFILE_DIR)/fs.install/www.generated
	rm -rf $(PROFILE_DIR)/fs.install/www
	mv $(PROFILE_DIR)/fs.install/www.generated \
		$(PROFILE_DIR)/fs.install/www
	test ! -e $(PROFILE_DIR)/fs.install/www/www
	# rootprep creates these model-wide links before the first image build.  The
	# atomic WWW replacement above must restore them before manifesting, or all
	# userN.asp links plus PAC/WPAD become dangling at runtime.
	ln -sfn /tmp/var/wwwext $(PROFILE_DIR)/fs.install/www/ext
	ln -sfn /tmp/var/wwwext $(PROFILE_DIR)/fs.install/www/user
	ln -sfn /www/ext/proxy.pac $(PROFILE_DIR)/fs.install/www/proxy.pac
	ln -sfn /www/ext/proxy.pac $(PROFILE_DIR)/fs.install/www/wpad.dat
	cd $(PROFILE_DIR)/fs.install; \
		find www -type f -print0 | sort -z | xargs -0 sha256sum \
			> $(WEB_PAYLOAD_MANIFEST)
	test -s $(WEB_PAYLOAD_MANIFEST)
	cd $(PROFILE_DIR)/fs.install; \
		find www -type l -print0 | sort -z | \
		while IFS= read -r -d '' link; do \
			printf '%s\t%s\n' "$$link" "$$(readlink "$$link")"; \
		done > $(WEB_SYMLINK_MANIFEST)
	test -s $(WEB_SYMLINK_MANIFEST)
	install -D -m 0644 $(WEB_PAYLOAD_MANIFEST) \
		$(PROFILE_DIR)/fs.install/usr/share/codex/web-payload.sha256
	install -D -m 0644 $(WEB_SYMLINK_MANIFEST) \
		$(PROFILE_DIR)/fs.install/usr/share/codex/web-symlinks.manifest
	# Older iterations placed these files under /etc, which is a runtime link to
	# volatile /tmp/etc on this platform.  Never package ambiguous stale copies.
	rm -f \
		$(PROFILE_DIR)/fs.install/etc/codex-web-payload.sha256 \
		$(PROFILE_DIR)/fs.install/etc/codex-web-symlinks.manifest
	promote_artifact() { \
		source_file="$$1"; target_file="$$2"; \
		if [ -f "$$source_file" ]; then \
			test ! -L "$$source_file"; \
			source_mode="$$(stat -c '%a' "$$source_file")"; \
			case "$$source_mode" in ''|*[!0-7]*) exit 1;; esac; \
			install -D -m "$$source_mode" "$$source_file" "$$target_file"; \
			test "$$(stat -c '%a' "$$target_file")" = "$$source_mode"; \
		else \
			test -f "$$target_file"; \
		fi; \
	}; \
	promote_artifact $(PROFILE_DIR)/fs.install/shared/usr/lib/libshared.so \
		$(PROFILE_DIR)/fs.install/usr/lib/libshared.so; \
	promote_artifact $(PROFILE_DIR)/fs.install/infosvr/usr/sbin/infosvr \
		$(PROFILE_DIR)/fs.install/usr/sbin/infosvr; \
	promote_artifact $(PROFILE_DIR)/fs.install/rstats/bin/rstats \
		$(PROFILE_DIR)/fs.install/bin/rstats; \
	promote_artifact $(PROFILE_DIR)/fs.install/nt_center/usr/sbin/Notify_Event2NC \
		$(PROFILE_DIR)/fs.install/usr/sbin/Notify_Event2NC; \
	promote_artifact $(PROFILE_DIR)/fs.install/httpd/usr/sbin/httpd \
		$(PROFILE_DIR)/fs.install/usr/sbin/httpd; \
	promote_artifact $(PROFILE_DIR)/fs.install/rc/sbin/rc \
		$(PROFILE_DIR)/fs.install/sbin/rc; \
	promote_artifact $(PROFILE_DIR)/fs.install/rc/usr/sbin/ntp \
		$(PROFILE_DIR)/fs.install/usr/sbin/ntp; \
	promote_artifact $(PROFILE_DIR)/fs.install/networkmap/usr/sbin/networkmap \
		$(PROFILE_DIR)/fs.install/usr/sbin/networkmap; \
	promote_artifact $(PROFILE_DIR)/fs.install/networkmap/usr/lib/libbwdpi.so \
		$(PROFILE_DIR)/fs.install/usr/lib/libbwdpi.so; \
	promote_artifact $(PROFILE_DIR)/fs.install/wget/usr/sbin/wget \
		$(PROFILE_DIR)/fs.install/usr/sbin/wget; \
	promote_artifact $(PROFILE_DIR)/fs.install/zlib/usr/lib/libz.so.1 \
		$(PROFILE_DIR)/fs.install/usr/lib/libz.so.1
	# Package install targets stage their complete payload below a package-named
	# directory. The selected artifacts have now been promoted into the
	# flat firmware tree, so remove only those known duplicate staging roots.
	rm -rf \
		$(PROFILE_DIR)/fs.install/shared \
		$(PROFILE_DIR)/fs.install/infosvr \
		$(PROFILE_DIR)/fs.install/rstats \
		$(PROFILE_DIR)/fs.install/nt_center \
		$(PROFILE_DIR)/fs.install/httpd \
		$(PROFILE_DIR)/fs.install/rc \
		$(PROFILE_DIR)/fs.install/networkmap \
		$(PROFILE_DIR)/fs.install/wget \
		$(PROFILE_DIR)/fs.install/zlib
	# fsbuild creates these legacy containers for optional external payloads.
	# On GT-AX11000 they are empty; leaving them behind only on a repeated
	# build makes rust-fast rootfs topology differ from the clean reference.
	# rmdir is deliberately fail-soft so a future non-empty vendor payload is
	# preserved and will be exposed by the full-rootfs equivalence gate.
	-rmdir \
		$(PROFILE_DIR)/fs.install/rom/rom/modules \
		$(PROFILE_DIR)/fs.install/rom/rom/scripts \
		$(PROFILE_DIR)/fs.install/rom/rom
	cd $(PROFILE_DIR)/fs.install; sha256sum \
		usr/lib/libshared.so \
		usr/sbin/infosvr \
		bin/rstats \
		usr/sbin/Notify_Event2NC \
		usr/sbin/httpd \
		sbin/rc \
		usr/sbin/ntp \
		usr/sbin/networkmap \
		usr/lib/libbwdpi.so \
		usr/sbin/wget \
		usr/lib/libz.so.1 > $(RUST_CONSUMER_MANIFEST)
	cd $(TARGETS_DIR); ./buildFS
	cd $(TARGETS_DIR); ./buildFS2
	+$(MAKE) buildimage_final
	rm -f $(PROFILE_DIR)/*cferom*
