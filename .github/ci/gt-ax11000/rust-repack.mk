.PHONY: rust-components-relink rust-ui-httpd-relink rust-firmware-repack

rust-components-relink:
	+$(MAKE) -C router \
		infosvr-install rstats-install nt_center-install httpd-install rc-install \
		www-install

# Short iteration path for changes confined to the authenticated HTTP boundary
# and its Web UI. Invoking this through the platform Makefile preserves all HND
# exports that a direct `make -C router` call would miss.
rust-ui-httpd-relink:
	+$(MAKE) -C router httpd-install www-install

rust-firmware-repack:
	+$(MAKE) -C router strips
	# Copy the post-strip package artifacts into the flat staging tree used by
	# buildFS, then bind the repack to their exact contents rather than mtimes.
	if [ -f $(PROFILE_DIR)/fs.install/www/www/Advanced_WAdvanced_Content.asp ]; then \
		install -m 0644 \
			$(PROFILE_DIR)/fs.install/www/www/Advanced_WAdvanced_Content.asp \
			$(PROFILE_DIR)/fs.install/www/Advanced_WAdvanced_Content.asp; \
	else \
		test -f $(PROFILE_DIR)/fs.install/www/Advanced_WAdvanced_Content.asp; \
	fi
	# www-install stages a complete package under fs.install/www/www. Once its
	# selected page is promoted above, retaining that package directory would
	# duplicate the whole Web UI as /www/www in the firmware rootfs.
	rm -rf $(PROFILE_DIR)/fs.install/www/www
	promote_artifact() { \
		source_file="$$1"; target_file="$$2"; \
		if [ -f "$$source_file" ]; then \
			install -D "$$source_file" "$$target_file"; \
		else \
			test -f "$$target_file"; \
		fi; \
	}; \
	promote_artifact $(PROFILE_DIR)/fs.install/infosvr/usr/sbin/infosvr \
		$(PROFILE_DIR)/fs.install/usr/sbin/infosvr; \
	promote_artifact $(PROFILE_DIR)/fs.install/rstats/bin/rstats \
		$(PROFILE_DIR)/fs.install/bin/rstats; \
	promote_artifact $(PROFILE_DIR)/fs.install/nt_center/usr/sbin/Notify_Event2NC \
		$(PROFILE_DIR)/fs.install/usr/sbin/Notify_Event2NC; \
	promote_artifact $(PROFILE_DIR)/fs.install/httpd/usr/sbin/httpd \
		$(PROFILE_DIR)/fs.install/usr/sbin/httpd; \
	promote_artifact $(PROFILE_DIR)/fs.install/rc/sbin/rc \
		$(PROFILE_DIR)/fs.install/sbin/rc
	# Package install targets stage their complete payload below a package-named
	# directory. The five selected artifacts have now been promoted into the
	# flat firmware tree, so remove only those known duplicate staging roots.
	rm -rf \
		$(PROFILE_DIR)/fs.install/infosvr \
		$(PROFILE_DIR)/fs.install/rstats \
		$(PROFILE_DIR)/fs.install/nt_center \
		$(PROFILE_DIR)/fs.install/httpd \
		$(PROFILE_DIR)/fs.install/rc
	cd $(PROFILE_DIR)/fs.install; sha256sum \
		usr/sbin/infosvr \
		bin/rstats \
		usr/sbin/Notify_Event2NC \
		usr/sbin/httpd \
		sbin/rc > $(RUST_CONSUMER_MANIFEST)
	cd $(TARGETS_DIR); ./buildFS
	cd $(TARGETS_DIR); ./buildFS2
	+$(MAKE) buildimage_final
	rm -f $(PROFILE_DIR)/*cferom*
