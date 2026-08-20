.PHONY: rust-components-relink rust-firmware-repack

rust-components-relink:
	+$(MAKE) -C router \
		infosvr-install rstats-install nt_center-install httpd-install rc-install

rust-firmware-repack:
	+$(MAKE) -C router strips
	# Copy the post-strip package artifacts into the flat staging tree used by
	# buildFS, then bind the repack to their exact contents rather than mtimes.
	install -D $(PROFILE_DIR)/fs.install/infosvr/usr/sbin/infosvr \
		$(PROFILE_DIR)/fs.install/usr/sbin/infosvr
	install -D $(PROFILE_DIR)/fs.install/rstats/bin/rstats \
		$(PROFILE_DIR)/fs.install/bin/rstats
	install -D $(PROFILE_DIR)/fs.install/nt_center/usr/sbin/Notify_Event2NC \
		$(PROFILE_DIR)/fs.install/usr/sbin/Notify_Event2NC
	install -D $(PROFILE_DIR)/fs.install/httpd/usr/sbin/httpd \
		$(PROFILE_DIR)/fs.install/usr/sbin/httpd
	install -D $(PROFILE_DIR)/fs.install/rc/sbin/rc \
		$(PROFILE_DIR)/fs.install/sbin/rc
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
