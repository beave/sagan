AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

#INCLUDES = @INCLUDES@

# Install BFD include file, and others that it needs.
#install-data-local: 
#	@$(NORMAL_INSTALL)
#	$(mkinstalldirs) $(sysconfdir)
#	$(INSTALL_DATA)sagan.conf $(sysconfdir)/sagan.yaml

install-data-local:
	test -z "$(DESTDIR)$(sysconfdir)" || /bin/mkdir -p "$(DESTDIR)$(sysconfdir)"
	test -f "$(DESTDIR)$(sysconfdir)/sagan.yaml" || $(INSTALL_DATA) etc/sagan.yaml "$(DESTDIR)$(sysconfdir)/sagan.yaml"
	test -z "$(DESTDIR)$(bindir)" || /bin/mkdir -p "$(DESTDIR)$(bindir)"
	$(INSTALL) -d "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 644 etc/sagan.8 "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 755 src/sagan "$(DESTDIR)$(bindir)/sagan"
	$(INSTALL) -d "$(DESTDIR)/var/log/sagan"
	$(INSTALL) -d "$(DESTDIR)/var/run/sagan"
	@echo ""
	@echo "------------------------------------------------------------------------------"
	@echo "Sagan has been installed! You still need to do a few more things before your"
	@echo "up and running.  For more information, see https://sagan.readthedocs.io"
	@echo "------------------------------------------------------------------------------"
	@echo ""


