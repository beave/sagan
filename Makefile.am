AUTOMAKE_OPIONS=foreign no-dependencies
SUBDIRS = src

INCLUDES = @INCLUDES@

# Install BFD include file, and others that it needs.
#install-data-local: 
#	@$(NORMAL_INSTALL)
#	$(mkinstalldirs) $(sysconfdir)
#	$(INSTALL_DATA)sagan.conf $(sysconfdir)/sagan.conf

install-data-local:
	test -z "$(DESTDIR)$(sysconfdir)" || /bin/mkdir -p "$(DESTDIR)$(sysconfdir)"
	test -f "$(DESTDIR)$(sysconfdir)/sagan.conf" || $(INSTALL_DATA) etc/sagan.conf "$(DESTDIR)$(sysconfdir)/sagan.conf"
	test -z "$(DESTDIR)$(sbindir)" || /bin/mkdir -p "$(DESTDIR)$(sbindir)"
	$(INSTALL) -d "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 644 etc/sagan.8 "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 755 src/sagan "$(DESTDIR)$(sbindir)/sagan"
	$(INSTALL) -d "$(DESTDIR)/var/log/sagan"
	$(INSTALL) -d "$(DESTDIR)/var/run/sagan"
	@echo ""
	@echo "------------------------------------------------------------------------------"
	@echo "Sagan has been installed! You still need to do a few more things before your"
	@echo "up and running.  For more information, see:"
	@echo "https://wiki.quadrantsec.com/twiki/bin/view/Main/SaganInstall"
	@echo "------------------------------------------------------------------------------"
	@echo ""



