EXEC =blockfinder

install: all
	test -d $(DESTDIR)/usr/bin/ || mkdir -p $(DESTDIR)/usr/bin/
	cp $(EXEC) $(DESTDIR)/usr/bin/

uninstall: all
	rm $(DESTDIR)/usr/bin/$(EXEC)

deb-src:
	dpkg-buildpackage -S -rfakeroot -us -uc

deb:
	dpkg-buildpackage -rfakeroot -us -uc

deb-clean:
	-rm build
	debian/rules clean
