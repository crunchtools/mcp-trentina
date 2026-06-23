NAME = cockpit-trentina
VERSION = 0.2.2
COCKPIT_DIR = /usr/share/cockpit/$(NAME)
DBUS_DIR = /usr/share/dbus-1/system.d

install-cockpit:
	install -d $(DESTDIR)$(COCKPIT_DIR)
	install -m 644 cockpit-trentina/manifest.json $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-trentina/index.html $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-trentina/trentina.js $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-trentina/trentina.css $(DESTDIR)$(COCKPIT_DIR)/

install-dbus:
	install -d $(DESTDIR)$(DBUS_DIR)
	install -m 644 dbus/com.crunchtools.Airlock1.conf $(DESTDIR)$(DBUS_DIR)/

install: install-cockpit install-dbus

dev-link:
	ln -sfn $(CURDIR)/cockpit-trentina $(DESTDIR)$(COCKPIT_DIR)

# RPM build targets
tarball:
	mkdir -p dist
	tar czf dist/$(NAME)-$(VERSION).tar.gz \
		--transform='s,^,$(NAME)-$(VERSION)/,' \
		cockpit-trentina/ dbus/ Makefile cockpit-trentina.spec

srpm: tarball
	rpmbuild -bs \
		--define "_sourcedir $(CURDIR)/dist" \
		--define "_srcrpmdir $(CURDIR)/dist" \
		cockpit-trentina.spec

rpm: tarball
	rpmbuild -ba \
		--define "_sourcedir $(CURDIR)/dist" \
		--define "_srcrpmdir $(CURDIR)/dist" \
		--define "_rpmdir $(CURDIR)/dist" \
		--define "_builddir $(CURDIR)/dist/build" \
		--define "_buildrootdir $(CURDIR)/dist/buildroot" \
		cockpit-trentina.spec

clean:
	rm -rf dist/
