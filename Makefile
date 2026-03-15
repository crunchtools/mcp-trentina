NAME = cockpit-airlock
VERSION = 0.2.0
COCKPIT_DIR = /usr/share/cockpit/$(NAME)
DBUS_DIR = /usr/share/dbus-1/system.d

install-cockpit:
	install -d $(DESTDIR)$(COCKPIT_DIR)
	install -m 644 cockpit-airlock/manifest.json $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-airlock/index.html $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-airlock/airlock.js $(DESTDIR)$(COCKPIT_DIR)/
	install -m 644 cockpit-airlock/airlock.css $(DESTDIR)$(COCKPIT_DIR)/

install-dbus:
	install -d $(DESTDIR)$(DBUS_DIR)
	install -m 644 dbus/com.crunchtools.Airlock1.conf $(DESTDIR)$(DBUS_DIR)/

install: install-cockpit install-dbus

dev-link:
	ln -sfn $(CURDIR)/cockpit-airlock $(DESTDIR)$(COCKPIT_DIR)

# RPM build targets
tarball:
	mkdir -p dist
	tar czf dist/$(NAME)-$(VERSION).tar.gz \
		--transform='s,^,$(NAME)-$(VERSION)/,' \
		cockpit-airlock/ dbus/ Makefile cockpit-airlock.spec

srpm: tarball
	rpmbuild -bs \
		--define "_sourcedir $(CURDIR)/dist" \
		--define "_srcrpmdir $(CURDIR)/dist" \
		cockpit-airlock.spec

rpm: tarball
	rpmbuild -ba \
		--define "_sourcedir $(CURDIR)/dist" \
		--define "_srcrpmdir $(CURDIR)/dist" \
		--define "_rpmdir $(CURDIR)/dist" \
		cockpit-airlock.spec

clean:
	rm -rf dist/
