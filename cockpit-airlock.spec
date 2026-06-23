Name:           cockpit-airlock
Version:        0.2.2
Release:        1%{?dist}
Summary:        Cockpit plugin for MCP Airlock defense pipeline visualization
License:        AGPL-3.0-or-later
URL:            https://github.com/crunchtools/mcp-trentina
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       cockpit-bridge >= 300
Requires:       cockpit-system >= 300

%description
Cockpit plugin that visualizes the MCP Airlock three-layer defense pipeline
(L1 sanitization, L2 Prompt Guard 2 classifier, L3 Gemini Q-Agent) in real
time via the com.crunchtools.Airlock1 D-Bus interface.

Displays layer status, blocklist stats, live pipeline events, and per-request
detail breakdowns in the Cockpit Tools sidebar.

%prep
%setup -q

%install
install -d %{buildroot}%{_datadir}/cockpit/%{name}
install -m 644 cockpit-airlock/manifest.json %{buildroot}%{_datadir}/cockpit/%{name}/
install -m 644 cockpit-airlock/index.html %{buildroot}%{_datadir}/cockpit/%{name}/
install -m 644 cockpit-airlock/airlock.js %{buildroot}%{_datadir}/cockpit/%{name}/
install -m 644 cockpit-airlock/airlock.css %{buildroot}%{_datadir}/cockpit/%{name}/

install -d %{buildroot}%{_datadir}/dbus-1/system.d
install -m 644 dbus/com.crunchtools.Airlock1.conf %{buildroot}%{_datadir}/dbus-1/system.d/

%files
%{_datadir}/cockpit/%{name}/
%{_datadir}/dbus-1/system.d/com.crunchtools.Airlock1.conf

%changelog
* Sat Mar 15 2026 Scott McCarty <scott@crunchtools.com> - 0.2.0-1
- Initial package: Cockpit plugin + D-Bus policy for MCP Airlock
