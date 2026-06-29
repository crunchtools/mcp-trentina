# Cockpit Plugin

Trentina includes a Cockpit plugin that provides a live web dashboard for monitoring the defense pipeline. Layer status, blocklist entries, and pipeline events are displayed in real time through the Cockpit web console — the same interface sysadmins already use to manage RHEL systems.

## Why This Matters

CLI tools and log files work for debugging, but they don't give you a persistent, at-a-glance view of what your defense pipeline is doing. The Cockpit plugin shows you layer health, active detections, and blocklist state without switching context or running queries. It's the operational dashboard for Trentina.

## What It Shows

### Layer Status

Real-time status of each defense layer:

- **Layer 1 (Sanitize)** — active/unavailable
- **Layer 2 (Classifier)** — active/unavailable, with the loaded model path
- **Layer 3 (Q-Agent)** — active/unavailable, with the configured model name

Each layer shows a green "Active" or orange "Unavailable" badge so you can immediately see if something is down.

### Blocklist Summary

Current blocklist state with:

- Total blocked sources
- Breakdown by risk level (critical / high)
- Recent detections with source URL/path, detection timestamp, and risk level

### Live Pipeline Events

A scrolling table of defense pipeline events as they happen:

- Source URL or file path
- Detection scores from each layer
- Risk level classification
- Timestamp

Click any event row to see the full detection details including which layers fired and what they found.

## Architecture

The plugin connects to Trentina's D-Bus interface (`com.crunchtools.Trentina1`) on the system bus. Cockpit's built-in `cockpit.dbus()` API handles the connection — no additional dependencies needed.

```
┌─────────────────┐         D-Bus          ┌─────────────────┐
│  Cockpit Web UI  │ ◄──────────────────── │    Trentina     │
│  (browser)       │   com.crunchtools     │    (systemd)    │
│                  │   .Trentina1           │                 │
│  PatternFly 6    │                       │  Events ring    │
│  No React        │                       │  buffer         │
└─────────────────┘                       └─────────────────┘
```

The plugin is vanilla JavaScript with PatternFly 6 CSS — no React, no build step, no node_modules. It renders directly from D-Bus signals using Cockpit's standard proxy API.

## Installation

The plugin lives in `cockpit-trentina/` and installs to Cockpit's plugin directory:

```bash
# Copy to Cockpit plugin path
sudo cp -r cockpit-trentina /usr/share/cockpit/trentina

# Or install via RPM spec
rpmbuild -ba cockpit-trentina.spec
```

Once installed, the "Trentina" item appears in Cockpit's "Tools" menu on the next page load. No Cockpit restart needed.

### Files

| File | Purpose |
|------|---------|
| `cockpit-trentina/manifest.json` | Cockpit plugin metadata — menu label, keywords |
| `cockpit-trentina/index.html` | Entry point — loads PatternFly CSS and plugin JS |
| `cockpit-trentina/trentina.js` | All plugin logic — D-Bus connection, rendering, event handling |
| `cockpit-trentina/trentina.css` | Custom styles (score bars, layout) |
| `cockpit-trentina.spec` | RPM spec for packaging |

## Requirements

- Cockpit installed and running on the host
- Trentina running as a systemd service (for D-Bus availability)
- PatternFly 6 CSS (ships with Cockpit on RHEL 10+)

## Related

- [Defense Pipeline](defense-pipeline.md) — the layers the plugin monitors
- [Blocklist](blocklist.md) — detection memory shown in the blocklist card
- [Audit Log](audit-log.md) — programmatic access to the same data via `quarantine_stats`
