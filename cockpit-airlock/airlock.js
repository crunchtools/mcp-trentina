/*
 * cockpit-airlock — Cockpit plugin for mcp-airlock-crunchtools
 *
 * Connects to com.crunchtools.Airlock1 on the system D-Bus.
 * Three tabs: "Pipeline Events", "Blocklist", "Trust".
 * Detail views for events and blocklist entries.
 */

(function () {
    "use strict";

    var IFACE = "com.crunchtools.Airlock1";
    var PATH = "/com/crunchtools/Airlock1";
    var client = cockpit.dbus(IFACE, { bus: "system" });
    var allEvents = [];
    var currentView = "list"; /* "list", "blocklist", "trust", or "detail" */
    var activeTab = "events"; /* "events", "blocklist", or "trust" */

    /* -- Dark mode — sync with Cockpit shell theme -- */

    function applyTheme() {
        var pref = localStorage.getItem("shell:style") || "auto";
        var dark = pref === "dark" ||
            (pref === "auto" && window.matchMedia &&
             window.matchMedia("(prefers-color-scheme: dark)").matches);
        if (dark)
            document.documentElement.classList.add("pf-v6-theme-dark");
        else
            document.documentElement.classList.remove("pf-v6-theme-dark");
    }

    applyTheme();
    window.addEventListener("storage", function (e) {
        if (e.key === "shell:style") applyTheme();
    });
    if (window.matchMedia)
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);

    /* -- Helpers -- */

    function dbusCall(method, args) {
        return client.call(PATH, IFACE, method, args || []);
    }

    function badge(text, color) {
        return '<span class="pf-v6-c-label pf-m-compact pf-m-' + color + '">' +
            '<span class="pf-v6-c-label__content">' + escHtml(text) + '</span></span>';
    }

    function riskColor(level) {
        if (level === "critical" || level === "high") return "red";
        if (level === "medium") return "orange";
        return "green";
    }

    function trustColor(level) {
        if (level === "quarantined") return "blue";
        if (level === "sanitized-only" || level === "scan") return "cyan";
        if (level === "trusted-sanitized") return "green";
        return "grey";
    }

    function escHtml(s) {
        if (!s) return "";
        return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function formatTime(ts) {
        if (!ts) return "";
        var d = new Date(ts * 1000);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function formatDate(ts) {
        if (!ts) return "";
        var d = new Date(ts * 1000);
        return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" }) + ", " + formatTime(ts);
    }

    function formatIsoDate(isoStr) {
        if (!isoStr) return "";
        var d = new Date(isoStr);
        if (isNaN(d.getTime())) return escHtml(isoStr);
        return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" }) + ", " +
            d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function truncate(s, max) {
        if (!s) return "";
        max = max || 50;
        return s.length <= max ? s : s.substring(0, max - 1) + "\u2026";
    }

    function scoreBar(score) {
        if (score === null || score === undefined) return "";
        var pct = Math.round(score * 100);
        var color = pct > 50 ? "#c9190b" : pct > 20 ? "#f0ab00" : "#3e8635";
        return '<div class="airlock-score-bar">' +
            '<div class="airlock-score-fill" style="width:' + pct + '%;background:' + color + '"></div>' +
            '<span class="airlock-score-text">' + pct + '%</span></div>';
    }

    function humanKey(key) {
        return key.replace(/^(html|unicode|encoded|exfiltration|delimiters|directives)_/, "")
            .replace(/_/g, " ");
    }

    function dlGroup(label, value) {
        return '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term"><span class="pf-v6-c-description-list__text">' + escHtml(label) + '</span></dt>' +
            '<dd class="pf-v6-c-description-list__description"><div class="pf-v6-c-description-list__text">' + value + '</div></dd></div>';
    }

    /* -- Tab Bar -- */

    function renderTabBar() {
        return '<div class="airlock-tabs">' +
            '<button class="airlock-tab' + (activeTab === "events" ? " active" : "") + '" data-tab="events">Pipeline Events</button>' +
            '<button class="airlock-tab' + (activeTab === "blocklist" ? " active" : "") + '" data-tab="blocklist">Blocklist</button>' +
            '<button class="airlock-tab' + (activeTab === "trust" ? " active" : "") + '" data-tab="trust">Trust</button>' +
            '</div>';
    }

    function bindTabClicks() {
        var tabs = document.querySelectorAll(".airlock-tab");
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener("click", function () {
                var tab = this.getAttribute("data-tab");
                if (tab === activeTab) return;
                activeTab = tab;
                if (tab === "events") {
                    renderListView();
                    loadSummary();
                } else if (tab === "blocklist") {
                    renderBlocklistView();
                } else if (tab === "trust") {
                    renderTrustView();
                }
            });
        }
    }

    /* -- Common page header + tabs -- */

    function pageHeader() {
        return '<div class="pf-v6-c-page">' +
            '<div class="pf-v6-c-page__main-container">' +
            '<main class="pf-v6-c-page__main">' +

            /* Title */
            '<section class="pf-v6-c-page__main-section">' +
            '<div class="pf-v6-c-content"><h1>Airlock Defense Pipeline</h1></div>' +
            '</section>' +

            /* Summary bar */
            '<section class="pf-v6-c-page__main-section pf-m-light airlock-summary-bar">' +
            '<div id="summary-bar">Loading...</div>' +
            '</section>' +

            /* Alert area */
            '<div id="alert-area"></div>' +

            /* Tabs */
            '<section class="pf-v6-c-page__main-section airlock-tab-section">' +
            renderTabBar() +
            '</section>';
    }

    function pageFooter() {
        return '</main></div></div>';
    }

    /* -- List View -- */

    function renderListView() {
        currentView = "list";
        activeTab = "events";
        document.getElementById("app").innerHTML =
            pageHeader() +

            /* Events table */
            '<section class="pf-v6-c-page__main-section pf-m-no-padding" id="tab-content">' +
            '<table class="pf-v6-c-table pf-m-grid-md" role="grid">' +
            '<thead><tr role="row">' +
            '<th role="columnheader" class="pf-v6-c-table__th">Tool</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Source</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Mode</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Risk</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">L1</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">L2</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">L3</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Time</th>' +
            '</tr></thead>' +
            '<tbody id="events-tbody" role="rowgroup"></tbody>' +
            '</table>' +
            '<div id="empty-state" class="airlock-empty">No events yet. Use airlock tools to see pipeline activity.</div>' +
            '</section>' +

            pageFooter();

        bindTabClicks();
        renderEvents();
    }

    function renderEvents() {
        var tbody = document.getElementById("events-tbody");
        var empty = document.getElementById("empty-state");
        if (!tbody) return;

        tbody.innerHTML = "";
        if (empty) empty.style.display = allEvents.length === 0 ? "" : "none";

        /* Newest first */
        for (var i = allEvents.length - 1; i >= 0; i--) {
            addEventRow(tbody, allEvents[i], i);
        }
    }

    function addEventRow(tbody, ev, idx) {
        var d = ev.data || {};
        var tr = document.createElement("tr");
        tr.role = "row";
        tr.className = "pf-v6-c-table__tr airlock-event-row";

        var detections = d.l1_detections || 0;
        var l1Text = detections > 0
            ? '<span class="airlock-col-warn">' + detections + ' found</span>'
            : '<span class="airlock-muted">0</span>';

        var l2Text = d.l2_label
            ? '<span class="' + (d.l2_label === "MALICIOUS" ? "airlock-col-warn" : "airlock-col-ok") + '">' +
              escHtml(d.l2_label) + '</span>'
            : '<span class="airlock-muted">\u2014</span>';

        var l3Text;
        if (d.l3_injection_detected === true) {
            l3Text = '<span class="airlock-col-warn">' + escHtml(d.l3_confidence || "detected") + '</span>';
        } else if (d.l3_model) {
            l3Text = '<span class="airlock-col-ok">clean</span>';
        } else {
            l3Text = '<span class="airlock-muted">\u2014</span>';
        }

        tr.innerHTML =
            '<td class="pf-v6-c-table__td" data-label="Tool"><a class="airlock-tool-link">' + escHtml(d.tool) + '</a></td>' +
            '<td class="pf-v6-c-table__td" data-label="Source" title="' + escHtml(d.source) + '">' + escHtml(truncate(d.source, 45)) + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Mode">' + (d.trust_level ? badge(d.trust_level, trustColor(d.trust_level)) : '') + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Risk">' + (d.risk_level ? badge(d.risk_level, riskColor(d.risk_level)) : '') + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="L1">' + l1Text + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="L2">' + l2Text + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="L3">' + l3Text + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Time">' + formatDate(ev.timestamp) + '</td>';

        tr.addEventListener("click", function () { showDetail(idx); });
        tbody.appendChild(tr);
    }

    /* -- Blocklist View -- */

    function renderBlocklistView() {
        currentView = "blocklist";
        activeTab = "blocklist";
        document.getElementById("app").innerHTML =
            pageHeader() +

            /* Blocklist table */
            '<section class="pf-v6-c-page__main-section pf-m-no-padding" id="tab-content">' +
            '<table class="pf-v6-c-table pf-m-grid-md" role="grid">' +
            '<thead><tr role="row">' +
            '<th role="columnheader" class="pf-v6-c-table__th">Source</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Type</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Domain</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Risk</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Detected At</th>' +
            '</tr></thead>' +
            '<tbody id="blocklist-tbody" role="rowgroup"></tbody>' +
            '</table>' +
            '<div id="blocklist-empty" class="airlock-empty">No blocklist entries. Sources flagged by the pipeline will appear here.</div>' +
            '</section>' +

            pageFooter();

        bindTabClicks();
        loadSummary();
        loadBlocklist();
    }

    function loadBlocklist() {
        dbusCall("GetBlocklist").then(function (result) {
            var rows;
            try { rows = JSON.parse(result[0]); } catch (e) { rows = []; }

            var tbody = document.getElementById("blocklist-tbody");
            var empty = document.getElementById("blocklist-empty");
            if (!tbody) return;

            tbody.innerHTML = "";
            if (empty) empty.style.display = rows.length === 0 ? "" : "none";

            for (var i = 0; i < rows.length; i++) {
                addBlocklistRow(tbody, rows[i]);
            }
        }).catch(function (err) {
            console.error("GetBlocklist failed:", err);
        });
    }

    function addBlocklistRow(tbody, entry) {
        var tr = document.createElement("tr");
        tr.role = "row";
        tr.className = "pf-v6-c-table__tr airlock-event-row";

        tr.innerHTML =
            '<td class="pf-v6-c-table__td" data-label="Source" title="' + escHtml(entry.source) + '">' +
            '<a class="airlock-tool-link">' + escHtml(truncate(entry.source, 55)) + '</a></td>' +
            '<td class="pf-v6-c-table__td" data-label="Type">' + escHtml(entry.source_type) + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Domain">' + escHtml(entry.domain || "\u2014") + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Risk">' + badge(entry.risk_level, riskColor(entry.risk_level)) + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Detected At">' + formatIsoDate(entry.detected_at) + '</td>';

        tr.addEventListener("click", function () { showBlocklistDetail(entry); });
        tbody.appendChild(tr);
    }

    function showBlocklistDetail(entry) {
        currentView = "detail";
        var l1Stats = {};
        try { l1Stats = JSON.parse(entry.layer1_stats || "{}"); } catch (e) { /* ignore */ }
        var qagent = {};
        try { qagent = JSON.parse(entry.qagent_assessment || "{}"); } catch (e) { /* ignore */ }

        /* L1 stats summary */
        var l1Items = [];
        for (var key in l1Stats) {
            if (l1Stats[key] > 0) {
                l1Items.push(l1Stats[key] + " " + humanKey(key));
            }
        }
        var l1Summary = l1Items.length > 0
            ? '<span class="airlock-col-warn">' + l1Items.join(", ") + '</span>'
            : '<span class="airlock-col-ok">Clean</span>';

        /* Q-Agent summary */
        var qSummary;
        if (qagent.injection_detected) {
            qSummary = '<span class="airlock-col-warn">Injection detected</span>' +
                (qagent.confidence ? ' (' + escHtml(qagent.confidence) + ')' : '') +
                (qagent.risk_level ? ' &mdash; ' + badge(qagent.risk_level, riskColor(qagent.risk_level)) : '');
        } else if (qagent.classifier_label) {
            qSummary = '<span class="' + (qagent.classifier_label === "MALICIOUS" ? "airlock-col-warn" : "airlock-col-ok") + '">' +
                escHtml(qagent.classifier_label) + '</span>';
            if (qagent.classifier_score != null) qSummary += " " + scoreBar(qagent.classifier_score);
        } else if (qagent.blocked_by === "p-agent") {
            qSummary = '<span class="airlock-col-warn">Blocked by P-Agent</span>';
        } else {
            qSummary = '<span class="airlock-muted">n/a</span>';
        }

        var html =
            '<div class="pf-v6-c-page">' +
            '<div class="pf-v6-c-page__main-container">' +
            '<main class="pf-v6-c-page__main">' +

            /* Breadcrumb */
            '<section class="pf-v6-c-page__main-breadcrumb">' +
            '<nav class="pf-v6-c-breadcrumb">' +
            '<ol class="pf-v6-c-breadcrumb__list">' +
            '<li class="pf-v6-c-breadcrumb__item">' +
            '<a class="pf-v6-c-breadcrumb__link" id="breadcrumb-back">Blocklist</a>' +
            '</li>' +
            '<li class="pf-v6-c-breadcrumb__item">' +
            '<span class="pf-v6-c-breadcrumb__item-divider"> &rsaquo; </span>' +
            '<span>Detection #' + entry.id + '</span>' +
            '</li>' +
            '</ol></nav></section>' +

            /* Title */
            '<section class="pf-v6-c-page__main-section airlock-detail-header">' +
            '<div class="pf-v6-c-content"><h1>Blocked: ' + escHtml(entry.source_type) + '</h1></div>' +
            '<div class="airlock-detail-meta">' +
            '<code class="airlock-source-full">' + escHtml(entry.source) + '</code>' +
            ' &nbsp; ' + badge(entry.risk_level, riskColor(entry.risk_level)) +
            (entry.domain ? ' &nbsp; Domain: ' + escHtml(entry.domain) : '') +
            ' &nbsp; ' + formatIsoDate(entry.detected_at) +
            '</div></section>' +

            /* Detection details */
            '<section class="pf-v6-c-page__main-section pf-m-light airlock-detail-compact">' +
            '<dl class="pf-v6-c-description-list pf-m-horizontal pf-m-compact">' +
            dlGroup("L1 Stats", l1Summary) +
            dlGroup("Q-Agent Assessment", qSummary) +
            '</dl></section>' +

            '</main></div></div>';

        document.getElementById("app").innerHTML = html;

        document.getElementById("breadcrumb-back").addEventListener("click", function () {
            renderBlocklistView();
        });
    }

    /* -- Trust View -- */

    function renderTrustView() {
        currentView = "trust";
        activeTab = "trust";
        document.getElementById("app").innerHTML =
            pageHeader() +

            /* Trust toolbar */
            '<section class="pf-v6-c-page__main-section airlock-trust-toolbar">' +
            '<div class="airlock-trust-add">' +
            '<input type="text" id="trust-domain-input" class="pf-v6-c-form-control" placeholder="example.com" />' +
            '<button class="pf-v6-c-button pf-m-primary pf-m-small" id="trust-add-btn">Add Domain</button>' +
            '</div>' +
            '<div class="airlock-trust-actions">' +
            '<button class="pf-v6-c-button pf-m-secondary pf-m-small" id="trust-import-btn">Import JSON</button>' +
            '<button class="pf-v6-c-button pf-m-secondary pf-m-small" id="trust-export-btn">Export JSON</button>' +
            '</div>' +
            '</section>' +

            /* Trust table */
            '<section class="pf-v6-c-page__main-section pf-m-no-padding" id="tab-content">' +
            '<div id="trust-count" class="airlock-trust-count"></div>' +
            '<table class="pf-v6-c-table pf-m-grid-md" role="grid">' +
            '<thead><tr role="row">' +
            '<th role="columnheader" class="pf-v6-c-table__th">Domain</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Added</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Source</th>' +
            '<th role="columnheader" class="pf-v6-c-table__th">Actions</th>' +
            '</tr></thead>' +
            '<tbody id="trust-tbody" role="rowgroup"></tbody>' +
            '</table>' +
            '<div id="trust-empty" class="airlock-empty">No trusted domains. Add domains to skip L3 extraction costs.</div>' +
            '</section>' +

            /* Hidden file input for import */
            '<input type="file" id="trust-file-input" accept=".json" style="display:none" />' +

            pageFooter();

        bindTabClicks();
        loadSummary();
        loadTrustedDomains();
        bindTrustActions();
    }

    function loadTrustedDomains() {
        dbusCall("GetTrustedDomains").then(function (result) {
            var domains;
            try { domains = JSON.parse(result[0]); } catch (e) { domains = []; }

            var tbody = document.getElementById("trust-tbody");
            var empty = document.getElementById("trust-empty");
            var countEl = document.getElementById("trust-count");
            if (!tbody) return;

            tbody.innerHTML = "";
            if (empty) {
                empty.style.display = domains.length === 0 ? "" : "none";
                empty.textContent = "No trusted domains. Add domains to skip L3 extraction costs.";
            }
            if (countEl) countEl.textContent = domains.length + " trusted domain" + (domains.length !== 1 ? "s" : "");

            for (var i = 0; i < domains.length; i++) {
                addTrustRow(tbody, domains[i]);
            }
        }).catch(function (err) {
            console.error("GetTrustedDomains failed:", err);
            /* Show upgrade notice — the D-Bus service is too old */
            var empty = document.getElementById("trust-empty");
            if (empty) {
                empty.style.display = "";
                empty.innerHTML =
                    badge("Service Upgrade Required", "orange") +
                    '<p style="margin-top:8px">The Airlock service does not support trust management yet. ' +
                    'Rebuild and restart the container to enable this feature.</p>';
            }
            var countEl = document.getElementById("trust-count");
            if (countEl) countEl.textContent = "";
            /* Disable the toolbar buttons */
            var addBtn = document.getElementById("trust-add-btn");
            var importBtn = document.getElementById("trust-import-btn");
            var exportBtn = document.getElementById("trust-export-btn");
            if (addBtn) addBtn.disabled = true;
            if (importBtn) importBtn.disabled = true;
            if (exportBtn) exportBtn.disabled = true;
        });
    }

    function addTrustRow(tbody, entry) {
        var tr = document.createElement("tr");
        tr.role = "row";
        tr.className = "pf-v6-c-table__tr";

        tr.innerHTML =
            '<td class="pf-v6-c-table__td" data-label="Domain"><code>' + escHtml(entry.domain) + '</code></td>' +
            '<td class="pf-v6-c-table__td" data-label="Added">' + formatIsoDate(entry.added_at) + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Source">' + badge(entry.source, entry.source === "json-seed" ? "blue" : "grey") + '</td>' +
            '<td class="pf-v6-c-table__td" data-label="Actions">' +
            '<button class="pf-v6-c-button pf-m-danger pf-m-small airlock-trust-remove" data-domain="' + escHtml(entry.domain) + '">Remove</button>' +
            '</td>';

        tbody.appendChild(tr);

        tr.querySelector(".airlock-trust-remove").addEventListener("click", function (e) {
            e.stopPropagation();
            var domain = this.getAttribute("data-domain");
            dbusCall("RemoveTrustedDomain", [domain]).then(function () {
                loadTrustedDomains();
                loadSummary();
            }).catch(function (err) {
                console.error("RemoveTrustedDomain failed:", err);
            });
        });
    }

    function bindTrustActions() {
        /* Add domain */
        var addBtn = document.getElementById("trust-add-btn");
        var addInput = document.getElementById("trust-domain-input");
        if (addBtn && addInput) {
            addBtn.addEventListener("click", function () {
                var domain = addInput.value.trim();
                if (!domain) return;
                dbusCall("AddTrustedDomain", [domain]).then(function () {
                    addInput.value = "";
                    loadTrustedDomains();
                    loadSummary();
                }).catch(function (err) {
                    console.error("AddTrustedDomain failed:", err);
                });
            });
            addInput.addEventListener("keydown", function (e) {
                if (e.key === "Enter") addBtn.click();
            });
        }

        /* Import */
        var importBtn = document.getElementById("trust-import-btn");
        var fileInput = document.getElementById("trust-file-input");
        if (importBtn && fileInput) {
            importBtn.addEventListener("click", function () {
                fileInput.click();
            });
            fileInput.addEventListener("change", function () {
                var file = fileInput.files[0];
                if (!file) return;
                var reader = new FileReader();
                reader.onload = function (e) {
                    dbusCall("ImportTrustedDomains", [e.target.result]).then(function (result) {
                        var r;
                        try { r = JSON.parse(result[0]); } catch (ex) { r = {}; }
                        loadTrustedDomains();
                        loadSummary();
                        if (r.added != null) {
                            alert("Imported " + r.added + " new domains (of " + r.total + " total).");
                        }
                    }).catch(function (err) {
                        console.error("ImportTrustedDomains failed:", err);
                        alert("Import failed: " + err);
                    });
                    fileInput.value = "";
                };
                reader.readAsText(file);
            });
        }

        /* Export */
        var exportBtn = document.getElementById("trust-export-btn");
        if (exportBtn) {
            exportBtn.addEventListener("click", function () {
                dbusCall("ExportTrustedDomains").then(function (result) {
                    var blob = new Blob([result[0]], { type: "application/json" });
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement("a");
                    a.href = url;
                    a.download = "airlock-trusted-domains.json";
                    a.click();
                    URL.revokeObjectURL(url);
                }).catch(function (err) {
                    console.error("ExportTrustedDomains failed:", err);
                });
            });
        }
    }

    /* -- Detail View -- */

    function pipelineCard(label, statusHtml, bodyHtml) {
        return '<div class="airlock-pipeline-card">' +
            '<div class="airlock-pipeline-card-header">' +
            '<span class="airlock-pipeline-card-label">' + escHtml(label) + '</span>' +
            '<span class="airlock-pipeline-card-status">' + statusHtml + '</span>' +
            '</div>' +
            '<div class="airlock-pipeline-card-body">' + bodyHtml + '</div>' +
            '</div>';
    }

    function showDetail(idx) {
        var ev = allEvents[idx];
        if (!ev) return;

        currentView = "detail";
        var d = ev.data || {};
        var stats = d.stats || {};

        var toolName = d.tool || "Event";
        var eventId = d.event_id || "";

        /* Collect attack vectors */
        var attackTypes = [];
        for (var key in stats) {
            if (stats[key] > 0) {
                attackTypes.push({ key: key, label: humanKey(key), count: stats[key] });
            }
        }

        /* Size info */
        var inSize = d.input_size || 0;
        var outSize = d.output_size || 0;
        var reduction = inSize > 0 ? Math.round((1 - outSize / inSize) * 100) : 0;
        var l3TextLen = d.l3_extracted_text ? d.l3_extracted_text.length : 0;
        var l3Compression = outSize > 0 && l3TextLen > 0 ? Math.round((l3TextLen / outSize) * 100) : 0;

        /* --- Raw Input card --- */
        var rawBody = d.raw_content
            ? '<pre class="airlock-payload">' + escHtml(d.raw_content) + '</pre>'
            : '<span class="airlock-muted">No raw content captured</span>';
        var rawStatus = '<span class="airlock-muted">' + inSize.toLocaleString() + ' bytes</span>';

        /* --- L1 Filtered card --- */
        var l1Status = attackTypes.length > 0
            ? '<span class="airlock-col-warn">' + attackTypes.map(function(a) { return a.count + " " + a.label; }).join(", ") + '</span>'
            : '<span class="airlock-col-ok">Clean</span>';
        if (reduction > 0) {
            l1Status += ' <span class="airlock-muted">' + reduction + '% stripped</span>';
        }
        var l1Body = d.sanitized_content
            ? '<pre class="airlock-payload">' + escHtml(d.sanitized_content) + '</pre>'
            : '<span class="airlock-muted">No filtered content captured</span>';

        /* --- L2 Response card --- */
        var l2Status;
        if (d.l2_label) {
            l2Status = (d.l2_label === "MALICIOUS" ? '<span class="airlock-col-warn">' : '<span class="airlock-col-ok">') +
                escHtml(d.l2_label) + '</span>';
        } else {
            l2Status = '<span class="airlock-muted">Not run</span>';
        }
        var l2Body = '';
        if (d.l2_label) {
            l2Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Verdict:</span> ' +
                (d.l2_label === "MALICIOUS" ? '<span class="airlock-col-warn">' : '<span class="airlock-col-ok">') +
                escHtml(d.l2_label) + '</span></div>';
            if (d.l2_score != null) {
                l2Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Score:</span> ' +
                    scoreBar(d.l2_score) + '</div>';
            }
            l2Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Model:</span> Prompt Guard 2</div>';
        } else {
            l2Body = '<span class="airlock-muted">Classifier not available</span>';
        }

        /* --- L3 Analysis card --- */
        var trustLvl = d.trust_level || "";
        var l3Status;
        if (d.l3_model) {
            if (d.l3_injection_detected) {
                l3Status = '<span class="airlock-col-warn">Injection</span>';
            } else {
                l3Status = '<span class="airlock-col-ok">Clean</span>';
            }
        } else if (trustLvl === "trusted-sanitized") {
            l3Status = '<span class="airlock-muted">Skipped</span>';
        } else if (trustLvl === "scan") {
            l3Status = '<span class="airlock-muted">N/A</span>';
        } else {
            l3Status = '<span class="airlock-muted">Not run</span>';
        }
        var l3Body = '';
        if (d.l3_model) {
            l3Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Model:</span> ' + escHtml(d.l3_model) + '</div>';
            if (d.l3_injection_detected != null) {
                l3Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Injection:</span> ' +
                    (d.l3_injection_detected
                        ? '<span class="airlock-col-warn">Detected</span>'
                        : '<span class="airlock-col-ok">None</span>') + '</div>';
            }
            if (d.l3_confidence) {
                l3Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Confidence:</span> ' +
                    escHtml(d.l3_confidence) + '</div>';
            }
            if (d.l3_input_tokens || d.l3_output_tokens) {
                l3Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Tokens:</span> ' +
                    (d.l3_input_tokens ? d.l3_input_tokens.toLocaleString() + ' in' : '') +
                    (d.l3_input_tokens && d.l3_output_tokens ? ' / ' : '') +
                    (d.l3_output_tokens ? d.l3_output_tokens.toLocaleString() + ' out' : '') +
                    '</div>';
            }
            if (l3TextLen > 0 && outSize > 0) {
                l3Body += '<div class="airlock-pipeline-detail-row"><span class="airlock-muted">Output:</span> ' +
                    l3TextLen.toLocaleString() + ' chars (' + l3Compression + '% of L1 input)</div>';
            }
            if (d.l3_extracted_text) {
                l3Body += '<pre class="airlock-payload">' + escHtml(d.l3_extracted_text) + '</pre>';
            }
        } else if (trustLvl === "trusted-sanitized") {
            l3Body = '<span class="airlock-muted">Skipped for trusted domain</span>';
        } else if (toolName === "search") {
            l3Body = '<span class="airlock-muted">Not used (search pipeline is L0 \u2192 L1 \u2192 L2)</span>';
        } else if (trustLvl === "scan") {
            l3Body = '<span class="airlock-muted">Detection scan passed (no threats found)</span>';
        } else {
            l3Body = '<span class="airlock-muted">Q-Agent not available</span>';
        }

        var html =
            '<div class="pf-v6-c-page">' +
            '<div class="pf-v6-c-page__main-container">' +
            '<main class="pf-v6-c-page__main">' +

            /* Breadcrumb */
            '<section class="pf-v6-c-page__main-breadcrumb">' +
            '<nav class="pf-v6-c-breadcrumb">' +
            '<ol class="pf-v6-c-breadcrumb__list">' +
            '<li class="pf-v6-c-breadcrumb__item">' +
            '<a class="pf-v6-c-breadcrumb__link" id="breadcrumb-back">Pipeline Events</a>' +
            '</li>' +
            '<li class="pf-v6-c-breadcrumb__item">' +
            '<span class="pf-v6-c-breadcrumb__item-divider"> &rsaquo; </span>' +
            '<span>' + escHtml(toolName) + '</span>' +
            '</li>' +
            '</ol></nav></section>' +

            /* Header — tool name + structured metadata */
            '<section class="pf-v6-c-page__main-section airlock-detail-header">' +
            '<div class="pf-v6-c-content"><h1>' + escHtml(toolName) + '</h1></div>' +
            '<div class="airlock-detail-meta-grid">' +
            '<div class="airlock-meta-row">' +
            '<span class="airlock-meta-label">Source</span>' +
            '<code class="airlock-source-full">' + escHtml(d.source) + '</code>' +
            '</div>' +
            '<div class="airlock-meta-row">' +
            '<span class="airlock-meta-label">Mode</span>' +
            (d.trust_level ? badge(d.trust_level, trustColor(d.trust_level)) : '<span class="airlock-muted">unknown</span>') +
            '</div>' +
            '<div class="airlock-meta-row">' +
            '<span class="airlock-meta-label">Risk</span>' +
            (d.risk_level ? badge(d.risk_level, riskColor(d.risk_level)) : '<span class="airlock-muted">unknown</span>') +
            '</div>' +
            '<div class="airlock-meta-row">' +
            '<span class="airlock-meta-label">Time</span>' +
            '<span>' + formatDate(ev.timestamp) +
            (d.duration_ms ? ' (' + d.duration_ms + ' ms)' : '') + '</span>' +
            '</div>' +
            (eventId ? '<div class="airlock-meta-row">' +
            '<span class="airlock-meta-label">Event ID</span>' +
            '<code class="airlock-event-id">' + escHtml(eventId) + '</code>' +
            '</div>' : '') +
            '</div>' +
            '</section>' +

            /* Pipeline Analysis — stage-by-stage flow with metrics */
            '<section class="pf-v6-c-page__main-section">' +
            '<div class="pf-v6-c-content"><h2>Pipeline Analysis</h2></div>' +
            '</section>' +
            '<section class="pf-v6-c-page__main-section pf-m-light airlock-detail-compact">' +
            '<div class="airlock-analysis-flow">' +
            '<div class="airlock-analysis-stage">' +
            '<span class="airlock-analysis-label">Raw Input</span>' +
            '<span class="airlock-analysis-value">' + inSize.toLocaleString() + ' chars</span>' +
            '</div>' +
            '<div class="airlock-analysis-arrow">\u2192</div>' +
            '<div class="airlock-analysis-stage">' +
            '<span class="airlock-analysis-label">L1 Sanitized</span>' +
            '<span class="airlock-analysis-value">' + outSize.toLocaleString() + ' chars</span>' +
            (reduction > 0 ? '<span class="airlock-analysis-delta">\u2212' + reduction + '%</span>' : '') +
            '</div>' +
            '<div class="airlock-analysis-arrow">\u2192</div>' +
            '<div class="airlock-analysis-stage">' +
            '<span class="airlock-analysis-label">L2 Classifier</span>' +
            '<span class="airlock-analysis-value">' + (d.l2_label ? escHtml(d.l2_label) + (d.l2_score != null ? ' (' + Math.round(d.l2_score * 100) + '%)' : '') : '\u2014') + '</span>' +
            '</div>' +
            (d.l3_model ? (
            '<div class="airlock-analysis-arrow">\u2192</div>' +
            '<div class="airlock-analysis-stage">' +
            '<span class="airlock-analysis-label">L3 Q-Agent</span>' +
            '<span class="airlock-analysis-value">' + l3TextLen.toLocaleString() + ' chars</span>' +
            (l3Compression > 0 ? '<span class="airlock-analysis-delta">' + l3Compression + '% of L1</span>' : '') +
            '</div>'
            ) : '') +
            '</div>' +
            /* Metrics row under the flow */
            '<div class="airlock-analysis-metrics">' +
            '<span class="airlock-analysis-metric">' +
            '<span class="airlock-muted">Duration:</span> ' + (d.duration_ms || 0) + ' ms</span>' +
            (d.l3_input_tokens ? '<span class="airlock-analysis-metric"><span class="airlock-muted">L3 Input:</span> ' + d.l3_input_tokens.toLocaleString() + ' tokens</span>' : '') +
            (d.l3_output_tokens ? '<span class="airlock-analysis-metric"><span class="airlock-muted">L3 Output:</span> ' + d.l3_output_tokens.toLocaleString() + ' tokens</span>' : '') +
            (d.l3_model && l3Compression > 0 ? '<span class="airlock-analysis-metric"><span class="airlock-muted">Compression:</span> ' +
            inSize.toLocaleString() + ' \u2192 ' + l3TextLen.toLocaleString() + ' chars (' + (inSize > 0 ? Math.round((l3TextLen / inSize) * 100) : 0) + '% of raw)</span>' : '') +
            '</div>' +
            '</section>' +

            /* Pipeline stages — 4 equal cards in a 2x2 grid */
            '<section class="pf-v6-c-page__main-section">' +
            '<div class="pf-v6-c-content"><h2>Pipeline Detail</h2></div>' +
            '</section>' +
            '<section class="pf-v6-c-page__main-section pf-m-light airlock-detail-compact">' +
            '<div class="airlock-pipeline-grid">' +
            pipelineCard("Raw Input", rawStatus, rawBody) +
            pipelineCard("L1 Filtered", l1Status, l1Body) +
            pipelineCard("L2 Response", l2Status, l2Body) +
            pipelineCard("L3 Analysis", l3Status, l3Body) +
            '</div>' +
            '</section>' +

            '</main></div></div>';

        document.getElementById("app").innerHTML = html;

        document.getElementById("breadcrumb-back").addEventListener("click", function () {
            renderListView();
            loadSummary();
        });
    }

    /* -- Detection Alerts -- */

    function showDetectionAlert(layer, source, severity, detailsJson) {
        var area = document.getElementById("alert-area");
        if (!area) return;

        var details = {};
        try { details = JSON.parse(detailsJson || "{}"); } catch(e) { /* ignore */ }

        var el = document.createElement("div");
        el.className = "pf-v6-c-alert pf-m-danger pf-m-inline airlock-alert";
        el.innerHTML =
            '<div class="pf-v6-c-alert__icon"><i class="pficon pficon-error-circle-o"></i></div>' +
            '<p class="pf-v6-c-alert__title"><strong>Injection Detected</strong></p>' +
            '<div class="pf-v6-c-alert__description">' +
            badge(layer, "red") + ' flagged ' +
            '<code>' + escHtml(truncate(source, 60)) + '</code> as ' +
            badge(severity.toUpperCase(), riskColor(severity)) +
            '</div>';

        area.insertBefore(el, area.firstChild);
        setTimeout(function () {
            if (el.parentNode) { el.style.opacity = "0"; setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 300); }
        }, 20000);
    }

    /* -- D-Bus -- */

    function layerCard(label, name, active) {
        return '<div class="airlock-layer-card">' +
            '<span class="airlock-layer-card-label">' + escHtml(label) + '</span>' +
            '<span class="airlock-layer-card-name">' + escHtml(name) + '</span>' +
            '<span class="airlock-layer-card-status ' + (active ? "active" : "unavail") + '">' +
            (active ? "Active" : "Unavailable") + '</span></div>';
    }

    function statItem(label, value) {
        return '<span class="airlock-stat-item">' + escHtml(label) + ': ' +
            '<span class="airlock-stat-value">' + escHtml(String(value)) + '</span></span>';
    }

    function loadSummary() {
        /* Each D-Bus call resolves independently so one missing method
         * (e.g. older service without GetTrustedDomains) doesn't kill
         * the entire summary bar. */
        var layersP = dbusCall("GetLayerStatus").catch(function() { return [null]; });
        var statsP = dbusCall("GetStats").catch(function() { return [null]; });
        /* GetTrustedDomains may not exist on older services — fall back
         * to GetTrustConfig (always available) for the count. */
        var trustP = dbusCall("GetTrustedDomains").catch(function() {
            return dbusCall("GetTrustConfig").then(function(r) {
                /* Convert JSON config to domain-count-compatible array */
                try {
                    var cfg = JSON.parse(r[0]);
                    var domains = cfg.trusted_domains || [];
                    return [JSON.stringify(domains.map(function(d) { return { domain: d }; }))];
                } catch(e) { return ["[]"]; }
            }).catch(function() { return ["[]"]; });
        });

        Promise.all([layersP, statsP, trustP]).then(function(results) {
            var layers, stats, trustedDomains;
            try { layers = results[0][0] ? JSON.parse(results[0][0]) : null; } catch(e) { layers = null; }
            try { stats = results[1][0] ? JSON.parse(results[1][0]) : null; } catch(e) { stats = null; }
            try { trustedDomains = JSON.parse(results[2][0]); } catch(e) { trustedDomains = []; }

            var el = document.getElementById("summary-bar");
            if (!el) return;

            var html = "";

            /* Layer cards */
            if (layers) {
                var l2Model = (layers.l2_classifier && layers.l2_classifier.model) || "Prompt Guard 2";
                var l3Model = (layers.l3_qagent && layers.l3_qagent.model) || "Unknown";
                var pAgent = (stats && stats.p_agent) || "Unknown";

                html += '<div class="airlock-layer-cards">';
                html += layerCard("L1", "Python Sanitizer", layers.l1_sanitize.active);
                html += layerCard("L2", l2Model, layers.l2_classifier.active);
                html += layerCard("L3", l3Model, layers.l3_qagent.active);
                html += '<div class="airlock-layer-card">' +
                    '<span class="airlock-layer-card-label">P-Agent</span>' +
                    '<span class="airlock-layer-card-name">' + escHtml(pAgent) + '</span>' +
                    '<span class="airlock-layer-card-status active">Connected</span></div>';
                html += '</div>';
            }

            /* Stats row */
            var blockedCount = (stats && stats.blocklist) ? (stats.blocklist.total_blocked || 0) : 0;
            var trustedCount = trustedDomains ? trustedDomains.length : 0;

            /* Detection rate: events with any detection / total events */
            var totalEvents = allEvents.length;
            var detectedEvents = 0;
            for (var i = 0; i < allEvents.length; i++) {
                var d = allEvents[i].data || {};
                if ((d.l1_detections && d.l1_detections > 0) ||
                    d.l2_label === "MALICIOUS" ||
                    d.l3_injection_detected === true) {
                    detectedEvents++;
                }
            }
            var detectionRate = totalEvents > 0 ? Math.round((detectedEvents / totalEvents) * 100) : 0;

            html += '<div class="airlock-stats-row">';
            html += statItem("Tool Usage", totalEvents);
            html += statItem("Blocked", blockedCount);
            html += statItem("Trusted", trustedCount);
            html += statItem("Detection", detectionRate + "%");
            html += '</div>';

            el.innerHTML = html;
        });
    }

    function loadEvents() {
        dbusCall("GetRecentEvents", [100]).then(function(result) {
            try {
                var raw = JSON.parse(result[0]);
                allEvents = raw.filter(function(e) { return e.event === "request_processed"; });
            } catch(e) {
                allEvents = [];
            }
            if (currentView === "list") renderEvents();
        }).catch(function(err) {
            console.error("GetRecentEvents failed:", err);
        });
    }

    function setupSignals() {
        client.subscribe(
            { interface: IFACE },
            function(_path, _iface, signal, args) {
                if (signal === "RequestProcessed") {
                    /* Signal is a notification — reload full data from SQLite
                     * so all fields (L2, L3, content, etc.) are populated */
                    loadEvents();
                    if (currentView === "list" || currentView === "trust") loadSummary();
                } else if (signal === "DetectionOccurred") {
                    /* args: layer, source, severity, details_json, event_id, p_agent_name */
                    showDetectionAlert(args[0], args[1], args[2], args[3]);
                }
            }
        );
    }

    /* -- Init -- */

    function init() {
        renderListView();
        loadSummary();
        loadEvents();
        setupSignals();

        /* Periodic summary refresh */
        setInterval(function() {
            if (currentView === "list" || currentView === "blocklist" || currentView === "trust") loadSummary();
        }, 30000);
    }

    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", init);
    else
        init();
})();
