/*
 * cockpit-trentina — Cockpit plugin for mcp-trentina-crunchtools
 *
 * Connects to com.crunchtools.Trentina1 on the system D-Bus and renders
 * live pipeline events using PatternFly 6 CSS classes (no React).
 */

(function () {
    "use strict";

    var client = cockpit.dbus("com.crunchtools.Trentina1", { bus: "system" });
    var airlockObj = client.proxy("com.crunchtools.Trentina1", "/com/crunchtools/Trentina1");

    var maxTableRows = 200;
    var selectedEvent = null;

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#x27;");
    }

    function riskClass(level) {
        switch (level) {
            case "critical": return "pf-m-red";
            case "high": return "pf-m-red";
            case "medium": return "pf-m-orange";
            default: return "pf-m-green";
        }
    }

    function layerBadge(active) {
        if (active)
            return '<span class="pf-v6-c-label pf-m-green pf-m-compact"><span class="pf-v6-c-label__content">Active</span></span>';
        return '<span class="pf-v6-c-label pf-m-orange pf-m-compact"><span class="pf-v6-c-label__content">Unavailable</span></span>';
    }

    function formatTime(ts) {
        if (!ts) return "";
        var d = new Date(ts * 1000);
        return d.toLocaleTimeString();
    }

    function truncateSource(source, maxLen) {
        maxLen = maxLen || 60;
        if (source.length <= maxLen) return source;
        return source.substring(0, maxLen - 3) + "...";
    }

    function scoreBar(score) {
        if (score === null || score === undefined) return "";
        var pct = Math.round(score * 100);
        return '<div class="airlock-score-bar">' +
            '<div class="airlock-score-fill" style="width: ' + pct + '%"></div>' +
            '<span class="airlock-score-text">' + pct + '%</span>' +
            '</div>';
    }

    function renderPage() {
        var html = '<div class="pf-v6-c-page">' +
            '<main class="pf-v6-c-page__main">' +
            '<section class="pf-v6-c-page__main-section">' +
            '<div class="pf-v6-c-content"><h1>Trentina Defense Pipeline</h1></div>' +
            '</section>' +
            '<section class="pf-v6-c-page__main-section pf-m-light">' +
            '<div class="pf-v6-l-grid pf-m-gutter">' +

            /* Layer Status Card */
            '<div class="pf-v6-l-grid__item pf-m-12-col pf-m-6-col-on-lg">' +
            '<div class="pf-v6-c-card" id="layer-status-card">' +
            '<div class="pf-v6-c-card__header"><div class="pf-v6-c-card__header-main">Layer Status</div></div>' +
            '<div class="pf-v6-c-card__body" id="layer-status-body">Loading...</div>' +
            '</div></div>' +

            /* Blocklist Card */
            '<div class="pf-v6-l-grid__item pf-m-12-col pf-m-6-col-on-lg">' +
            '<div class="pf-v6-c-card" id="blocklist-card">' +
            '<div class="pf-v6-c-card__header"><div class="pf-v6-c-card__header-main">Blocklist</div></div>' +
            '<div class="pf-v6-c-card__body" id="blocklist-body">Loading...</div>' +
            '</div></div>' +

            /* Live Events Card */
            '<div class="pf-v6-l-grid__item pf-m-12-col">' +
            '<div class="pf-v6-c-card">' +
            '<div class="pf-v6-c-card__header"><div class="pf-v6-c-card__header-main">Live Pipeline Events</div></div>' +
            '<div class="pf-v6-c-card__body">' +
            '<table class="pf-v6-c-table pf-m-compact pf-m-grid-md" id="events-table">' +
            '<thead><tr>' +
            '<th>Time</th><th>Tool</th><th>Source</th><th>Trust</th><th>Risk</th><th>L1</th><th>L2</th>' +
            '</tr></thead>' +
            '<tbody id="events-tbody"></tbody>' +
            '</table></div></div></div>' +

            /* Detail Card */
            '<div class="pf-v6-l-grid__item pf-m-12-col">' +
            '<div class="pf-v6-c-card" id="detail-card" style="display:none">' +
            '<div class="pf-v6-c-card__header"><div class="pf-v6-c-card__header-main">Pipeline Detail</div></div>' +
            '<div class="pf-v6-c-card__body" id="detail-body"></div>' +
            '</div></div>' +

            '</div></section></main></div>';

        document.body.innerHTML = html;
    }

    function renderLayerStatus(layer_json) {
        var layers = JSON.parse(layer_json);
        var el = document.getElementById("layer-status-body");
        if (!el) return;

        el.innerHTML =
            '<dl class="pf-v6-c-description-list pf-m-horizontal">' +
            '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">L1 Sanitize</dt>' +
            '<dd class="pf-v6-c-description-list__description">' + layerBadge(layers.l1_sanitize.active) + ' ' + escapeHtml(layers.l1_sanitize.description) + '</dd></div>' +
            '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">L2 Classify</dt>' +
            '<dd class="pf-v6-c-description-list__description">' + layerBadge(layers.l2_classifier.active) + ' ' + escapeHtml(layers.l2_classifier.description) + '</dd></div>' +
            '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">L3 Q-Agent</dt>' +
            '<dd class="pf-v6-c-description-list__description">' + layerBadge(layers.l3_qagent.active) + ' ' + escapeHtml(layers.l3_qagent.description) +
            (layers.l3_qagent.model ? ' (' + escapeHtml(layers.l3_qagent.model) + ')' : '') + '</dd></div>' +
            '</dl>';
    }

    function renderStats(stats_json) {
        var info = JSON.parse(stats_json);
        var el = document.getElementById("blocklist-body");
        if (!el) return;

        var bl = info.blocklist;
        var riskParts = [];
        for (var level in bl.by_risk_level) {
            riskParts.push(level + "(" + bl.by_risk_level[level] + ")");
        }
        el.innerHTML =
            '<dl class="pf-v6-c-description-list pf-m-horizontal">' +
            '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">Total blocked</dt>' +
            '<dd class="pf-v6-c-description-list__description">' + bl.total_blocked + '</dd></div>' +
            '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">By risk</dt>' +
            '<dd class="pf-v6-c-description-list__description">' + (riskParts.join(" ") || "none") + '</dd></div>' +
            '</dl>';
    }

    function addEventRow(ev, prepend) {
        var tbody = document.getElementById("events-tbody");
        if (!tbody) return;

        var d = ev.data || ev;
        var tr = document.createElement("tr");
        tr.className = "pf-v6-c-table__tr airlock-event-row";
        tr.dataset.event = JSON.stringify(ev);

        tr.innerHTML =
            '<td class="pf-v6-c-table__td">' + formatTime(ev.timestamp) + '</td>' +
            '<td class="pf-v6-c-table__td"><code>' + escapeHtml(d.tool) + '</code></td>' +
            '<td class="pf-v6-c-table__td" title="' + escapeHtml(d.source) + '">' + escapeHtml(truncateSource(d.source || "")) + '</td>' +
            '<td class="pf-v6-c-table__td"><span class="pf-v6-c-label pf-m-compact ' + riskClass("low") + '"><span class="pf-v6-c-label__content">' + escapeHtml(d.trust_level) + '</span></span></td>' +
            '<td class="pf-v6-c-table__td"><span class="pf-v6-c-label pf-m-compact ' + riskClass(d.risk_level) + '"><span class="pf-v6-c-label__content">' + escapeHtml((d.risk_level || "").toUpperCase()) + '</span></span></td>' +
            '<td class="pf-v6-c-table__td">' + (d.l1_detections || 0) + '</td>' +
            '<td class="pf-v6-c-table__td">' + escapeHtml(d.l2_label || "—") + (d.l2_score !== null && d.l2_score !== undefined ? ' (' + (d.l2_score * 100).toFixed(1) + '%)' : '') + '</td>';

        tr.addEventListener("click", function () {
            selectedEvent = ev;
            renderDetail(ev);
        });

        if (prepend)
            tbody.insertBefore(tr, tbody.firstChild);
        else
            tbody.appendChild(tr);

        /* Trim old rows */
        while (tbody.children.length > maxTableRows)
            tbody.removeChild(tbody.lastChild);
    }

    function renderRecentEvents(events_json) {
        var events = JSON.parse(events_json);
        for (var i = 0; i < events.length; i++) {
            addEventRow(events[i], false);
        }
    }

    function renderDetail(ev) {
        var card = document.getElementById("detail-card");
        var body = document.getElementById("detail-body");
        if (!card || !body) return;

        var d = ev.data || ev;
        var stats = d.stats || {};

        card.style.display = "";

        var html = '<dl class="pf-v6-c-description-list">';

        /* L1 */
        html += '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">L1 Sanitize</dt>' +
            '<dd class="pf-v6-c-description-list__description">';
        for (var key in stats) {
            if (stats[key] > 0) {
                html += '<div>' + key + ': ' + stats[key] + '</div>';
            }
        }
        html += '<div>Size: ' + (d.input_size || 0).toLocaleString() + ' &rarr; ' +
            (d.output_size || 0).toLocaleString();
        if (d.input_size > 0) {
            var reduction = Math.round((1 - d.output_size / d.input_size) * 100);
            html += ' (' + reduction + '% reduction)';
        }
        html += '</div></dd></div>';

        /* L2 */
        html += '<div class="pf-v6-c-description-list__group">' +
            '<dt class="pf-v6-c-description-list__term">L2 Classify</dt>' +
            '<dd class="pf-v6-c-description-list__description">';
        if (d.l2_label) {
            html += d.l2_label + ' ' + scoreBar(d.l2_score);
        } else {
            html += 'Not available';
        }
        html += '</dd></div>';

        /* Duration */
        if (d.duration_ms) {
            html += '<div class="pf-v6-c-description-list__group">' +
                '<dt class="pf-v6-c-description-list__term">Duration</dt>' +
                '<dd class="pf-v6-c-description-list__description">' + d.duration_ms + 'ms</dd></div>';
        }

        html += '</dl>';
        body.innerHTML = html;
    }

    function setupSignals() {
        airlockObj.addEventListener("signal", function (event, name, args) {
            if (name === "RequestProcessed") {
                var ev = {
                    event: "request_processed",
                    timestamp: Date.now() / 1000,
                    data: {
                        tool: args[0],
                        source: args[1],
                        trust_level: args[2],
                        risk_level: args[3],
                        duration_ms: args[4],
                        stats: JSON.parse(args[5] || "{}"),
                    }
                };
                addEventRow(ev, true);
            } else if (name === "DetectionOccurred") {
                showDetectionAlert(args[0], args[1], args[2], args[3]);
            }
        });
    }

    function showDetectionAlert(layer, source, severity, detailsJson) {
        var section = document.querySelector(".pf-v6-c-page__main-section");
        if (!section) return;

        var alert = document.createElement("div");
        alert.className = "pf-v6-c-alert pf-m-danger pf-m-inline airlock-alert";
        alert.innerHTML =
            '<div class="pf-v6-c-alert__icon"><i class="fas fa-exclamation-circle"></i></div>' +
            '<p class="pf-v6-c-alert__title">Injection Detected</p>' +
            '<div class="pf-v6-c-alert__description">' +
            '<strong>' + escapeHtml(layer) + '</strong> flagged <code>' + escapeHtml(source) + '</code> as <strong>' + escapeHtml(severity) + '</strong>' +
            '</div>';

        section.insertBefore(alert, section.firstChild);

        setTimeout(function () {
            if (alert.parentNode) alert.parentNode.removeChild(alert);
        }, 15000);
    }

    function init() {
        renderPage();

        airlockObj.wait().then(function () {
            airlockObj.GetLayerStatus()
                .then(renderLayerStatus)
                .catch(function (err) { console.warn("GetLayerStatus failed:", err); });

            airlockObj.GetStats()
                .then(renderStats)
                .catch(function (err) { console.warn("GetStats failed:", err); });

            airlockObj.GetRecentEvents(50)
                .then(renderRecentEvents)
                .catch(function (err) { console.warn("GetRecentEvents failed:", err); });

            setupSignals();
        }).catch(function (err) {
            document.getElementById("layer-status-body").textContent = "D-Bus connection failed: " + err;
            console.error("D-Bus proxy failed:", err);
        });
    }

    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", init);
    else
        init();
})();
