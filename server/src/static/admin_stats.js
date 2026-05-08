(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);

    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, c => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c]));
    }

    function fmtNum(n) {
        const v = Number(n || 0);
        return Number.isFinite(v) ? v.toLocaleString() : "0";
    }

    function fmtBytes(bytes) {
        const n = Number(bytes || 0);
        if (!Number.isFinite(n) || n <= 0) return "0 B";
        const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        const digits = i === 0 ? 0 : (v >= 100 ? 1 : 2);
        return `${v.toFixed(digits)} ${units[i]}`;
    }

    function setText(id, value) {
        const el = $(id);
        if (el) el.textContent = value;
    }

    function rowsHtml(rows, nameKey, emptyText) {
        if (!Array.isArray(rows) || rows.length === 0) {
            return `<tr><td colspan="3">${esc(emptyText || "No data")}</td></tr>`;
        }

        return rows.map(r => `
            <tr>
                <td class="mono">${esc(r[nameKey] || "—")}</td>
                <td class="num">${fmtNum(r.count)}</td>
                <td class="num">${fmtBytes(r.bytes)}</td>
            </tr>
        `).join("");
    }

    async function loadStats(force = false) {
        const url = force ? "/api/v4/admin/stats/summary?refresh=1" : "/api/v4/admin/stats/summary";
        const btn = $("refreshBtn");
        const status = $("status");

        if (btn) btn.disabled = true;
        if (status) status.textContent = "Scanning live storage…";

        try {
            const r = await fetch(url, {
                headers: { "Accept": "application/json" },
                cache: "no-store"
            });

            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j.ok) {
                throw new Error(j.message || j.error || `HTTP ${r.status}`);
            }

            const users = j.users || {};
            const workspaces = j.workspaces || {};
            const files = j.files || {};

            setText("cardUsers", fmtNum(users.total));
            setText(
                "cardUsersMini",
                `${fmtNum(users.enabled)} enabled · ${fmtNum(users.disabled)} disabled · ${fmtNum(users.admins)} admin`
            );

            setText("cardFiles", fmtNum(files.total_count));
            setText(
                "cardFilesMini",
                `${fmtNum(files.scanned_roots)} roots scanned · ${fmtNum(files.skipped_roots)} skipped`
            );

            setText("cardBytes", fmtBytes(files.total_bytes));
            setText("cardBytesMini", `Largest file ${fmtBytes(files.largest_bytes)}`);

            setText("cardWorkspaces", fmtNum(workspaces.total));
            setText(
                "cardWorkspacesMini",
                `${fmtNum(workspaces.enabled)} enabled · ${fmtNum(workspaces.user_created)} user-created · avg file ${fmtBytes(files.average_bytes)}`
            );

            $("mimeRows").innerHTML = rowsHtml(j.top_mime_types, "mime", "No MIME data");
            $("extRows").innerHTML = rowsHtml(j.top_extensions, "extension", "No extension data");
            $("scopeRows").innerHTML = rowsHtml(j.files_by_scope, "scope", "No scope data");

            const warnings = Array.isArray(j.warnings) ? j.warnings : [];
            const warningHtml = warnings.length
                ? `<tr><th>Warnings</th><td class="warn">${warnings.map(esc).join("<br>")}</td></tr>`
                : `<tr><th>Warnings</th><td>None</td></tr>`;

            $("detailRows").innerHTML = `
                <tr><th>Generated</th><td class="mono">${esc(j.generated_at_iso || "—")}</td></tr>
                <tr><th>Method</th><td>${esc(j.method || "—")}</td></tr>
                <tr><th>Notes</th><td>${esc(j.note || "—")}</td></tr>
                ${warningHtml}
            `;

            if (status) {
                status.textContent = `Updated ${j.generated_at_iso || "now"}`;
            }
        } catch (e) {
            if (status) status.textContent = `Failed: ${e.message || e}`;
            ["mimeRows", "extRows", "scopeRows"].forEach(id => {
                const el = $(id);
                if (el) el.innerHTML = `<tr><td colspan="3">Failed to load statistics.</td></tr>`;
            });
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const btn = $("refreshBtn");
        if (btn) btn.addEventListener("click", loadStats);
        loadStats();
    });
})();
