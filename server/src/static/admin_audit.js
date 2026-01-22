// PQ-NAS Admin Audit UI (static)
// - Tail:   GET /api/v4/audit/tail?n=200  -> { lines: [...] }
// - Verify: GET /api/v4/audit/verify     -> { ok: true/false, ... }
//
// Enhancements:
// - Sticky header (CSS)
// - Row index column
// - Better status mapping based on event + ok/error
// - Integrity auto-poll (every 60s) when Auto-refresh is ON
// - Auto state pill (Auto: ON/OFF)
// - Export filtered rows as JSON / CSV

let _all = [];            // all parsed entries
let _filtered = [];       // filtered view
let _autoTimer = null;
let _verifyTimer = null;
let _expandedKey = null;  // currently expanded row key (optional)

function $(id) { return document.getElementById(id); }

function clampInt(v, lo, hi, fallback) {
    const n = parseInt(String(v || "").trim(), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(hi, Math.max(lo, n));
}

function nowIsoCompact() {
    const d = new Date();
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function safeJsonParseMaybe(line) {
    if (line == null) return { _raw: line };
    if (typeof line === "object") return line;

    if (typeof line === "string") {
        const s = line.trim();
        if (!s) return { _raw: line };
        if (s.startsWith("{") || s.startsWith("[")) {
            try { return JSON.parse(s); } catch (_) {}
        }
        return { _raw: line };
    }
    return { _raw: line };
}

function pick(obj, keys) {
    for (const k of keys) {
        if (obj && Object.prototype.hasOwnProperty.call(obj, k) && obj[k] != null) return obj[k];
    }
    return undefined;
}

// ---------- field mapping ----------
function toTsText(e) {
    const s = pick(e, ["ts", "time", "timestamp", "at", "when", "datetime"]);
    if (typeof s === "string" && s.trim()) return s;

    const n = pick(e, ["ts_unix", "unix", "iat", "created_at", "t", "epoch"]);
    if (typeof n === "number" && Number.isFinite(n)) {
        const ms = (n > 1e12) ? n : n * 1000;
        const d = new Date(ms);
        if (!isNaN(d.getTime())) return d.toISOString();
    }
    return "—";
}

function toEventText(e) {
    const ev = pick(e, ["event", "type", "action", "op", "name", "kind"]);
    if (typeof ev === "string" && ev.trim()) return ev;
    return "(unknown)";
}

function toFingerprint(e) {
    const fp = pick(e, ["fingerprint_hex", "fp_hex", "fingerprint", "fp", "fingerprint_b64", "fp_b64"]);
    if (fp == null) return "—";
    return String(fp);
}

function toSid(e) {
    const sid = pick(e, ["sid", "session_id", "session", "browser_sid", "req_sid"]);
    if (sid == null) return "—";
    return String(sid);
}

function toIp(e) {
    const ip = pick(e, ["ip", "remote_ip", "client_ip", "addr", "remote_addr"]);
    if (ip == null) return "—";
    return String(ip);
}

// ---------- status mapping (improved) ----------
function inferStatus(e) {
    // 1) explicit booleans
    const ok = pick(e, ["ok", "success", "verified", "allowed"]);
    if (typeof ok === "boolean") return ok ? "ok" : "fail";

    // 2) explicit error fields
    if (pick(e, ["error", "err", "failure", "denied"]) != null) return "fail";

    // 3) event name heuristics
    const ev = String(toEventText(e) || "").toLowerCase();

    // fail-ish
    if (ev.includes("fail") || ev.includes("denied") || ev.includes("reject") || ev.includes("error")) return "fail";

    // ok-ish
    if (ev.includes("ok") || ev.includes("approved") || ev.includes("issued") || ev.includes("minted") || ev.includes("verified")) return "ok";

    // warn-ish (policy / rate / suspicious / replay etc.)
    if (ev.includes("policy") || ev.includes("rate") || ev.includes("suspicious") || ev.includes("replay")) return "warn";

    return "info";
}

function statusLabel(st) {
    if (st === "ok") return "OK";
    if (st === "fail") return "FAIL";
    if (st === "warn") return "WARN";
    return "INFO";
}

function statusClass(st) {
    if (st === "ok") return "ok";
    if (st === "fail") return "fail";
    if (st === "warn") return "warn";
    return "info";
}

function matchesAny(hay, needle) {
    if (!needle) return true;
    return String(hay || "").toLowerCase().includes(String(needle).toLowerCase());
}

function rowKey(e, idx) {
    const ts = toTsText(e);
    const ev = toEventText(e);
    const fp = toFingerprint(e);
    return `${ts}¦${ev}¦${fp}¦${idx}`;
}

function prettyJson(e) {
    try { return JSON.stringify(e, null, 2); }
    catch (_) { return String(e); }
}

// Simple HTML escaping to avoid rendering raw audit data as HTML.
function escapeHtml(s) {
    return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function setPill(el, kind, label) {
    if (!el) return;
    el.classList.remove("ok", "fail", "warn", "info", "on");
    el.classList.add(kind);
    const v = el.querySelector(".v");
    if (v) v.textContent = label;
}

// ---------- rendering ----------
function renderTable() {
    const tbody = $("tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    for (let i = 0; i < _filtered.length; i++) {
        const e = _filtered[i];
        const k = rowKey(e, i);

        const ts = toTsText(e);
        const ev = toEventText(e);
        const fp = toFingerprint(e);
        const sid = toSid(e);
        const ip = toIp(e);
        const st = inferStatus(e);

        const tr = document.createElement("tr");
        tr.className = "clickable";
        tr.dataset.key = k;

        // Row index: show newest-first numbering if desired.
        // Current tail is typically oldest->newest or newest->oldest depending on backend;
        // We keep simple 1..N in current view.
        const idxText = String(i + 1);

        tr.innerHTML = `
      <td class="col-idx mono" title="${escapeHtml(idxText)}">${escapeHtml(idxText)}</td>
      <td class="col-ts mono" title="${escapeHtml(ts)}">${escapeHtml(ts)}</td>
      <td class="col-status"><span class="statusPill ${statusClass(st)}">${statusLabel(st)}</span></td>
      <td class="col-event" title="${escapeHtml(ev)}">${escapeHtml(ev)}</td>
      <td class="col-fp mono" title="${escapeHtml(fp)}">${escapeHtml(fp)}</td>
      <td class="col-sid mono" title="${escapeHtml(sid)}">${escapeHtml(sid)}</td>
      <td class="col-ip mono" title="${escapeHtml(ip)}">${escapeHtml(ip)}</td>
    `;

        tr.addEventListener("click", () => toggleExpand(k, e));
        tbody.appendChild(tr);

        if (_expandedKey === k) {
            const detailTr = buildDetailRow(e, k);
            tbody.appendChild(detailTr);
        }
    }

    $("countText").textContent = String(_filtered.length);
    $("loadedText").textContent = String(_all.length);
}

function buildDetailRow(e, k) {
    const detailTr = document.createElement("tr");
    detailTr.className = "detailRow";
    const td = document.createElement("td");
    td.colSpan = 7;

    const json = prettyJson(e);
    td.innerHTML = `
    <div class="detail">
      <pre class="mono">${escapeHtml(json)}</pre>
      <div class="detailActions">
        <button class="btn" data-act="copy">Copy JSON</button>
        <button class="btn" data-act="collapse">Collapse</button>
        <div class="small">Row key:</div>
        <div class="pill"><span class="v mono" style="max-width:170px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(k)}</span></div>
      </div>
    </div>
  `;

    td.querySelector('[data-act="copy"]').addEventListener("click", async (ev) => {
        ev.stopPropagation();
        try {
            await navigator.clipboard.writeText(json);
        } catch (_) {
            const ta = document.createElement("textarea");
            ta.value = json;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            ta.remove();
        }
    });

    td.querySelector('[data-act="collapse"]').addEventListener("click", (ev) => {
        ev.stopPropagation();
        _expandedKey = null;
        renderTable();
    });

    detailTr.appendChild(td);
    return detailTr;
}

function toggleExpand(k) {
    _expandedKey = (_expandedKey === k) ? null : k;
    renderTable();
}

// ---------- filtering ----------
function applyFilters() {
    const qEvent = $("qEvent").value.trim();
    const qFp = $("qFp").value.trim();
    const qSid = $("qSid").value.trim();
    const qIp = $("qIp").value.trim();

    _filtered = _all.filter((e) => {
        const ev = toEventText(e);
        const fp = toFingerprint(e);
        const sid = toSid(e);
        const ip = toIp(e);
        return (
            matchesAny(ev, qEvent) &&
            matchesAny(fp, qFp) &&
            matchesAny(sid, qSid) &&
            matchesAny(ip, qIp)
        );
    });

    // collapse expanded if it no longer exists
    if (_expandedKey) {
        const still = _filtered.some((e, i) => rowKey(e, i) === _expandedKey);
        if (!still) _expandedKey = null;
    }

    renderTable();
}

// ---------- network ----------
async function loadTail() {
    const n = clampInt($("tailN").value, 1, 5000, 200);
    $("tailNText").textContent = String(n);

    const url = `/api/v4/audit/tail?n=${encodeURIComponent(String(n))}`;
    try {
        const r = await fetch(url, { cache: "no-store" });
        if (!r.ok) {
            setPill($("lastFetchPill"), "fail", `HTTP ${r.status}`);
            return;
        }
        const j = await r.json();
        const lines = Array.isArray(j.lines) ? j.lines : [];
        _all = lines.map(safeJsonParseMaybe);

        _expandedKey = null;
        setPill($("lastFetchPill"), "ok", nowIsoCompact());
        applyFilters();
    } catch (e) {
        setPill($("lastFetchPill"), "fail", "network error");
    }
}

async function verifyChain() {
    try {
        setPill($("integrityPill"), "warn", "checking…");
        const r = await fetch("/api/v4/audit/verify", { cache: "no-store" });
        if (!r.ok) {
            setPill($("integrityPill"), "fail", `HTTP ${r.status}`);
            return;
        }
        const j = await r.json();
        if (j && j.ok === true) {
            setPill($("integrityPill"), "ok", "OK");
        } else {
            setPill($("integrityPill"), "fail", "FAILED");
            console.error("audit verify failed:", j);
        }
    } catch (e) {
        setPill($("integrityPill"), "fail", "network error");
    }
}

// ---------- auto refresh + auto verify ----------
function stopAuto() {
    if (_autoTimer) clearInterval(_autoTimer);
    _autoTimer = null;

    if (_verifyTimer) clearInterval(_verifyTimer);
    _verifyTimer = null;
}

function startAuto() {
    stopAuto();

    const sec = clampInt($("intervalSec").value, 1, 3600, 3);
    $("intervalText").textContent = `${sec}s`;

    // Tail refresh interval (user-controlled)
    _autoTimer = setInterval(() => {
        loadTail();
    }, sec * 1000);

    // Integrity verify interval (fixed 60s, only when auto is enabled)
    _verifyTimer = setInterval(() => {
        verifyChain();
    }, 60 * 1000);
}

function syncAutoUi() {
    const on = $("autoToggle").checked;

    // auto pill
    const autoPill = $("autoPill");
    if (on) {
        setPill(autoPill, "on", "ON");
        $("btnRefresh").classList.add("glow");
    } else {
        setPill(autoPill, "info", "OFF");
        $("btnRefresh").classList.remove("glow");
    }
}

function syncAuto() {
    const on = $("autoToggle").checked;
    syncAutoUi();
    if (on) startAuto();
    else stopAuto();
}

// ---------- export ----------
function downloadBlob(filename, contentType, data) {
    const blob = new Blob([data], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function exportJson() {
    const ts = new Date().toISOString().replaceAll(":", "-");
    const filename = `pqnas-audit-${ts}.json`;
    const payload = JSON.stringify(_filtered, null, 2);
    downloadBlob(filename, "application/json;charset=utf-8", payload);
}

function csvEscape(v) {
    const s = String(v ?? "");
    // RFC4180-ish: quote if contains comma, quote, newline
    if (/[",\n\r]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
    return s;
}

function exportCsv() {
    const ts = new Date().toISOString().replaceAll(":", "-");
    const filename = `pqnas-audit-${ts}.csv`;

    // export both “table columns” + raw JSON
    const header = ["idx","timestamp","status","event","fingerprint","sid","ip","raw_json"];
    const rows = _filtered.map((e, i) => {
        const tsText = toTsText(e);
        const st = inferStatus(e);
        const ev = toEventText(e);
        const fp = toFingerprint(e);
        const sid = toSid(e);
        const ip = toIp(e);
        const raw = prettyJson(e);
        return [
            i + 1,
            tsText,
            statusLabel(st),
            ev,
            fp,
            sid,
            ip,
            raw
        ].map(csvEscape).join(",");
    });

    const csv = header.join(",") + "\n" + rows.join("\n") + "\n";
    downloadBlob(filename, "text/csv;charset=utf-8", csv);
}

// ---------- init ----------
function wire() {
    $("btnRefresh").addEventListener("click", () => loadTail());
    $("btnVerify").addEventListener("click", () => verifyChain());
    $("btnExportJson").addEventListener("click", () => exportJson());
    $("btnExportCsv").addEventListener("click", () => exportCsv());

    $("btnClear").addEventListener("click", () => {
        $("qEvent").value = "";
        $("qFp").value = "";
        $("qSid").value = "";
        $("qIp").value = "";
        _expandedKey = null;
        applyFilters();
    });

    for (const id of ["qEvent", "qFp", "qSid", "qIp"]) {
        $(id).addEventListener("input", () => applyFilters());
    }

    $("autoToggle").addEventListener("change", () => syncAuto());
    $("intervalSec").addEventListener("change", () => syncAuto());
    $("tailN").addEventListener("change", () => loadTail());

    window.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") {
            _expandedKey = null;
            renderTable();
        }
    });
}

window.addEventListener("load", async () => {
    wire();
    syncAutoUi();
    await loadTail();
    await verifyChain();
});
