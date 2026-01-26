// PQ-NAS Admin Audit UI (static)
// - Tail:   GET /api/v4/audit/tail?n=200  -> { lines: [...] }
// - Verify: GET /api/v4/audit/verify     -> { ok: true/false, ... }

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
    const fp =
        pick(e, ["fingerprint_hex", "fp_hex", "fingerprint", "fp", "fingerprint_b64", "fp_b64"]) ??
        pick(e && e.f, ["fingerprint_hex", "fp_hex", "fingerprint", "fp", "fingerprint_b64", "fp_b64"]);
    if (fp == null) return "—";
    return String(fp);
}

function toSid(e) {
    const sid =
        pick(e, ["sid", "session_id", "session", "browser_sid", "req_sid"]) ??
        pick(e && e.f, ["sid", "session_id", "session", "browser_sid", "req_sid"]);
    if (sid == null) return "—";
    return String(sid);
}

function toIp(e) {
    const ip =
        pick(e, ["ip", "remote_ip", "client_ip", "addr", "remote_addr"]) ??
        pick(e && e.f, ["ip", "remote_ip", "client_ip", "addr", "remote_addr", "xff", "cf_ip"]);
    if (ip == null) return "—";
    return String(ip);
}

// ---------- status mapping ----------
function inferStatus(e) {
    // PQ-NAS uses outcome="ok|fail|deny" on most audit lines.
    const oc = pick(e, ["outcome"]);
    if (typeof oc === "string") {
        const o = oc.toLowerCase();
        if (o === "ok") return "ok";
        if (o === "fail" || o === "deny") return "fail";
    }

    const ok = pick(e, ["ok", "success", "verified", "allowed"]);
    if (typeof ok === "boolean") return ok ? "ok" : "fail";
    if (pick(e, ["error", "err", "failure", "denied"]) != null) return "fail";

    const ev = String(toEventText(e) || "").toLowerCase();

    if (ev.includes("fail") || ev.includes("denied") || ev.includes("reject") || ev.includes("error")) return "fail";
    if (ev.includes("ok") || ev.includes("approved") || ev.includes("issued") || ev.includes("minted") || ev.includes("verified")) return "ok";
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

function eventClasses(e) {
    const ev = String(toEventText(e) || "").toLowerCase();

    const cls = [];

    // Family buckets
    if (ev.startsWith("admin.")) cls.push("ev-admin");
    if (ev.includes("storage") || ev.includes("quota") || ev.includes("dir_") || ev.includes("directory")) cls.push("ev-storage");
    if (ev.startsWith("v4.") || ev.includes("cookie") || ev.includes("session") || ev.includes("login") || ev.includes("verify")) cls.push("ev-auth");

    // Status-derived tint (works even if event name doesn’t say much)
    const st = inferStatus(e);
    if (st === "warn") cls.push("ev-warnline");
    if (st === "fail") cls.push("ev-errorline");

    // Exact “make these pop” lines (your examples)
    if (ev === "admin.user_storage_allocated" || ev.endsWith(".user_storage_allocated")) cls.push("ev-storage-alloc");
    if (ev === "admin.user_storage_dir_created" || ev.endsWith(".user_storage_dir_created")) cls.push("ev-storage-dir");
    if (ev === "admin.user_enabled" || ev.endsWith(".user_enabled")) cls.push("ev-admin-enabled");

    return cls.join(" ");
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
        tr.className = "clickable " + eventClasses(e);
        tr.dataset.key = k;

        const evLower = String(ev || "").toLowerCase();

        // families
        if (evLower.startsWith("admin.")) tr.classList.add("ev-admin");
        if (evLower.startsWith("v4.")) tr.classList.add("ev-auth");
        if (evLower.includes("storage")) tr.classList.add("ev-storage");

        if (st === "warn") tr.classList.add("ev-warnline");
        if (st === "fail") tr.classList.add("ev-errorline");

        // exact ones you named
        if (evLower === "admin.user_storage_allocated") tr.classList.add("ev-storage-alloc");
        if (evLower === "admin.user_storage_dir_created") tr.classList.add("ev-storage-dir");
        if (evLower === "admin.user_enabled" || evLower === "admin.user_status_set") tr.classList.add("ev-admin-enabled");


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
        <button class="btn" data-act="copy" type="button">Copy JSON</button>
        <button class="btn" data-act="collapse" type="button">Collapse</button>
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

// NEW: newest-first (ISO timestamps sort correctly as strings)
        _all.sort((a, b) => {
            const ta = String(toTsText(a) || "");
            const tb = String(toTsText(b) || "");

            // push missing/unknown timestamps to bottom
            const aBad = (ta === "—" || !ta.trim());
            const bBad = (tb === "—" || !tb.trim());
            if (aBad && bBad) return 0;
            if (aBad) return 1;
            if (bBad) return -1;

            if (ta < tb) return 1;
            if (ta > tb) return -1;

            // tie-breaker for deterministic order
            const ea = String(toEventText(a) || "");
            const eb = String(toEventText(b) || "");
            return ea.localeCompare(eb);
        });


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

    _autoTimer = setInterval(() => {
        loadTail();
    }, sec * 1000);

    _verifyTimer = setInterval(() => {
        verifyChain();
    }, 60 * 1000);
}

function syncAutoUi() {
    const on = $("autoToggle").checked;

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
    if (/[",\n\r]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
    return s;
}

function exportJsonFriendlyRow(e, i) {
    // Keep this stable for operators: flatten common fields while still including raw JSON.
    return {
        idx: i + 1,
        ts: toTsText(e),
        status: statusLabel(inferStatus(e)),
        event: toEventText(e),
        fingerprint: toFingerprint(e),
        sid: toSid(e),
        ip: toIp(e),
        raw: e
    };
}

function exportCsv() {
    const ts = new Date().toISOString().replaceAll(":", "-");
    const filename = `pqnas-audit-${ts}.csv`;

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

// ---------- rotate ----------
const rotateBtn = document.getElementById("btnRotateAudit");
const rotatePill = document.getElementById("rotateAuditStatus");

async function doRotateAudit() {
    if (!rotateBtn) return;

    if (!confirm("Rotate audit log now?\n\nThis will create a rotated file and write a rotate_header line to the new active log.")) {
        return;
    }

    rotateBtn.disabled = true;
    if (rotatePill) {
        rotatePill.style.display = "inline-flex";
        rotatePill.className = "pill info";
        rotatePill.querySelector(".v").textContent = "rotating…";
    }

    try {
        const r = await fetch("/api/v4/admin/rotate-audit", { method: "POST", cache: "no-store" });
        const j = await r.json();
        if (!j.ok) throw new Error(j.error || "rotate failed");

        if (rotatePill) {
            rotatePill.className = "pill ok";
            rotatePill.querySelector(".v").textContent = "OK";
            rotatePill.title = j.rotated_jsonl_path || "OK";
        }

        // Refresh after rotation so the operator immediately sees the new header line.
        await loadTail();
        await verifyChain();
    } catch (e) {
        if (rotatePill) {
            rotatePill.className = "pill fail";
            rotatePill.querySelector(".v").textContent = "ERROR";
            rotatePill.title = String(e);
        }
    } finally {
        rotateBtn.disabled = false;
    }
}

rotateBtn?.addEventListener("click", doRotateAudit);

// ---------- init ----------
function onClick(id, fn) { const el = $(id); if (el) el.addEventListener("click", fn); }
function onInput(id, fn) { const el = $(id); if (el) el.addEventListener("input", fn); }
function onChange(id, fn) { const el = $(id); if (el) el.addEventListener("change", fn); }

function wire() {
    onClick("btnRefresh", () => loadTail());
    onClick("btnVerify", () => verifyChain());
    onClick("btnExportJson", () => exportJson());
    onClick("btnExportCsv", () => exportCsv());

    onClick("btnClear", () => {
        if ($("qEvent")) $("qEvent").value = "";
        if ($("qFp")) $("qFp").value = "";
        if ($("qSid")) $("qSid").value = "";
        if ($("qIp")) $("qIp").value = "";
        _expandedKey = null;
        applyFilters();
    });

    for (const id of ["qEvent", "qFp", "qSid", "qIp"]) onInput(id, () => applyFilters());

    onChange("autoToggle", () => syncAuto());
    onChange("intervalSec", () => syncAuto());
    onChange("tailN", () => loadTail());

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
