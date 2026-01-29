async function apiGet(path) {
    const r = await fetch(path, { headers: { "Accept": "application/json" }, cache: "no-store" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
    return j;
}

async function apiPost(path, body) {
    const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(body),
        cache: "no-store",
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
    return j;
}

function $(id) { return document.getElementById(id); }

function pill(status) {
    const cls = (status || "disabled");
    return `<span class="pill ${cls}">${cls}</span>`;
}

function esc(s) {
    return (s || "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmtGBFromBytes(b) {
    const n = Number(b || 0);
    if (!isFinite(n) || n <= 0) return "";
    const gb = n / (1024 * 1024 * 1024);
    // keep it simple: show up to 2 decimals, trim trailing zeros
    return (Math.round(gb * 100) / 100).toString();
}

function fmtQuotaCell(u) {
    const st = (u.storage_state || "unallocated");
    if (st !== "allocated") return `<span class="muted">—</span>`;
    const gb = fmtGBFromBytes(u.quota_bytes);
    return gb ? `${esc(gb)} GB` : `<span class="muted">0</span>`;
}

function storagePill(state) {
    const s = (state || "unallocated");
    const cls = (s === "allocated") ? "enabled" : "disabled"; // reuse pill CSS classes
    return `<span class="pill ${cls}">${esc(s)}</span>`;
}

function fmtBytes(n) {
    n = Number(n || 0);
    const units = ["B","KiB","MiB","GiB","TiB"];
    let u = 0;
    while (n >= 1024 && u < units.length - 1) { n /= 1024; u++; }
    return `${n.toFixed(u === 0 ? 0 : 2)} ${units[u]}`;
}

function showToast(msg, ms = 10000) {
    let t = document.getElementById("toast");
    if (!t) {
        t = document.createElement("div");
        t.id = "toast";
        t.style.position = "fixed";
        t.style.right = "18px";
        t.style.bottom = "18px";
        t.style.zIndex = "99999";

        /* sizing */
        t.style.maxWidth = "520px";
        t.style.width = "min(520px, calc(100vw - 36px))";

        t.style.padding = "12px 14px";
        t.style.borderRadius = "12px";
        t.style.border = "1px solid var(--border)";
        t.style.background = "rgba(0,0,0,0.70)";
        t.style.color  = "var(--fg)";
        t.style.boxShadow = "0 18px 70px rgba(0,0,0,0.55)";
        t.style.font = "14px system-ui, -apple-system, Segoe UI, Roboto, sans-serif";

        /* wrapping + scroll */
        t.style.whiteSpace = "pre-wrap";
        t.style.wordBreak = "break-all";
        t.style.overflowWrap = "anywhere";
        t.style.maxHeight = "60vh";
        t.style.overflow = "auto";

        /* allow selection */
        t.style.userSelect = "text";
        t.style.cursor = "text";

        t.style.display = "none";
        document.body.appendChild(t);
    }

    t.textContent = msg;
    t.onclick = () => {
        navigator.clipboard.writeText(msg).catch(() => {});
    };

    t.style.display = "block";
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(() => { t.style.display = "none"; }, ms);
}

let allUsers = [];
let actorFp = "";

function setMsg(text) {
    const el = $("msg");
    if (el) el.textContent = text || "";
}

function render() {
    const f = ($("filter")?.value || "").toLowerCase().trim();
    const rows = allUsers.filter(u => {
        const hay = [
            u.fingerprint, u.name, u.notes, u.role, u.status,
            u.group, u.email, u.storage_state,
            String(u.quota_bytes || "")
        ].join(" ").toLowerCase();
        return !f || hay.includes(f);
    });

    const tb = $("tbody");
    if (!tb) return;

    tb.innerHTML = rows.map(u => {
        const isSelf = actorFp && String(u.fingerprint || "") === actorFp;

        const selfTag = isSelf
            ? `<span class="pill enabled" title="This is you" style="margin-left:8px;">you</span>`
            : "";

        // Disallow self-modification (Allocate is allowed for self)
        const disAttr = isSelf ? ` disabled title="Refusing to modify your own admin entry"` : "";
        const disClass = isSelf ? ` style="opacity:0.45; cursor:not-allowed;"` : "";

        return `<tr>
        <td class="mono">${esc(u.fingerprint)}</td>

        <td>
            <div><b>${esc(u.name || "")}</b>${selfTag}</div>
            <div class="muted" style="white-space:pre-wrap;">${esc(u.notes || "")}</div>
        </td>

        <td>${esc(u.role || "")}</td>
        <td>${pill(u.status)}</td>

        <td>${esc(u.group || "")}</td>
        <td>${storagePill(u.storage_state)}</td>
        <td class="mono">${fmtQuotaCell(u)}</td>

        <td class="mono">${esc(u.added_at || "")}</td>
        <td class="mono">${esc(u.last_seen || "")}</td>

        <td class="row-actions">
            <button class="btn secondary" data-act="enable" data-fp="${esc(u.fingerprint)}" type="button"${disAttr}${disClass}>Enable</button>
            <button class="btn secondary" data-act="disable" data-fp="${esc(u.fingerprint)}" type="button"${disAttr}${disClass}>Disable</button>
            <button class="btn secondary" data-act="revoke" data-fp="${esc(u.fingerprint)}" type="button"${disAttr}${disClass}>Revoke</button>
            <button class="btn secondary" data-act="allocate" data-fp="${esc(u.fingerprint)}" type="button">Allocate</button>
            <button class="btn danger" data-act="delete" data-fp="${esc(u.fingerprint)}" type="button"${disAttr}${disClass}>Delete</button>
        </td>
    </tr>`;
    }).join("");

    tb.querySelectorAll("button").forEach(b => {
        b.addEventListener("click", async () => {
            const fp = b.getAttribute("data-fp");
            const act = b.getAttribute("data-act");

            if (!fp || !act) return;

            const isSelf = actorFp && fp === actorFp;
            if (isSelf && (act === "enable" || act === "disable" || act === "revoke" || act === "delete")) {
                alert("Refusing to modify your own admin entry (prevents lockout or role change).");
                return;
            }

            if (act === "delete") {
                const msg =
                    "Delete this user from users.json?\n\n" +
                    "This removes the entry entirely (cleanup). " +
                    "If they scan again, they will re-appear as disabled.";
                if (!confirm(msg)) return;

                try {
                    setMsg("Deleting…");
                    await apiPost("/api/v4/admin/users/delete", { fingerprint: fp });
                    await refresh();
                    setMsg("Delete OK");
                    showToast("User deleted");
                } catch (e) {
                    alert("Failed: " + e.message);
                    setMsg("Error: " + e.message);
                }
                return;
            }

            if (act === "enable") {
                try {
                    setMsg("Enabling…");
                    await apiPost("/api/v4/admin/users/enable", { fingerprint: fp });
                    await refresh();
                    setMsg("Enabled");
                    showToast("User enabled");
                } catch (e) {
                    alert("Failed: " + e.message);
                    setMsg("Error: " + e.message);
                }
                return;
            }

            if (act === "allocate") {
                const cur = allUsers.find(x => x.fingerprint === fp) || {};

                const isAllocated = String(cur.storage_state || "").toLowerCase() === "allocated";
                if (isAllocated) {
                    if (!confirm("Storage is already allocated for this user.\n\nChange quota anyway?")) return;
                }

                const suggested = fmtGBFromBytes(cur.quota_bytes) || "10";
                const input = prompt("Allocate storage.\n\nQuota in GB:", suggested);
                if (input === null) return;

                const quota_gb = Number(String(input).trim());
                if (!isFinite(quota_gb) || quota_gb < 0) {
                    alert("Invalid quota. Enter a number >= 0.");
                    return;
                }

                try {
                    setMsg(isAllocated ? "Updating storage…" : "Allocating…");
                    const j = await apiPost("/api/v4/admin/users/storage", { fingerprint: fp, quota_gb, force: isAllocated });
                    await refresh();

                    const path = j.root_rel || "(missing)";
                    const qb = Number(j.quota_bytes || 0);
                    const quotaText = qb ? fmtBytes(qb) : `${quota_gb} GB`;
                    const at = j.storage_set_at || "";

                    showToast(
                        (isAllocated ? "Storage updated (click to copy)\n" : "Storage allocated\n") +
                        `Path: ${path}\n` +
                        `Quota: ${quotaText}\n` +
                        (at ? `Set at: ${at}` : "")
                    );

                    setMsg(isAllocated ? "Storage updated" : "Allocated");
                } catch (e) {
                    alert("Failed: " + e.message);
                    setMsg("Error: " + e.message);
                }
                return;
            }

            const status =
                (act === "disable") ? "disabled" :
                    (act === "revoke") ? "revoked" : "";

            if (!status) return;

            if (act === "revoke") {
                if (!confirm("Revoke this user? This hard-blocks login for that fingerprint.")) return;
            }

            try {
                setMsg("Saving…");
                await apiPost("/api/v4/admin/users/status", { fingerprint: fp, status });
                await refresh();
                setMsg("Saved");
                showToast(`User status: ${status}`);
            } catch (e) {
                alert("Failed: " + e.message);
                setMsg("Error: " + e.message);
            }
        });
    });
}

async function refresh() {
    setMsg("Loading users…");
    const j = await apiGet("/api/v4/admin/users");
    actorFp = String(j.actor_fp || "");
    allUsers = (j.users || []).sort((a,b) => (a.fingerprint||"").localeCompare(b.fingerprint||""));
    render();
    setMsg(`Loaded ${allUsers.length} users`);
}

async function upsertFromForm() {
    const fp = ($("fp")?.value || "").trim();
    const name = ($("name")?.value || "").trim();
    const role = ($("role")?.value || "user").trim();
    const notes = ($("notes")?.value || "").trim();

    if (!fp || fp.length < 32) throw new Error("fingerprint looks invalid");
    await apiPost("/api/v4/admin/users/upsert", { fingerprint: fp, name, role, notes });
    await refresh();
    setMsg("Upsert OK");
    showToast("User upserted");
}

window.addEventListener("load", async () => {
    $("btnRefresh")?.addEventListener("click", refresh);
    $("filter")?.addEventListener("input", render);

    $("btnAdd")?.addEventListener("click", async () => {
        setMsg("");
        try { await upsertFromForm(); }
        catch (e) { setMsg("Error: " + e.message); }
    });

    try { await refresh(); }
    catch (e) { setMsg("Failed to load users: " + e.message); }
});
