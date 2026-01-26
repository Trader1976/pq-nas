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

let allUsers = [];

function setMsg(text) {
    const el = $("msg");
    if (el) el.textContent = text || "";
}

function render() {
    const f = ($("filter")?.value || "").toLowerCase().trim();

    // Approvals view behavior:
    // - If filter is empty: show only non-enabled (disabled/revoked)
    // - If filter is non-empty: show whatever matches (including enabled)
    const rows = allUsers.filter(u => {
        const st = String(u.status || "disabled").toLowerCase();
        if (!f && st === "enabled") return false;

        const hay = [
            u.fingerprint, u.name, u.notes, u.role, u.status
        ].join(" ").toLowerCase();

        return !f || hay.includes(f);
    });

    const tb = $("tbody");
    if (!tb) return;

    tb.innerHTML = rows.map(u => {
        return `<tr>
            <td class="mono">${esc(u.fingerprint)}</td>

            <td>
                <div><b>${esc(u.name || "")}</b></div>
                <div class="muted" style="white-space:pre-wrap;">${esc(u.notes || "")}</div>
            </td>

            <td>${esc(u.role || "")}</td>
            <td>${pill(u.status)}</td>

            <td class="mono">${esc(u.added_at || "")}</td>
            <td class="mono">${esc(u.last_seen || "")}</td>

            <td class="row-actions">
                <button class="btn secondary" data-act="enable" data-fp="${esc(u.fingerprint)}" type="button">Enable</button>
                <button class="btn secondary" data-act="disable" data-fp="${esc(u.fingerprint)}" type="button">Disable</button>
                <button class="btn secondary" data-act="revoke" data-fp="${esc(u.fingerprint)}" type="button">Revoke</button>
                <button class="btn danger" data-act="delete" data-fp="${esc(u.fingerprint)}" type="button">Delete</button>
            </td>
        </tr>`;
    }).join("");

    tb.querySelectorAll("button").forEach(b => {
        b.addEventListener("click", async () => {
            const fp = b.getAttribute("data-fp");
            const act = b.getAttribute("data-act");

            if (!fp || !act) return;

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
    allUsers = (j.users || []).sort((a,b) => (a.fingerprint||"").localeCompare(b.fingerprint||""));
    render();
    setMsg(`Loaded ${allUsers.length} users`);
}

window.addEventListener("load", async () => {
    $("btnRefresh")?.addEventListener("click", refresh);
    $("btnRefresh2")?.addEventListener("click", refresh);
    $("filter")?.addEventListener("input", render);

    try { await refresh(); }
    catch (e) { setMsg("Failed to load users: " + e.message); }
});
