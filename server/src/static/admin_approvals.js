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


function injectApprovalsConfirmCss() {
    if (document.getElementById("approvalsConfirmCss")) return;

    const style = document.createElement("style");
    style.id = "approvalsConfirmCss";
    style.textContent = `
.approvalsConfirmBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}

.approvalsConfirmCard{
    width:min(640px, calc(100vw - 24px));
    max-height:min(84vh, 900px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:18px;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    box-shadow:0 18px 70px rgba(0,0,0,0.42);
    color:var(--fg, #111);
}

.approvalsConfirmHead{
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.approvalsConfirmTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}

.approvalsConfirmSub{
    margin-top:4px;
    font-size:12px;
    color:var(--fg-dim, rgba(0,0,0,0.65));
}

.approvalsConfirmBody{
    padding:16px;
    display:grid;
    grid-template-columns:130px minmax(0, 1fr);
    gap:10px 14px;
    overflow:auto;
    min-height:0;
}

.approvalsConfirmKey{
    color:var(--fg-dim, rgba(0,0,0,0.68));
    font-weight:850;
}

.approvalsConfirmValue{
    color:var(--fg, #111);
    overflow-wrap:anywhere;
    white-space:pre-wrap;
}

.approvalsConfirmValue.mono{
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    font-size:12px;
}

.approvalsConfirmNote{
    grid-column:1 / -1;
    padding:10px 12px;
    border:1px solid rgba(var(--fail-rgb, 180,40,40),0.35);
    border-radius:14px;
    background:rgba(var(--fail-rgb, 180,40,40),0.10);
    color:var(--fg, #111);
    font-weight:850;
}

.approvalsConfirmFoot{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.approvalsConfirmBtn{
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:14px;
    padding:9px 14px;
    font:inherit;
    font-weight:850;
    color:var(--fg, #111);
    background:linear-gradient(180deg, rgba(255,255,255,0.20), rgba(0,0,0,0.04));
    cursor:pointer;
}

.approvalsConfirmBtn:hover{
    filter:brightness(1.05);
}

.approvalsConfirmBtn.secondary{
    opacity:.90;
}

.approvalsConfirmBtn.danger{
    border-color:rgba(var(--fail-rgb, 180,40,40),0.48);
    background:rgba(var(--fail-rgb, 180,40,40),0.14);
    color:var(--fg, #111);
}

html[data-theme="bright"] .approvalsConfirmBackdrop{
    background:rgba(0,0,0,0.30);
}

html[data-theme="bright"] .approvalsConfirmCard{
    background:linear-gradient(180deg, #ffffff, #f2f4f7) !important;
    border-color:rgba(70,80,95,0.32) !important;
    color:#111827 !important;
    box-shadow:0 22px 80px rgba(0,0,0,0.28) !important;
}

html[data-theme="bright"] .approvalsConfirmHead,
html[data-theme="bright"] .approvalsConfirmFoot{
    background:rgba(15,23,42,0.045) !important;
    border-color:rgba(70,80,95,0.22) !important;
}

html[data-theme="bright"] .approvalsConfirmTitle,
html[data-theme="bright"] .approvalsConfirmValue,
html[data-theme="bright"] .approvalsConfirmBtn{
    color:#111827 !important;
}

html[data-theme="bright"] .approvalsConfirmSub,
html[data-theme="bright"] .approvalsConfirmKey{
    color:rgba(17,24,39,0.68) !important;
}

html[data-theme="bright"] .approvalsConfirmNote{
    background:rgba(180,40,40,0.10) !important;
    border-color:rgba(180,40,40,0.30) !important;
    color:#111827 !important;
}

html[data-theme="bright"] .approvalsConfirmBtn.secondary{
    background:linear-gradient(180deg, #ffffff, #e8ebef) !important;
}

html[data-theme="bright"] .approvalsConfirmBtn.danger{
    background:rgba(180,40,40,0.14) !important;
    border-color:rgba(180,40,40,0.38) !important;
    color:#111827 !important;
}

html[data-theme="win_classic"] .approvalsConfirmBackdrop{
    background:rgba(0,0,0,0.38);
}
`;
    document.head.appendChild(style);
}

function openApprovalsConfirmModal(opts = {}) {
    injectApprovalsConfirmCss();

    return new Promise((resolve) => {
        const options = opts || {};

        const modal = document.createElement("div");
        modal.className = "approvalsConfirmBackdrop";
        modal.setAttribute("role", "dialog");
        modal.setAttribute("aria-modal", "true");

        const card = document.createElement("div");
        card.className = "approvalsConfirmCard";

        const head = document.createElement("div");
        head.className = "approvalsConfirmHead";

        const title = document.createElement("div");
        title.className = "approvalsConfirmTitle";
        title.textContent = options.title || "Confirm action";

        const sub = document.createElement("div");
        sub.className = "approvalsConfirmSub";
        sub.textContent = options.subtitle || "";

        head.appendChild(title);
        if (sub.textContent) head.appendChild(sub);

        const body = document.createElement("div");
        body.className = "approvalsConfirmBody";

        for (const row of Array.isArray(options.rows) ? options.rows : []) {
            const k = document.createElement("div");
            k.className = "approvalsConfirmKey";
            k.textContent = String(row.label || "");

            const v = document.createElement("div");
            v.className = row.mono ? "approvalsConfirmValue mono" : "approvalsConfirmValue";
            v.textContent = String(row.value || "");

            body.appendChild(k);
            body.appendChild(v);
        }

        if (options.note) {
            const note = document.createElement("div");
            note.className = "approvalsConfirmNote";
            note.textContent = String(options.note || "");
            body.appendChild(note);
        }

        const foot = document.createElement("div");
        foot.className = "approvalsConfirmFoot";

        const spacer = document.createElement("div");
        spacer.style.flex = "1 1 auto";

        const cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "approvalsConfirmBtn secondary";
        cancelBtn.textContent = options.cancelText || "Cancel";

        const okBtn = document.createElement("button");
        okBtn.type = "button";
        okBtn.className = options.danger ? "approvalsConfirmBtn danger" : "approvalsConfirmBtn";
        okBtn.textContent = options.confirmText || "OK";

        foot.appendChild(spacer);
        foot.appendChild(cancelBtn);
        foot.appendChild(okBtn);

        card.appendChild(head);
        card.appendChild(body);
        card.appendChild(foot);
        modal.appendChild(card);
        document.body.appendChild(modal);

        const finish = (value) => {
            document.removeEventListener("keydown", onKey, true);
            modal.remove();
            resolve(!!value);
        };

        const onKey = (ev) => {
            if (ev.key === "Escape") {
                ev.preventDefault();
                ev.stopPropagation();
                finish(false);
                return;
            }

            if (ev.key === "Enter") {
                ev.preventDefault();
                ev.stopPropagation();
                finish(true);
            }
        };

        document.addEventListener("keydown", onKey, true);

        modal.addEventListener("click", (ev) => {
            if (ev.target === modal) finish(false);
        });

        cancelBtn.addEventListener("click", () => finish(false));
        okBtn.addEventListener("click", () => finish(true));

        window.setTimeout(() => {
            if (options.danger) cancelBtn.focus();
            else okBtn.focus();
        }, 0);
    });
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
                const ok = await openApprovalsConfirmModal({
                    title: "Delete user entry?",
                    subtitle: "This removes the user from users.json.",
                    rows: [
                        { label: "Fingerprint", value: fp, mono: true },
                    ],
                    note: "This removes the entry entirely as cleanup. If they scan again, they will re-appear as disabled.",
                    confirmText: "Delete",
                    cancelText: "Cancel",
                    danger: true,
                });
                if (!ok) return;

                try {
                    setMsg("Deleting…");
                    await apiPost("/api/v4/admin/users/delete", { fingerprint: fp });
                    await refresh();
                    setMsg("Delete OK");
                } catch (e) {
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
                    setMsg("Error: " + e.message);
                }
                return;
            }

            const status =
                (act === "disable") ? "disabled" :
                    (act === "revoke") ? "revoked" : "";

            if (!status) return;

            if (act === "revoke") {
                const ok = await openApprovalsConfirmModal({
                    title: "Revoke user?",
                    subtitle: "This hard-blocks login for this fingerprint.",
                    rows: [
                        { label: "Fingerprint", value: fp, mono: true },
                    ],
                    note: "Use this when the identity should not be allowed to log in again.",
                    confirmText: "Revoke",
                    cancelText: "Cancel",
                    danger: true,
                });
                if (!ok) return;
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
