async function apiGet(path) {
    const r = await fetch(path, { headers: { "Accept": "application/json" }, cache: "no-store" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
    return j;
}


// for showing quota usage bar
function clamp01(x) {
    x = Number(x);
    if (!isFinite(x)) return 0;
    return Math.max(0, Math.min(1, x));
}

function fmtBytesShort(n) {
    if (!Number.isFinite(n) || n < 0) return "—";
    const units = ["B","KiB","MiB","GiB","TiB"];
    let x = n, i = 0;
    while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return `${x.toFixed(i === 0 ? 0 : (i === 1 ? 1 : 2))} ${units[i]}`;
}

function quotaUsageText(usedBytes, quotaBytes) {
    const used = Number(usedBytes);
    const quota = Number(quotaBytes);
    if (!isFinite(quota) || quota <= 0) return "—";
    return `${fmtBytesShort(isFinite(used) ? used : NaN)} / ${fmtBytesShort(quota)}`;
}

function quotaUsagePct(usedBytes, quotaBytes) {
    const used = Number(usedBytes);
    const quota = Number(quotaBytes);
    if (!isFinite(used) || !isFinite(quota) || quota <= 0) return 0;
    return clamp01(used / quota);
}


// allow multiple open rows
const openUsers = new Set(); // fingerprints


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

function avatarSrc(u) {
    const s = String(u?.avatar_url || "").trim();
    return s || "";
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
function shortFp(fp) {
    fp = String(fp || "");
    if (fp.length <= 20) return fp;
    return fp.slice(0, 12) + "…" + fp.slice(-12);
}
function avatarThumb(u) {
    const src = avatarSrc(u);
    if (!src) return `<div class="muted">—</div>`;
    return `
      <img
        src="${esc(src)}"
        alt="avatar"
        style="width:26px;height:26px;border-radius:8px;object-fit:cover;border:1px solid var(--border);background:var(--panel2);"
        title="Avatar"
        onerror="this.style.opacity='0.35'; this.title='Avatar failed to load';"
      />
    `.trim();
}
let avatarModalFp = "";
let avatarModalUrl = "";

function openAvatarModal(fp, url) {
    avatarModalFp = String(fp || "");
    avatarModalUrl = String(url || "");

    const m = $("avatarModal");
    const img = $("avatarModalImg");
    const rm = $("avatarRemoveBtn");

    if (!m || !img || !rm) return;

    img.src = avatarModalUrl || "";
    rm.disabled = !avatarModalFp;

    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");
}

function closeAvatarModal() {
    const m = $("avatarModal");
    const img = $("avatarModalImg");
    if (img) img.src = ""; // stop loading / free memory
    avatarModalFp = "";
    avatarModalUrl = "";

    if (m) {
        m.classList.remove("open");
        m.setAttribute("aria-hidden", "true");
    }
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
        t.style.background = "linear-gradient(180deg, var(--panel2), var(--panel))";
        t.style.color = "var(--fg)";
        t.style.boxShadow = "var(--shadow)";
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

        const fp = String(u.fingerprint || "");
        const isOpen = openUsers.has(fp);
        const isSelf = actorFp && fp === actorFp;

        const selfTag = isSelf
            ? `<span class="pill enabled" title="This is you" style="margin-left:8px;">you</span>`
            : "";

        // Disallow self-modification (Allocate is allowed for self)
        // Allow self profile editing, but block dangerous self-actions
        const disEditAttr = "";
        const disEditClass = "";

        const disDangerAttr = isSelf
            ? ` disabled title="Refusing to modify your own admin entry"`
            : "";

        const disDangerClass = isSelf
            ? ` style="opacity:0.45; cursor:not-allowed;"`
            : "";


        // detail content
        const quotaBytes = Number(u.quota_bytes || 0);
        const quotaText = quotaBytes ? fmtBytes(quotaBytes) : "—";

        const usedBytes = Number(u.used_bytes ?? u.storage_used_bytes ?? 0);
        const quotaBytes2 = Number(u.quota_bytes ?? 0);

        const pct = quotaBytes2 > 0 ? clamp01(usedBytes / quotaBytes2) : 0;
        const pct100 = (pct * 100).toFixed(1);

        const quotaCls =
            pct >= 0.90 ? "danger" :
                pct >= 0.70 ? "warn" :
                    "";

        const detailRow = isOpen ? `

<tr class="detailRow" data-fp="${esc(fp)}">
  <td colspan="10">
    <div class="detailGrid">
      <div class="detailBox">
        <h3>Profile</h3>
        ${avatarSrc(u) ? `
          <div style="display:flex; gap:12px; align-items:center; margin:10px 0 14px;">
            <img
              src="${esc(avatarSrc(u))}"
              alt="avatar"
              data-avatar-open="1"
              data-fp="${esc(fp)}"
              style="width:128px; height:128px; border-radius:22px; object-fit:cover; border:1px solid var(--border); background:var(--panel2); cursor:pointer;"
              title="Click to preview"
              onerror="this.style.borderColor='red'; this.title='Avatar failed to load';"
            />


            <div class="muted" style="line-height:1.25;">
              Avatar<br/>
              <span class="mono" style="font-size:12px;">${esc(avatarSrc(u))}</span>
            </div>
          </div>
        ` : `
          <div class="muted" style="margin:8px 0 14px;">
            Avatar: <span class="mono">—</span>
          </div>
        `}

        <div class="detailActions">
            <button class="btn secondary" data-edit="${esc(fp)}" type="button" ${disEditAttr}${disEditClass}>Edit</button>
        </div>

        <div class="detailKV"><div class="k">Fingerprint</div><div class="v mono">${esc(fp)}</div></div>
        <div class="detailKV"><div class="k">Name</div><div class="v">${esc(u.name || "—")}</div></div>
        <div class="detailKV"><div class="k">Role</div><div class="v">${esc(u.role || "—")}</div></div>
        <div class="detailKV"><div class="k">Status</div><div class="v">${pill(u.status)}</div></div>
        <div class="detailKV"><div class="k">Group</div><div class="v">${esc(u.group || "—")}</div></div>
        <div class="detailKV"><div class="k">Email</div><div class="v">${esc(u.email || "—")}</div></div>
        <div class="detailKV"><div class="k">Storage</div><div class="v">${storagePill(u.storage_state)}</div></div>
        <div class="detailKV"><div class="k">Quota</div><div class="v mono">${esc(quotaText)}</div></div>
        <div class="detailKV"><div class="k">Added</div><div class="v mono">${esc(u.added_at || "—")}</div></div>
        <div class="detailKV"><div class="k">Last seen</div><div class="v mono">${esc(u.last_seen || "—")}</div></div>
      </div>

      <div class="detailBox">
        <h3>Notes</h3>
        <pre class="detailPre">${esc(u.notes || "—")}</pre>

        <div class="quotaBox">
          <div class="quotaTop">
            <div class="quotaLabel">Storage usage</div>
            <div class="quotaNum mono">${esc(quotaUsageText(u.used_bytes ?? u.storage_used_bytes, u.quota_bytes))}</div>
          </div>
            <div class="quotaBar" title="${esc(quotaUsageText(usedBytes, quotaBytes2))}">
                <div class="quotaFill ${quotaCls}" style="width:${pct100}%"></div>
          </div>
        </div>
      </div>

<div class="detailBox">
  <h3>Actions</h3>
  <div class="detailActions">
    <button class="btn secondary"
            data-act="enable"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Enable</button>

    <button class="btn secondary"
            data-act="disable"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Disable</button>

    <button class="btn secondary"
            data-act="revoke"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Revoke</button>

    <button class="btn secondary"
            data-act="allocate"
            data-fp="${esc(fp)}"
            type="button">Allocate</button>

    <button class="btn danger"
            data-act="delete"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Delete</button>
  </div>

  ${isSelf
            ? `<div class="muted" style="margin-top:10px;">
         Self-protection: enable / disable / revoke / delete are blocked for your own fingerprint.
       </div>`
            : ``}
</div>

    </div>
  </td>
</tr>

    `.trim() : "";

        return `
<tr class="userRow" data-fp="${esc(fp)}" aria-expanded="${isOpen ? "true" : "false"}">
  <td>${avatarThumb(u)}</td>

  <td class="mono">
    <button class="expBtn" data-exp="${esc(fp)}" type="button" aria-expanded="${isOpen ? "true" : "false"}" title="Expand/collapse">
      ${isOpen ? "▾" : "▸"}
    </button>
    <span style="margin-left:8px;" title="${esc(fp)}">${esc(shortFp(fp))}</span>
  </td>

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

  <td class="row-actions">
    <span class="muted">Open ▸</span>
  </td>
</tr>
${detailRow}
`.trim();

    }).join("");

    // ✅ Attach avatar modal click via delegation (works across rerenders)
    tb.onclick = (ev) => {
        const img = ev.target?.closest?.('img[data-avatar-open="1"]');
        if (!img) return;
        ev.stopPropagation();
        const fp = img.getAttribute("data-fp") || "";
        const src = img.getAttribute("src") || "";
        if (!src) return;
        openAvatarModal(fp, src);
    };


// -------------------- Edit button: load user into form --------------------
    tb.querySelectorAll("button[data-edit]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            ev.stopPropagation();

            const fp = btn.getAttribute("data-edit");
            if (!fp) return;

            const u = allUsers.find(x => String(x.fingerprint || "") === fp);
            if (!u) return;

            // Fill the edit form
            $("fp").value = fp;
            $("name").value = u.name || "";
            $("role").value = (u.role || "user");
            $("notes").value = u.notes || "";
            $("email").value = u.email || "";
            $("avatar_url").value = u.avatar_url || "";

            // bring it into view + focus
            $("fp").scrollIntoView({ behavior: "smooth", block: "center" });
            $("name").focus();
        });
    });


    // Expand/collapse handlers
    tb.querySelectorAll("button[data-exp]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            ev.stopPropagation();
            const fp = btn.getAttribute("data-exp");
            if (!fp) return;
            if (openUsers.has(fp)) openUsers.delete(fp);
            else openUsers.add(fp);
            render(); // re-render keeps multiple open
        });
    });

    // Optional: clicking the row toggles (but don't toggle when clicking action buttons)
    tb.querySelectorAll("tr.userRow").forEach(tr => {
        tr.addEventListener("click", (ev) => {
            const t = ev.target;
            if (t && (t.closest("button") || t.closest("a") || t.closest("input") || t.closest("select") || t.closest("textarea"))) {
                return; // let controls work normally
            }
            const fp = tr.getAttribute("data-fp");
            if (!fp) return;
            if (openUsers.has(fp)) openUsers.delete(fp);
            else openUsers.add(fp);
            render();
        });
    });

    // Existing action buttons (enable/disable/revoke/allocate/delete)
    tb.querySelectorAll("button[data-act]").forEach(b => {
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

    const email = ($("email")?.value || "").trim();
    const avatar_url = ($("avatar_url")?.value || "").trim(); // only if you add this input

    if (!fp || fp.length < 32) throw new Error("fingerprint looks invalid");

    await apiPost("/api/v4/admin/users/upsert", {
        fingerprint: fp,
        name,
        role,
        notes,
        email,
        avatar_url,
    });

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

    // ---------------- Avatar picker wiring ----------------
    // Avatar modal wiring
    $("avatarCloseBtn")?.addEventListener("click", closeAvatarModal);
    $("avatarModal")?.addEventListener("click", (ev) => {
        // click on backdrop closes; click inside card does not
        if (ev.target && ev.target.id === "avatarModal") closeAvatarModal();
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") closeAvatarModal();
    });

    $("avatarRemoveBtn")?.addEventListener("click", async () => {
        if (!avatarModalFp) return;
        if (!confirm("Remove this user's avatar?")) return;

        try {
            setMsg("Removing avatar…");
            await apiPost("/api/v4/admin/users/avatar_remove", { fingerprint: avatarModalFp });
            closeAvatarModal();
            await refresh();
            setMsg("Avatar removed");
            showToast("Avatar removed");
        } catch (e) {
            setMsg("Error: " + e.message);
            alert("Remove failed: " + e.message);
        }
    });

    $("avatar_url")?.addEventListener("click", () => {
        $("avatar_file")?.click();
    });

    $("avatar_file")?.addEventListener("change", async () => {
        const file = $("avatar_file").files?.[0];
        if (!file) return;

        const fp = ($("fp")?.value || "").trim();
        if (!fp || fp.length < 32) {
            showToast("Select a user first (fingerprint missing).");
            return;
        }

        try {
            setMsg("Uploading avatar…");

            const buf = await file.arrayBuffer();
            const bytes = new Uint8Array(buf);

            let bin = "";
            for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
            const data_b64 = btoa(bin);

            const body = {
                fingerprint: fp,
                filename: file.name || "avatar",
                mime: file.type || "application/octet-stream",
                data_b64,
            };

            const j = await apiPost("/api/v4/admin/users/avatar_upload", body);

            $("avatar_url").value = j.avatar_url || "";
            setMsg("Avatar uploaded (click Upsert to save)");
            showToast("Avatar uploaded");
        } catch (e) {
            setMsg("Error: " + e.message);
            alert("Upload failed: " + e.message);
        } finally {
            $("avatar_file").value = "";
        }
    });


    // ------------------------------------------------------

    try { await refresh(); }
    catch (e) { setMsg("Failed to load users: " + e.message); }
});

