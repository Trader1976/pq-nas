(() => {
    "use strict";

    const msg = document.getElementById("msg");
    const btnRefresh = document.getElementById("btnRefresh");

    const wsName = document.getElementById("wsName");
    const wsOwnerFp = document.getElementById("wsOwnerFp");
    const wsQuotaGb = document.getElementById("wsQuotaGb");
    const wsNotes = document.getElementById("wsNotes");
    const btnCreateWorkspace = document.getElementById("btnCreateWorkspace");

    const createOk = document.getElementById("createOk");
    const createErr = document.getElementById("createErr");

    const workspaceList = document.getElementById("workspaceList");

    let workspaces = [];
    let actorFp = "";

    function setMsg(t) {
        if (msg) msg.textContent = t || "";
    }

    function showOk(el, t) {
        if (!el) return;
        el.textContent = t || "";
        el.classList.toggle("show", !!t);
    }

    function showErr(el, t) {
        if (!el) return;
        el.textContent = t || "";
        el.classList.toggle("show", !!t);
    }

    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll("\"", "&quot;")
            .replaceAll("'", "&#39;");
    }

    function fmtSize(n) {
        const u = ["B", "KiB", "MiB", "GiB", "TiB"];
        let v = Number(n || 0);
        let i = 0;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
    }

    function displayMemberStatus(m) {
        const s = String(m && m.status || "").toLowerCase();
        const respondedAt = String(m && m.responded_at || "").trim();

        if (s === "disabled" && respondedAt) return "declined";
        if (s === "enabled" && respondedAt) return "accepted";
        return s || "";
    }

    function pillStatusClass(status) {
        const s = String(status || "").toLowerCase();
        if (s === "enabled" || s === "accepted") return "enabled";
        if (s === "disabled" || s === "declined") return "disabled";
        if (s === "invited") return "invited";
        return "";
    }
    function canDeleteWorkspace(ws) {
        const members = Array.isArray(ws.members) ? ws.members : [];
        const enabled = members.filter(m => String(m.status || "") === "enabled");
        return enabled.length === 1 && String(enabled[0].role || "") === "owner";
    }
    async function apiGetWorkspaces() {
        const r = await fetch("/api/v4/admin/workspaces", {
            credentials: "include",
            cache: "no-store"
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error)) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiCreateWorkspace(payload) {
        const r = await fetch("/api/v4/admin/workspaces/create", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiInviteMember(workspaceId, fingerprint, role) {
        const r = await fetch("/api/v4/admin/workspaces/members/add", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint,
                role
            })
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiRemoveMember(workspaceId, fingerprint) {
        const r = await fetch("/api/v4/admin/workspaces/members/remove", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint
            })
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiSetMemberRole(workspaceId, fingerprint, role) {
        const r = await fetch("/api/v4/admin/workspaces/members/set_role", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint,
                role
            })
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }
    async function apiDeleteWorkspace(workspaceId) {
        const r = await fetch("/api/v4/admin/workspaces/delete", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ workspace_id: workspaceId })
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiRenameWorkspace(workspaceId, name) {
        const r = await fetch("/api/v4/admin/workspaces/rename", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                name
            })
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.detail))
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`);
        }
        return j;
    }

    function memberRowHtml(ws, m) {
        const fp = escapeHtml(m.fingerprint || "");
        const role = escapeHtml(m.role || "viewer");

        const displayStatusRaw = displayMemberStatus(m);
        const status = escapeHtml(displayStatusRaw || m.status || "");
        const statusCls = pillStatusClass(displayStatusRaw || m.status);

        const respondedBits = [];
        if (displayStatusRaw === "declined" && m.responded_at) {
            respondedBits.push(`declined ${escapeHtml(m.responded_at)}`);
        } else if (displayStatusRaw === "accepted" && m.responded_at) {
            respondedBits.push(`accepted ${escapeHtml(m.responded_at)}`);
        } else if (m.responded_at) {
            respondedBits.push(`responded ${escapeHtml(m.responded_at)}`);
        }
        if (m.responded_by) respondedBits.push(`by ${escapeHtml(m.responded_by)}`);
        return `
            <div class="memberRow">
                <div class="memberFp">
                    <div class="mono">${fp}</div>
                    <div class="hint" style="margin-top:4px;">
                        added ${escapeHtml(m.added_at || "—")}
                        ${m.added_by ? ` by ${escapeHtml(m.added_by)}` : ""}
                        ${respondedBits.length ? ` • ${respondedBits.join(" ")}` : ""}
                    </div>
                </div>

                <div>
                    <span class="pill ${statusCls}">${status || "?"}</span>
                </div>

                <div>
                    <select class="memberRoleSel" data-workspace-id="${escapeHtml(ws.workspace_id || "")}" data-fingerprint="${fp}">
                        <option value="viewer" ${role === "viewer" ? "selected" : ""}>viewer</option>
                        <option value="editor" ${role === "editor" ? "selected" : ""}>editor</option>
                        <option value="owner" ${role === "owner" ? "selected" : ""}>owner</option>
                    </select>
                </div>

                <div class="row">
                    <button class="btn secondary memberRoleApplyBtn"
                            type="button"
                            data-workspace-id="${escapeHtml(ws.workspace_id || "")}"
                            data-fingerprint="${fp}">
                        Apply role
                    </button>
                    <button class="btn danger memberRemoveBtn"
                            type="button"
                            data-workspace-id="${escapeHtml(ws.workspace_id || "")}"
                            data-fingerprint="${fp}">
                        Remove
                    </button>
                </div>
            </div>
        `;
    }

    function workspaceCardHtml(ws) {
        const members = Array.isArray(ws.members) ? ws.members : [];
        const membersHtml = members.length
            ? members.map((m) => memberRowHtml(ws, m)).join("")
            : `<div class="hint">No members.</div>`;

        return `
            <div class="workspaceCard" data-workspace-id="${escapeHtml(ws.workspace_id || "")}">
                <div class="workspaceTop">
                    <div>
                        <div class="workspaceName">${escapeHtml(ws.name || ws.workspace_id || "Workspace")}</div>
                        <div class="hint mono" style="margin-top:6px;">${escapeHtml(ws.workspace_id || "")}</div>
                    </div>
                    <div class="row">
                        <span class="pill ${pillStatusClass(ws.status)}">${escapeHtml(ws.status || "?")}</span>
                        ${canDeleteWorkspace(ws) ? `
                            <button class="btn secondary workspaceRenameBtn"
                                    type="button"
                                    data-workspace-id="${escapeHtml(ws.workspace_id || "")}"
                                    data-workspace-name="${escapeHtml(ws.name || ws.workspace_id || "Workspace")}">
                                Rename
                            </button>
                            <button class="btn danger workspaceDeleteBtn"
                                    type="button"
                                    data-workspace-id="${escapeHtml(ws.workspace_id || "")}"
                                    data-workspace-name="${escapeHtml(ws.name || ws.workspace_id || "Workspace")}">
                                Delete workspace
                            </button>
                        ` : ""}
                    </div>
                </div>

                <div class="workspaceMeta">
                    <div class="k">Notes</div>
                    <div class="v">${escapeHtml(ws.notes || "—")}</div>

                    <div class="k">Owner / Created by</div>
                    <div class="v mono">${escapeHtml(ws.created_by || "—")}</div>

                    <div class="k">Created at</div>
                    <div class="v">${escapeHtml(ws.created_at || "—")}</div>

                    <div class="k">Storage state</div>
                    <div class="v">${escapeHtml(ws.storage_state || "—")}</div>

                    <div class="k">Pool</div>
                    <div class="v mono">${escapeHtml(ws.pool_id || ws.storage_pool_id || "default")}</div>

                    <div class="k">Quota</div>
                    <div class="v">${fmtSize(ws.quota_bytes || 0)}</div>

                    <div class="k">Root</div>
                    <div class="v mono">${escapeHtml(ws.root_rel || "—")}</div>

                    <div class="k">Members</div>
                    <div class="v">${Number(ws.member_count || members.length || 0)}</div>
                </div>

                <div class="membersBlock">
                    <div style="font-weight:900; margin-bottom:8px;">Members</div>
                    ${membersHtml}
                </div>

                <div class="memberInviteBlock">
                    <div style="font-weight:900;">Invite user</div>
                    <div class="hint">
                        Enter the user fingerprint. With the invitation flow you just added,
                        this creates a pending invite instead of immediate active access.
                    </div>

                    <div class="row">
                        <input class="inviteFp mono"
                               data-workspace-id="${escapeHtml(ws.workspace_id || "")}"
                               placeholder="Fingerprint hex"
                               style="flex:1; min-width:260px;" />

                        <select class="inviteRoleSel" data-workspace-id="${escapeHtml(ws.workspace_id || "")}">
                            <option value="viewer">viewer</option>
                            <option value="editor">editor</option>
                            <option value="owner">owner</option>
                        </select>

                        <button class="btn inviteMemberBtn"
                                type="button"
                                data-workspace-id="${escapeHtml(ws.workspace_id || "")}">
                            Invite user
                        </button>
                    </div>

                    <div class="hint">
                        Accepted invites appear in the user shell and then show up in File Manager.
                    </div>
                </div>
            </div>
        `;
    }

    function bindWorkspaceActions() {
        for (const btn of document.querySelectorAll(".workspaceRenameBtn")) {
            btn.addEventListener("click", async () => {
                const workspaceId = btn.dataset.workspaceId || "";
                const oldName = btn.dataset.workspaceName || "";
                if (!workspaceId) return;

                const nextName = prompt("New workspace name:", oldName);
                if (nextName == null) return;

                const name = String(nextName).trim();
                if (!name) {
                    setMsg("Rename failed: missing workspace name.");
                    return;
                }

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Renaming…";

                try {
                    await apiRenameWorkspace(workspaceId, name);
                    setMsg(`Renamed workspace: ${oldName} → ${name}`);
                    await load();
                } catch (e) {
                    setMsg(`Rename failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                    btn.textContent = old;
                }
            });
        }
        for (const btn of document.querySelectorAll(".workspaceDeleteBtn")) {
            btn.addEventListener("click", async () => {
                const workspaceId = btn.dataset.workspaceId || "";
                const workspaceName = btn.dataset.workspaceName || workspaceId;
                if (!workspaceId) return;

                const ok = confirm(
                    `Delete workspace permanently?\n\n` +
                    `Workspace: ${workspaceName}\n` +
                    `ID: ${workspaceId}\n\n` +
                    `This deletes the workspace record and its workspace directory.`
                );
                if (!ok) return;

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Deleting…";

                try {
                    await apiDeleteWorkspace(workspaceId);
                    setMsg(`Deleted workspace: ${workspaceName}`);
                    await load();
                } catch (e) {
                    setMsg(`Delete failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                    btn.textContent = old;
                }
            });
        }
        for (const btn of document.querySelectorAll(".inviteMemberBtn")) {
            btn.addEventListener("click", async () => {
                const workspaceId = btn.dataset.workspaceId || "";
                const fpInput = document.querySelector(`.inviteFp[data-workspace-id="${CSS.escape(workspaceId)}"]`);
                const roleSel = document.querySelector(`.inviteRoleSel[data-workspace-id="${CSS.escape(workspaceId)}"]`);

                const fingerprint = String(fpInput?.value || "").trim();
                const role = String(roleSel?.value || "viewer").trim();

                if (!workspaceId || !fingerprint) {
                    setMsg("Invite failed: missing workspace or fingerprint.");
                    return;
                }

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Inviting…";

                try {
                    await apiInviteMember(workspaceId, fingerprint, role);
                    if (fpInput) fpInput.value = "";
                    setMsg(`Invitation sent: ${fingerprint} → ${workspaceId}`);
                    await load();
                } catch (e) {
                    setMsg(`Invite failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                    btn.textContent = old;
                }
            });
        }

        for (const btn of document.querySelectorAll(".memberRemoveBtn")) {
            btn.addEventListener("click", async () => {
                const workspaceId = btn.dataset.workspaceId || "";
                const fingerprint = btn.dataset.fingerprint || "";
                if (!workspaceId || !fingerprint) return;

                const ok = confirm(`Remove member?\n\nWorkspace: ${workspaceId}\nFingerprint: ${fingerprint}`);
                if (!ok) return;

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Removing…";

                try {
                    await apiRemoveMember(workspaceId, fingerprint);
                    setMsg(`Removed member: ${fingerprint}`);
                    await load();
                } catch (e) {
                    setMsg(`Remove failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                    btn.textContent = old;
                }
            });
        }

        for (const btn of document.querySelectorAll(".memberRoleApplyBtn")) {
            btn.addEventListener("click", async () => {
                const workspaceId = btn.dataset.workspaceId || "";
                const fingerprint = btn.dataset.fingerprint || "";
                const sel = document.querySelector(`.memberRoleSel[data-workspace-id="${CSS.escape(workspaceId)}"][data-fingerprint="${CSS.escape(fingerprint)}"]`);
                const role = String(sel?.value || "viewer").trim();

                if (!workspaceId || !fingerprint) return;

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Saving…";

                try {
                    await apiSetMemberRole(workspaceId, fingerprint, role);
                    setMsg(`Updated role: ${fingerprint} → ${role}`);
                    await load();
                } catch (e) {
                    setMsg(`Role update failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                    btn.textContent = old;
                }
            });
        }
    }

    function applyDefaultOwnerFingerprint() {
        if (!wsOwnerFp) return;
        if (!actorFp) return;

        const cur = String(wsOwnerFp.value || "").trim();
        if (!cur) {
            wsOwnerFp.value = actorFp;
        }
    }

    function render() {
        if (!workspaceList) return;

        if (!workspaces.length) {
            workspaceList.innerHTML = `<div class="hint">No workspaces yet.</div>`;
            return;
        }

        workspaceList.innerHTML = workspaces.map(workspaceCardHtml).join("");
        bindWorkspaceActions();
    }

    async function load() {
        setMsg("Loading workspaces…");
        try {
            const j = await apiGetWorkspaces();
            actorFp = String(j.actor_fp || "").trim();
            workspaces = Array.isArray(j.workspaces) ? j.workspaces : [];
            applyDefaultOwnerFingerprint();
            render();
            setMsg(`Loaded ${workspaces.length} workspace(s).`);
        } catch (e) {
            actorFp = "";
            workspaces = [];
            render();
            setMsg(`Load failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    btnCreateWorkspace?.addEventListener("click", async () => {
        showOk(createOk, "");
        showErr(createErr, "");

        const payload = {
            name: String(wsName?.value || "").trim(),
            owner_fingerprint: String(wsOwnerFp?.value || "").trim(),
            quota_gb: Number(wsQuotaGb?.value || 0),
            notes: String(wsNotes?.value || "").trim()
        };

        if (!payload.name) {
            showErr(createErr, "Missing workspace name.");
            return;
        }
        if (!payload.owner_fingerprint) {
            showErr(createErr, "Missing owner fingerprint.");
            return;
        }

        btnCreateWorkspace.disabled = true;
        btnCreateWorkspace.textContent = "Creating…";

        try {
            const j = await apiCreateWorkspace(payload);
            showOk(createOk, `Workspace created: ${(j.workspace && j.workspace.name) || payload.name}`);
            if (wsName) wsName.value = "";
            if (wsOwnerFp) wsOwnerFp.value = actorFp || "";
            if (wsQuotaGb) wsQuotaGb.value = "";
            if (wsNotes) wsNotes.value = "";
            await load();
        } catch (e) {
            showErr(createErr, String(e && e.message ? e.message : e));
        } finally {
            btnCreateWorkspace.disabled = false;
            btnCreateWorkspace.textContent = "Create workspace";
        }
    });

    btnRefresh?.addEventListener("click", () => load());

    load();
})();