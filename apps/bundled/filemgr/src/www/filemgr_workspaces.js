(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (!FM) return;

    const scopeBar = document.getElementById("scopeBar");
    const scopeSelect = document.getElementById("scopeSelect");
    const scopeRole = document.getElementById("scopeRole");

    const favoritesToggleBtn = document.getElementById("favoritesToggleBtn");
    const uploadBtn = document.getElementById("uploadBtn");
    const uploadFolderBtn = document.getElementById("uploadFolderBtn");

    const workspaceMembersBtn = document.getElementById("workspaceMembersBtn");
    const workspaceLeaveBtn = document.getElementById("workspaceLeaveBtn");
    const workspaceMembersModal = document.getElementById("workspaceMembersModal");
    const workspaceMembersTitle = document.getElementById("workspaceMembersTitle");
    const workspaceMembersSub = document.getElementById("workspaceMembersSub");
    const workspaceMembersStatus = document.getElementById("workspaceMembersStatus");
    const workspaceMembersList = document.getElementById("workspaceMembersList");
    const workspaceMembersClose = document.getElementById("workspaceMembersClose");
    const SCOPE_KEY = "pqnas_filemgr_scope_v1";

    FM.scope = FM.scope || {
        mode: "user",            // "user" | "workspace"
        workspaceId: "",
        workspaceName: "",
        workspaceRole: ""
    };

    const workspaceEditorSessionId =
        (window.crypto && crypto.randomUUID)
            ? crypto.randomUUID()
            : ("wsedit-" + Date.now() + "-" + Math.random().toString(16).slice(2));

    function loadSavedScope() {
        try {
            const raw = localStorage.getItem(SCOPE_KEY);
            if (!raw) return;
            const j = JSON.parse(raw);
            if (!j || typeof j !== "object") return;

            FM.scope.mode = (j.mode === "workspace") ? "workspace" : "user";
            FM.scope.workspaceId = String(j.workspaceId || "");
            FM.scope.workspaceName = String(j.workspaceName || "");
            FM.scope.workspaceRole = String(j.workspaceRole || "");
        } catch (_) {}
    }

    function saveScope() {
        try {
            localStorage.setItem(SCOPE_KEY, JSON.stringify({
                mode: FM.scope.mode,
                workspaceId: FM.scope.workspaceId,
                workspaceName: FM.scope.workspaceName,
                workspaceRole: FM.scope.workspaceRole
            }));
        } catch (_) {}
    }

    function resetToUserScope() {
        FM.scope.mode = "user";
        FM.scope.workspaceId = "";
        FM.scope.workspaceName = "";
        FM.scope.workspaceRole = "";
        saveScope();
    }

    function isWorkspaceScope() {
        return FM.scope.mode === "workspace" && !!FM.scope.workspaceId;
    }

    function canCurrentScopeWrite() {
        if (!isWorkspaceScope()) return true;
        return FM.scope.workspaceRole === "owner" || FM.scope.workspaceRole === "editor";
    }

    function getCapabilities() {
        if (!isWorkspaceScope()) {
            return {
                favorites: true,
                shares: true,
                pqShares: true,
                textEdit: true,
                imagePreview: true,
                properties: true,
                zipFolder: true,
                zipSelection: true
            };
        }

        return {
            favorites: false,
            shares: canCurrentScopeWrite(),
            pqShares: false,
            textEdit: true,
            imagePreview: true,
            properties: true,
            zipFolder: true,
            zipSelection: true
        };
    }

    function listUrl(path) {
        if (!isWorkspaceScope()) {
            return path
                ? `/api/v4/files/list?path=${encodeURIComponent(path)}`
                : `/api/v4/files/list`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        if (path) qs.set("path", path);
        return `/api/v4/workspaces/files/list?${qs.toString()}`;
    }

    function mkdirUrl(path) {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/mkdir?path=${encodeURIComponent(path)}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path);
        return `/api/v4/workspaces/files/mkdir?${qs.toString()}`;
    }

    function putUrl(path, overwrite) {
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path);
            if (overwrite) qs.set("overwrite", "1");
            return `/api/v4/files/put?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path);
        if (overwrite) qs.set("overwrite", "1");
        return `/api/v4/workspaces/files/put?${qs.toString()}`;
    }
    function zipUrl(path, maxBytes) {
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path || "");
            if (maxBytes != null && Number(maxBytes) > 0) {
                qs.set("max_bytes", String(maxBytes));
            }
            return `/api/v4/files/zip?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path || "");
        if (maxBytes != null && Number(maxBytes) > 0) {
            qs.set("max_bytes", String(maxBytes));
        }
        return `/api/v4/workspaces/files/zip?${qs.toString()}`;
    }

    function zipSelUrl() {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/zip_sel`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        return `/api/v4/workspaces/files/zip_sel?${qs.toString()}`;
    }
    function getUrl(path) {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/get?path=${encodeURIComponent(path)}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path);
        return `/api/v4/workspaces/files/get?${qs.toString()}`;
    }

    function deleteUrl(path) {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/delete?path=${encodeURIComponent(path)}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path);
        return `/api/v4/workspaces/files/delete?${qs.toString()}`;
    }

    function moveUrl(from, to) {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/move?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("from", from);
        qs.set("to", to);
        return `/api/v4/workspaces/files/move?${qs.toString()}`;
    }

    function applyScopeUi() {
        const caps = getCapabilities();
        const writeOk = canCurrentScopeWrite();
        const inWorkspace = isWorkspaceScope();

        if (scopeRole) {
            if (inWorkspace) {
                scopeRole.textContent = FM.scope.workspaceRole || "";
                scopeRole.classList.toggle("hidden", !FM.scope.workspaceRole);
            } else {
                scopeRole.textContent = "";
                scopeRole.classList.add("hidden");
            }
        }

        if (favoritesToggleBtn) {
            favoritesToggleBtn.classList.toggle("hidden", !caps.favorites);
        }

        if (uploadBtn) uploadBtn.disabled = !writeOk;
        if (uploadFolderBtn) uploadFolderBtn.disabled = !writeOk;

        if (workspaceMembersBtn) {
            workspaceMembersBtn.classList.toggle("hidden", !inWorkspace);
        }
    }

    function statUrl(path) {
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path || ".");
            return `/api/v4/files/stat?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path || ".");
        return `/api/v4/workspaces/files/stat?${qs.toString()}`;
    }

    function statSelUrl() {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/stat_sel`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        return `/api/v4/workspaces/files/stat_sel?${qs.toString()}`;
    }

    function hashUrl(path, algo) {
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path || "");
            qs.set("algo", algo || "sha256");
            return `/api/v4/files/hash?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path || "");
        qs.set("algo", algo || "sha256");
        return `/api/v4/workspaces/files/hash?${qs.toString()}`;
    }

    function readTextUrl(path) {
        console.log("[workspaces.readTextUrl] workspaceScope =", isWorkspaceScope());
        console.log("[workspaces.readTextUrl] workspaceId =", FM.scope.workspaceId);
        console.log("[workspaces.readTextUrl] path =", path);
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path || "");
            return `/api/v4/files/read_text?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path || "");
        qs.set("session_id", workspaceEditorSessionId);
        return `/api/v4/workspaces/files/read_text?${qs.toString()}`;
    }

    function workspaceEditLeaseAcquireUrl(workspaceId) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        return `/api/v4/workspaces/files/edit_lease/acquire?${qs.toString()}`;
    }

    function workspaceEditLeaseRefreshUrl(workspaceId) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        return `/api/v4/workspaces/files/edit_lease/refresh?${qs.toString()}`;
    }

    function workspaceEditLeaseReleaseUrl(workspaceId) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        return `/api/v4/workspaces/files/edit_lease/release?${qs.toString()}`;
    }

    function writeTextUrl() {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/write_text`;
        }
        return `/api/v4/workspaces/files/write_text`;
    }

    function buildWriteTextBody(path, text, expectedMtimeEpoch, expectedSha256) {
        const body = {
            path: path || "",
            text: typeof text === "string" ? text : String(text ?? "")
        };

        if (expectedMtimeEpoch != null && expectedMtimeEpoch !== 0) {
            body.expected_mtime_epoch = expectedMtimeEpoch;
        }
        if (expectedSha256) {
            body.expected_sha256 = expectedSha256;
        }

        if (isWorkspaceScope()) {
            body.workspace_id = FM.scope.workspaceId;
            body.session_id = workspaceEditorSessionId;
        }

        return body;
    }

    async function acquireEditLease(path, leaseSeconds = 60) {
        if (!isWorkspaceScope()) {
            return {
                ok: true,
                edit: {
                    can_edit: true,
                    read_only: false,
                    locked_by_other: false
                }
            };
        }

        const r = await fetch(workspaceEditLeaseAcquireUrl(FM.scope.workspaceId), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: FM.scope.workspaceId,
                path: path || "",
                session_id: workspaceEditorSessionId,
                lease_seconds: leaseSeconds
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const err = new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
            err.status = r.status;
            err.response = j;
            throw err;
        }
        return j;
    }

    async function refreshEditLease(path, leaseSeconds = 60) {
        if (!isWorkspaceScope()) {
            return { ok: true };
        }

        const r = await fetch(workspaceEditLeaseRefreshUrl(FM.scope.workspaceId), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: FM.scope.workspaceId,
                path: path || "",
                session_id: workspaceEditorSessionId,
                lease_seconds: leaseSeconds
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const err = new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
            err.status = r.status;
            err.response = j;
            throw err;
        }
        return j;
    }

    async function releaseEditLease(path) {
        if (!isWorkspaceScope()) {
            return { ok: true, released: false };
        }

        const r = await fetch(workspaceEditLeaseReleaseUrl(FM.scope.workspaceId), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: FM.scope.workspaceId,
                path: path || "",
                session_id: workspaceEditorSessionId
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const err = new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
            err.status = r.status;
            err.response = j;
            throw err;
        }
        return j;
    }

    async function fetchWorkspaces() {
        const r = await fetch("/api/v4/workspaces", {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok || !Array.isArray(j.workspaces)) {
            throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
        }
        return j.workspaces;
    }

    async function fetchWorkspaceMembers(workspaceId) {
        const r = await fetch(`/api/v4/workspaces/members?workspace_id=${encodeURIComponent(workspaceId)}`, {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok || !Array.isArray(j.members)) {
            throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
        }
        return j;
    }

    async function apiLeaveWorkspace(workspaceId) {
        const r = await fetch("/api/v4/workspaces/leave", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ workspace_id: workspaceId })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
        }
        return j;
    }

    function populateScopeSelect(workspaces) {
        if (!scopeSelect) return;

        scopeSelect.innerHTML = "";

        const optUser = document.createElement("option");
        optUser.value = "user";
        optUser.textContent = "My files";
        scopeSelect.appendChild(optUser);

        for (const ws of workspaces) {
            if (!ws || !ws.workspace_id) continue;
            const opt = document.createElement("option");
            opt.value = `workspace:${ws.workspace_id}`;
            opt.textContent = ws.name || ws.workspace_id;
            opt.dataset.role = ws.role || "";
            opt.dataset.name = ws.name || "";
            scopeSelect.appendChild(opt);
        }

        if (isWorkspaceScope()) {
            const want = `workspace:${FM.scope.workspaceId}`;
            const found = Array.from(scopeSelect.options).some((o) => o.value === want);
            scopeSelect.value = found ? want : "user";
            if (!found) resetToUserScope();
        } else {
            scopeSelect.value = "user";
        }
    }

    async function refreshWorkspaceChoices() {
        try {
            const workspaces = await fetchWorkspaces();

            if (scopeBar) {
                scopeBar.classList.toggle("hidden", workspaces.length === 0);
            }

            populateScopeSelect(workspaces);
            applyScopeUi();
        } catch (e) {
            console.warn("Workspace refresh failed:", e);
            resetToUserScope();
            applyScopeUi();
        }
    }

    function closeWorkspaceMembersModal() {
        if (!workspaceMembersModal) return;
        workspaceMembersModal.classList.remove("show");
        workspaceMembersModal.setAttribute("aria-hidden", "true");
    }

    function memberStatusClass(status) {
        const s = String(status || "").toLowerCase();
        if (s === "enabled") return "ok";
        if (s === "invited") return "warn";
        if (s === "disabled") return "err";
        return "";
    }

    function renderWorkspaceMembers(items) {
        if (!workspaceMembersList) return;

        if (!Array.isArray(items) || !items.length) {
            workspaceMembersList.innerHTML = `<div class="mono" style="opacity:.8;">No members.</div>`;
            return;
        }

        workspaceMembersList.innerHTML = items.map((m) => {
            const fp = String(m.fingerprint || "");
            const role = String(m.role || "");
            const status = String(m.status || "");
            const addedAt = String(m.added_at || "");
            const addedBy = String(m.added_by || "");
            const respondedAt = String(m.responded_at || "");
            const respondedBy = String(m.responded_by || "");

            const respondedBits = [];
            if (respondedAt) respondedBits.push(`responded ${respondedAt}`);
            if (respondedBy) respondedBits.push(`by ${respondedBy}`);

            return `
            <div style="border:1px solid rgba(var(--fg-rgb),0.12); border-radius:14px; background:rgba(0,0,0,0.16); padding:12px;">
              <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:space-between;">
                <div class="mono" style="font-weight:900; overflow-wrap:anywhere;">${fp}</div>
                <span class="badge ${memberStatusClass(status)}">${status || "?"}</span>
              </div>

              <div style="margin-top:8px; display:grid; gap:4px;">
                <div><span class="k">Role</span> <span class="v">${role || "?"}</span></div>
                <div><span class="k">Added</span> <span class="v">${addedAt || "?"}${addedBy ? ` by ${addedBy}` : ""}</span></div>
                ${respondedBits.length ? `<div><span class="k">Response</span> <span class="v">${respondedBits.join(" ")}</span></div>` : ""}
              </div>
            </div>
        `;
        }).join("");
    }

    async function openWorkspaceMembersModal() {
        if (!isWorkspaceScope()) return;
        if (!workspaceMembersModal) return;

        workspaceMembersModal.classList.add("show");
        workspaceMembersModal.setAttribute("aria-hidden", "false");

        if (workspaceMembersTitle) {
            workspaceMembersTitle.textContent = "Workspace members";
        }
        if (workspaceMembersSub) {
            workspaceMembersSub.textContent = `${FM.scope.workspaceName || FM.scope.workspaceId}`;
        }
        if (workspaceMembersStatus) {
            workspaceMembersStatus.textContent = "Loading members…";
        }
        if (workspaceMembersList) {
            workspaceMembersList.innerHTML = "";
        }

        try {
            const j = await fetchWorkspaceMembers(FM.scope.workspaceId);
            renderWorkspaceMembers(j.members || []);
            if (workspaceMembersStatus) {
                workspaceMembersStatus.textContent = `${Array.isArray(j.members) ? j.members.length : 0} member(s)`;
            }
        } catch (e) {
            if (workspaceMembersStatus) {
                workspaceMembersStatus.textContent = `Failed to load members: ${String(e && e.message ? e.message : e)}`;
            }
            if (workspaceMembersList) {
                workspaceMembersList.innerHTML = "";
            }
        }
    }

    workspaceMembersBtn?.addEventListener("click", async () => {
        if (!isWorkspaceScope()) return;
        await openWorkspaceMembersModal();
    });

    workspaceMembersClose?.addEventListener("click", () => {
        closeWorkspaceMembersModal();
    });

    workspaceMembersModal?.addEventListener("click", (ev) => {
        if (ev.target === workspaceMembersModal) {
            closeWorkspaceMembersModal();
        }
    });

    workspaceLeaveBtn?.addEventListener("click", async () => {
        if (!isWorkspaceScope()) return;

        const workspaceId = FM.scope.workspaceId || "";
        const workspaceName = FM.scope.workspaceName || workspaceId;
        if (!workspaceId) return;

        const ok = confirm(
            `Leave workspace?\n\n` +
            `Workspace: ${workspaceName}\n\n` +
            `After leaving, it will disappear from the Location dropdown.`
        );
        if (!ok) return;

        const old = workspaceLeaveBtn.textContent;
        workspaceLeaveBtn.disabled = true;
        workspaceLeaveBtn.textContent = "Leaving…";

        try {
            await apiLeaveWorkspace(workspaceId);

            closeWorkspaceMembersModal();
            resetToUserScope();
            await refreshWorkspaceChoices();

            if (FM.clearSelection) FM.clearSelection();
            if (FM.setPathAndLoad) FM.setPathAndLoad("");

            alert(`You left workspace: ${workspaceName}`);
        } catch (e) {
            if (workspaceMembersStatus) {
                workspaceMembersStatus.textContent =
                    `Leave failed: ${String(e && e.message ? e.message : e)}`;
            }
        } finally {
            workspaceLeaveBtn.disabled = false;
            workspaceLeaveBtn.textContent = old;
        }
    });

    async function initWorkspaces() {
        loadSavedScope();

        try {
            const workspaces = await fetchWorkspaces();

            if (scopeBar) {
                scopeBar.classList.toggle("hidden", workspaces.length === 0);
            }

            populateScopeSelect(workspaces);
            applyScopeUi();

            scopeSelect?.addEventListener("change", async () => {
                const v = String(scopeSelect.value || "");
                if (v === "user") {
                    resetToUserScope();
                } else if (v.startsWith("workspace:")) {
                    const workspaceId = v.slice("workspace:".length);
                    const opt = scopeSelect.selectedOptions && scopeSelect.selectedOptions[0];

                    FM.scope.mode = "workspace";
                    FM.scope.workspaceId = workspaceId;
                    FM.scope.workspaceName = opt ? String(opt.dataset.name || opt.textContent || "") : "";
                    FM.scope.workspaceRole = opt ? String(opt.dataset.role || "") : "";
                    saveScope();
                } else {
                    resetToUserScope();
                }

                applyScopeUi();

                if (FM.clearSelection) FM.clearSelection();
                if (FM.setPathAndLoad) FM.setPathAndLoad("");
            });

            if (isWorkspaceScope() && FM.setPathAndLoad) {
                FM.setPathAndLoad("");
            }
        } catch (e) {
            console.warn("Workspace switcher init failed:", e);
            if (scopeBar) scopeBar.classList.add("hidden");
            resetToUserScope();
            applyScopeUi();
        }
    }
    FM.isWorkspaceScope = isWorkspaceScope;
    FM.getWorkspaceId = () => FM.scope.workspaceId || "";
    FM.getWorkspaceRole = () => FM.scope.workspaceRole || "";
    FM.canCurrentScopeWrite = canCurrentScopeWrite;
    FM.getCapabilities = getCapabilities;
    FM.getWorkspaceEditorSessionId = () => workspaceEditorSessionId;
    FM.workspaceEditorSessionId = workspaceEditorSessionId; // keep for compatibility

    FM.api = {
        listUrl,
        mkdirUrl,
        putUrl,
        getUrl,
        deleteUrl,
        moveUrl,
        statUrl,
        statSelUrl,
        hashUrl,
        zipUrl,
        zipSelUrl,
        readTextUrl,
        writeTextUrl,
        buildWriteTextBody,
        workspaceEditLeaseAcquireUrl,
        workspaceEditLeaseRefreshUrl,
        workspaceEditLeaseReleaseUrl,
        acquireEditLease,
        refreshEditLease,
        releaseEditLease,

        sharesListUrl() {
            if (!isWorkspaceScope()) return "/api/v4/shares/list";
            return `/api/v4/shares/list?workspace_id=${encodeURIComponent(FM.scope.workspaceId)}`;
        },

        applyShareCreateScope(body) {
            const out = (body && typeof body === "object") ? { ...body } : {};
            if (isWorkspaceScope()) {
                out.workspace_id = FM.scope.workspaceId;
            } else {
                delete out.workspace_id;
            }
            return out;
        }
    };

    initWorkspaces();
})();