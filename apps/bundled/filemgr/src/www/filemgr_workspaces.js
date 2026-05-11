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
    const workspaceCreateSharedBtn = document.getElementById("workspaceCreateSharedBtn");
    const SCOPE_KEY = "pqnas_filemgr_scope_v1";

    FM.scope = FM.scope || {
        mode: "user",            // "user" | "workspace"
        workspaceId: "",
        workspaceName: "",
        workspaceRole: "",
        workspaceKind: "",
        workspaceDisplayKind: ""
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
            FM.scope.workspaceKind = String(j.workspaceKind || "");
            FM.scope.workspaceDisplayKind = String(j.workspaceDisplayKind || "");
        } catch (_) {}
    }

    function saveScope() {
        try {
            localStorage.setItem(SCOPE_KEY, JSON.stringify({
                mode: FM.scope.mode,
                workspaceId: FM.scope.workspaceId,
                workspaceName: FM.scope.workspaceName,
                workspaceRole: FM.scope.workspaceRole,
                workspaceKind: FM.scope.workspaceKind,
                workspaceDisplayKind: FM.scope.workspaceDisplayKind
            }));
        } catch (_) {}
    }

    function resetToUserScope() {
        FM.scope.mode = "user";
        FM.scope.workspaceId = "";
        FM.scope.workspaceName = "";
        FM.scope.workspaceRole = "";
        FM.scope.workspaceKind = "";
        FM.scope.workspaceDisplayKind = "";
        saveScope();
    }

    function isWorkspaceScope() {
        return FM.scope.mode === "workspace" && !!FM.scope.workspaceId;
    }

    function canCurrentScopeWrite() {
        if (!isWorkspaceScope()) return true;
        return FM.scope.workspaceRole === "owner" || FM.scope.workspaceRole === "editor";
    }

    function isCurrentScopePersonalSharedSpace() {
        return isWorkspaceScope() && String(FM.scope.workspaceKind || "") === "personal";
    }

    function currentWorkspaceKindLabel() {
        if (!isWorkspaceScope()) return "";
        return isCurrentScopePersonalSharedSpace() ? "Shared Space" : "Workspace";
    }

    function canCurrentScopeManageMembers() {
        return isWorkspaceScope() && FM.scope.workspaceRole === "owner";
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

    function copyUrl(from, to) {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/copy?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("from", from);
        qs.set("to", to);
        return `/api/v4/workspaces/files/copy?${qs.toString()}`;
    }
    
    function applyScopeUi() {
        const caps = getCapabilities();
        const writeOk = canCurrentScopeWrite();
        const inWorkspace = isWorkspaceScope();

        document.body.classList.toggle("scope-user", !inWorkspace);
        document.body.classList.toggle("scope-workspace", inWorkspace);

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

    async function apiCreateSharedSpace(name, notes) {
        const r = await fetch("/api/v4/workspaces/create", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                name,
                notes: notes || ""
            })
        });

        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j || !j.ok) {
            throw new Error(j.message || j.error || ("HTTP " + r.status));
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
        optUser.dataset.kind = "user";
        optUser.dataset.displayKind = "my_files";
        optUser.dataset.role = "";
        optUser.dataset.name = "My files";
        scopeSelect.appendChild(optUser);

        for (const ws of workspaces) {
            if (!ws || !ws.workspace_id) continue;

            const kind = String(ws.kind || "admin");
            const displayKind = String(ws.display_kind || "");
            const isSharedSpace = kind === "personal" || displayKind === "shared_space";
            const name = String(ws.name || ws.workspace_id);
            const label = isSharedSpace ? `Shared Space · ${name}` : `Workspace · ${name}`;

            const opt = document.createElement("option");
            opt.value = `workspace:${ws.workspace_id}`;
            opt.textContent = label;
            opt.dataset.name = name;
            opt.dataset.role = String(ws.role || "");
            opt.dataset.kind = kind;
            opt.dataset.displayKind = displayKind;
            scopeSelect.appendChild(opt);
        }

        if (isWorkspaceScope()) {
            const want = `workspace:${FM.scope.workspaceId}`;
            const found = Array.from(scopeSelect.options).some((o) => o.value === want);
            scopeSelect.value = found ? want : "user";

            if (!found) {
                resetToUserScope();
            } else {
                const opt = scopeSelect.selectedOptions && scopeSelect.selectedOptions[0];
                if (opt) {
                    FM.scope.workspaceName = String(opt.dataset.name || opt.textContent || "");
                    FM.scope.workspaceRole = String(opt.dataset.role || "");
                    FM.scope.workspaceKind = String(opt.dataset.kind || "admin");
                    FM.scope.workspaceDisplayKind = String(opt.dataset.displayKind || "");
                    saveScope();
                }
            }
        } else {
            scopeSelect.value = "user";
        }
    }

    async function refreshWorkspaceChoices() {
        try {
            const workspaces = await fetchWorkspaces();

            if (scopeBar) {
                scopeBar.classList.remove("hidden");
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

    async function apiInviteWorkspaceMember(workspaceId, fingerprint, role) {
        const r = await fetch("/api/v4/workspaces/members/invite", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint,
                role: role || "viewer"
            })
        });

        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j || !j.ok) {
            throw new Error(j.message || j.error || ("HTTP " + r.status));
        }
        return j;
    }

    async function apiSetWorkspaceMemberRole(workspaceId, fingerprint, role) {
        const r = await fetch("/api/v4/workspaces/members/set_role", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint,
                role: role || "viewer"
            })
        });

        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j || !j.ok) {
            throw new Error(j.message || j.error || ("HTTP " + r.status));
        }
        return j;
    }

    async function apiRemoveWorkspaceMember(workspaceId, fingerprint) {
        const r = await fetch("/api/v4/workspaces/members/remove", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                workspace_id: workspaceId,
                fingerprint
            })
        });

        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j || !j.ok) {
            throw new Error(j.message || j.error || ("HTTP " + r.status));
        }
        return j;
    }

    function statusClass(status) {
        const s = String(status || "").toLowerCase();
        if (s === "enabled") return "ok";
        if (s === "invited") return "invited";
        if (s === "disabled") return "danger";
        return "";
    }

    function styleWorkspaceMemberPill(el) {
        if (!el) return;
        el.style.display = "inline-flex";
        el.style.alignItems = "center";
        el.style.justifyContent = "center";
        el.style.minHeight = "28px";
        el.style.padding = "6px 12px";
        el.style.borderRadius = "999px";
        el.style.lineHeight = "1.15";
        el.style.fontSize = "12px";
        el.style.fontWeight = "900";
        el.style.whiteSpace = "nowrap";
    }


    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll("\"", "&quot;")
            .replaceAll("'", "&#39;");
    }

    function externalWorkspaceAccessUrl(workspaceId) {
        const ws = encodeURIComponent(String(workspaceId || "").trim());
        return `${window.location.origin}/static/external_workspace.html?workspace_id=${ws}`;
    }

    async function copyTextToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return;
        }

        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "readonly");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();

        try {
            document.execCommand("copy");
        } finally {
            ta.remove();
        }
    }

    async function apiCreateWorkspaceExternalInvite(workspaceId, role, expiresInSeconds) {
        const r = await fetch("/api/v4/workspaces/external-invites/create", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                role: role || "viewer",
                expires_in_seconds: expiresInSeconds || 86400
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

    function renderWorkspaceMembers(members) {
        if (!workspaceMembersList) return;

        const canManage = canCurrentScopeManageMembers();
        const workspaceId = FM.scope.workspaceId || "";

        workspaceMembersList.innerHTML = "";

        if (!Array.isArray(members) || !members.length) {
            const empty = document.createElement("div");
            empty.className = "mono";
            empty.style.opacity = ".8";
            empty.textContent = "No members.";
            workspaceMembersList.appendChild(empty);
            return;
        }

        function addLine(parent, label, value) {
            const div = document.createElement("div");
            div.style.fontSize = "12px";

            const b = document.createElement("b");
            b.textContent = label;
            div.appendChild(b);

            div.appendChild(document.createTextNode(" " + (value || "—")));
            parent.appendChild(div);
        }

        async function reloadMembers() {
            await openWorkspaceMembersModal();
        }

        for (const m of members) {
            const fp = String(m.fingerprint || "");
            const role = String(m.role || "viewer");
            const status = String(m.status || "");
            const name = String(m.name || m.display_name || m.email || "");
            const avatar = String(m.avatar_url || "");
            const label = name || (fp ? fp.slice(0, 18) + "…" : "Member");

            const row = document.createElement("div");
            row.className = "memberRow";
            row.dataset.fingerprint = fp;
            row.style.display = "grid";
            row.style.gap = "10px";
            row.style.padding = "12px";
            row.style.border = "1px solid rgba(var(--fg-rgb),0.14)";
            row.style.borderRadius = "14px";
            row.style.background = "rgba(255,255,255,0.035)";

            const top = document.createElement("div");
            top.style.display = "grid";
            top.style.gridTemplateColumns = "48px minmax(0,1fr)";
            top.style.gap = "12px";
            top.style.alignItems = "start";

            const avatarWrap = document.createElement("div");
            if (avatar) {
                const img = document.createElement("img");
                img.src = avatar;
                img.alt = "";
                img.style.width = "48px";
                img.style.height = "48px";
                img.style.borderRadius = "12px";
                img.style.objectFit = "cover";
                img.style.border = "1px solid rgba(var(--fg-rgb),0.18)";
                avatarWrap.appendChild(img);
            } else {
                const blank = document.createElement("div");
                blank.style.width = "48px";
                blank.style.height = "48px";
                blank.style.borderRadius = "12px";
                blank.style.border = "1px solid rgba(var(--fg-rgb),0.18)";
                blank.style.background = "rgba(255,255,255,0.06)";
                avatarWrap.appendChild(blank);
            }

            const info = document.createElement("div");
            info.style.minWidth = "0";

            const head = document.createElement("div");
            head.style.display = "flex";
            head.style.gap = "8px";
            head.style.alignItems = "center";
            head.style.justifyContent = "space-between";
            head.style.flexWrap = "wrap";

            const title = document.createElement("div");
            title.style.fontWeight = "900";
            title.textContent = label;
            head.appendChild(title);

            const pills = document.createElement("div");
            pills.style.display = "flex";
            pills.style.gap = "8px";
            pills.style.alignItems = "center";
            pills.style.flexWrap = "wrap";

            const statusPill = document.createElement("span");
            statusPill.className = "pill " + statusClass(status);
            statusPill.textContent = status || "unknown";
            styleWorkspaceMemberPill(statusPill);
            pills.appendChild(statusPill);

            const rolePill = document.createElement("span");
            rolePill.className = "pill";
            rolePill.textContent = role;
            styleWorkspaceMemberPill(rolePill);
            pills.appendChild(rolePill);

            head.appendChild(pills);
            info.appendChild(head);

            const fpLine = document.createElement("div");
            fpLine.className = "mono";
            fpLine.style.opacity = ".78";
            fpLine.style.fontSize = "12px";
            fpLine.style.overflowWrap = "anywhere";
            fpLine.style.marginTop = "4px";
            fpLine.textContent = fp;
            info.appendChild(fpLine);

            const meta = document.createElement("div");
            meta.style.marginTop = "10px";
            meta.style.display = "grid";
            meta.style.gap = "4px";
            addLine(meta, "Added", String(m.added_at || "—"));
            addLine(meta, "Response", String(m.responded_at || "—"));
            info.appendChild(meta);

            top.appendChild(avatarWrap);
            top.appendChild(info);
            row.appendChild(top);

            if (canManage && fp) {
                const controls = document.createElement("div");
                controls.style.display = "flex";
                controls.style.gap = "8px";
                controls.style.alignItems = "center";
                controls.style.flexWrap = "wrap";
                controls.style.paddingTop = "8px";
                controls.style.borderTop = "1px solid rgba(var(--fg-rgb),0.10)";

                const sel = document.createElement("select");
                sel.style.minWidth = "130px";
                for (const r of ["viewer", "editor", "owner"]) {
                    const opt = document.createElement("option");
                    opt.value = r;
                    opt.textContent = r;
                    opt.selected = (r === role);
                    sel.appendChild(opt);
                }
                controls.appendChild(sel);

                const apply = document.createElement("button");
                apply.className = "btn secondary";
                apply.type = "button";
                apply.textContent = "Apply role";
                apply.addEventListener("click", async () => {
                    const old = apply.textContent;
                    apply.disabled = true;
                    apply.textContent = "Applying…";
                    try {
                        await apiSetWorkspaceMemberRole(workspaceId, fp, String(sel.value || "viewer"));
                        await reloadMembers();
                    } catch (e) {
                        if (workspaceMembersStatus) workspaceMembersStatus.textContent = "Role update failed: " + String(e && e.message ? e.message : e);
                        apply.disabled = false;
                        apply.textContent = old;
                    }
                });
                controls.appendChild(apply);

                if (status !== "enabled") {
                    const reinvite = document.createElement("button");
                    reinvite.className = "btn secondary";
                    reinvite.type = "button";
                    reinvite.textContent = "Re-invite";
                    reinvite.addEventListener("click", async () => {
                        const old = reinvite.textContent;
                        reinvite.disabled = true;
                        reinvite.textContent = "Re-inviting…";
                        try {
                            await apiInviteWorkspaceMember(workspaceId, fp, String(sel.value || "viewer"));
                            await reloadMembers();
                        } catch (e) {
                            if (workspaceMembersStatus) workspaceMembersStatus.textContent = "Re-invite failed: " + String(e && e.message ? e.message : e);
                            reinvite.disabled = false;
                            reinvite.textContent = old;
                        }
                    });
                    controls.appendChild(reinvite);
                }

                const remove = document.createElement("button");
                remove.className = "btn danger";
                remove.type = "button";
                remove.textContent = "Remove";
                remove.addEventListener("click", async () => {
                    if (!confirm("Remove member from Shared Space?\n\n" + fp)) return;

                    const old = remove.textContent;
                    remove.disabled = true;
                    remove.textContent = "Removing…";
                    try {
                        await apiRemoveWorkspaceMember(workspaceId, fp);
                        await reloadMembers();
                    } catch (e) {
                        if (workspaceMembersStatus) workspaceMembersStatus.textContent = "Remove failed: " + String(e && e.message ? e.message : e);
                        remove.disabled = false;
                        remove.textContent = old;
                    }
                });
                controls.appendChild(remove);

                row.appendChild(controls);
            }

            workspaceMembersList.appendChild(row);
        }
    }


    function ensureExternalWorkspaceAccessPanel() {
        if (!workspaceMembersModal) return;
        if (document.getElementById("sharedSpaceExternalAccessPanel")) return;

        const body = workspaceMembersModal.querySelector(".modalBody");
        if (!body || !workspaceMembersList) return;

        const panel = document.createElement("div");
        panel.id = "sharedSpaceExternalAccessPanel";
        panel.style.cssText = "margin-bottom:12px; padding:10px; border:1px solid rgba(255,128,0,.28); border-radius:14px; background:rgba(255,128,0,0.045);";

        panel.innerHTML = `
            <div style="font-weight:900; margin-bottom:8px;">External access</div>
            <div class="hint" style="margin-bottom:10px;">
                Share a stable access page with accepted external members, or create a one-time QR invite for a new external DNA Connect identity.
            </div>

            <div class="row" style="margin-bottom:12px;">
                <button id="sharedSpaceCopyExternalAccessBtn" class="btn secondary" type="button">
                    Copy external access link
                </button>
            </div>

            <div id="sharedSpaceExternalInviteControls">
                <div class="hint" style="margin-bottom:8px;">
                    Owner only: create an external invite QR. The outsider scans this once with DNA Connect to become an external workspace member.
                </div>

                <div class="row">
                    <select id="sharedSpaceExternalInviteRole">
                        <option value="viewer">viewer</option>
                        <option value="editor">editor</option>
                    </select>

                    <select id="sharedSpaceExternalInviteExpiry">
                        <option value="3600">1 hour</option>
                        <option value="86400" selected>24 hours</option>
                        <option value="604800">7 days</option>
                    </select>

                    <button id="sharedSpaceExternalInviteBtn" class="btn" type="button">
                        Create external invite QR
                    </button>
                </div>

                <div id="sharedSpaceExternalInviteResult" style="margin-top:12px;"></div>
            </div>
        `;

        body.insertBefore(panel, workspaceMembersList);

        const copyBtn = panel.querySelector("#sharedSpaceCopyExternalAccessBtn");
        copyBtn?.addEventListener("click", async () => {
            const workspaceId = FM.scope.workspaceId || "";
            if (!workspaceId) {
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = "Copy failed: missing workspace.";
                return;
            }

            const url = externalWorkspaceAccessUrl(workspaceId);
            const old = copyBtn.textContent;

            copyBtn.disabled = true;
            copyBtn.textContent = "Copying…";

            try {
                await copyTextToClipboard(url);
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = `Copied external access link: ${url}`;
                copyBtn.textContent = "Copied";
                setTimeout(() => {
                    copyBtn.textContent = old;
                    copyBtn.disabled = false;
                }, 1200);
            } catch (e) {
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = `Copy failed: ${String(e && e.message ? e.message : e)}`;
                copyBtn.textContent = old;
                copyBtn.disabled = false;
            }
        });

        const inviteBtn = panel.querySelector("#sharedSpaceExternalInviteBtn");
        inviteBtn?.addEventListener("click", async () => {
            const workspaceId = FM.scope.workspaceId || "";
            const role = String(panel.querySelector("#sharedSpaceExternalInviteRole")?.value || "viewer");
            const expires = Number(panel.querySelector("#sharedSpaceExternalInviteExpiry")?.value || 86400);
            const result = panel.querySelector("#sharedSpaceExternalInviteResult");

            if (!workspaceId) {
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = "External invite failed: missing workspace.";
                return;
            }

            const old = inviteBtn.textContent;
            inviteBtn.disabled = true;
            inviteBtn.textContent = "Creating…";
            if (result) result.innerHTML = "";

            try {
                const j = await apiCreateWorkspaceExternalInvite(workspaceId, role, expires);
                const inviteId = String(j.invite && j.invite.invite_id || "");
                const qrPath = String(j.qr_svg || "");

                if (!qrPath) throw new Error("server did not return qr_svg");

                const qrUrl = `${window.location.origin}${qrPath}`;

                if (result) {
                    result.innerHTML = `
                        <div class="hint" style="margin-bottom:8px;">
                            Invite created: <span class="mono">${escapeHtml(inviteId)}</span>
                        </div>

                        <div class="row" style="margin-bottom:10px;">
                            <button id="sharedSpaceCopyExternalInviteQrLinkBtn"
                                    class="btn secondary"
                                    type="button"
                                    data-url="${escapeHtml(qrUrl)}">
                                Copy invite QR link
                            </button>

                            <a class="btn secondary"
                               href="${escapeHtml(qrUrl)}"
                               target="_blank"
                               rel="noopener noreferrer"
                               style="text-decoration:none;">
                                Open QR
                            </a>
                        </div>

                        <div style="display:inline-flex; background:#fff; border-radius:14px; padding:12px; max-width:280px;">
                            <img alt="External invite QR"
                                 src="${escapeHtml(qrPath)}"
                                 style="width:240px; height:auto; display:block;">
                        </div>

                        <div class="hint" style="margin-top:8px;">
                            Send the invite QR link to the outsider. They open it and scan the QR with DNA Connect.
                            After acceptance, send them the external access link for future visits.
                        </div>
                    `;

                    const copyQrLinkBtn = result.querySelector("#sharedSpaceCopyExternalInviteQrLinkBtn");
                    copyQrLinkBtn?.addEventListener("click", async () => {
                        const url = copyQrLinkBtn.dataset.url || qrUrl;
                        const oldText = copyQrLinkBtn.textContent;
                        copyQrLinkBtn.disabled = true;
                        copyQrLinkBtn.textContent = "Copying…";

                        try {
                            await copyTextToClipboard(url);
                            if (workspaceMembersStatus) {
                                workspaceMembersStatus.textContent = `Copied invite QR link: ${url}`;
                            }
                            copyQrLinkBtn.textContent = "Copied";
                            setTimeout(() => {
                                copyQrLinkBtn.textContent = oldText;
                                copyQrLinkBtn.disabled = false;
                            }, 1200);
                        } catch (e) {
                            if (workspaceMembersStatus) {
                                workspaceMembersStatus.textContent = `Copy invite QR link failed: ${String(e && e.message ? e.message : e)}`;
                            }
                            copyQrLinkBtn.textContent = oldText;
                            copyQrLinkBtn.disabled = false;
                        }
                    });
                }

                if (workspaceMembersStatus) workspaceMembersStatus.textContent = `External invite QR created for ${role}.`;
            } catch (e) {
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = `External invite failed: ${String(e && e.message ? e.message : e)}`;
            } finally {
                inviteBtn.disabled = false;
                inviteBtn.textContent = old;
            }
        });
    }

    function ensureSharedSpaceInvitePanel() {
        if (!workspaceMembersModal || document.getElementById("sharedSpaceInvitePanel")) return;

        const body = workspaceMembersModal.querySelector(".modalBody");
        if (!body || !workspaceMembersList) return;

        const panel = document.createElement("div");
        panel.id = "sharedSpaceInvitePanel";
        panel.style.cssText = "display:none; margin-bottom:12px; padding:10px; border:1px solid rgba(var(--fg-rgb),0.16); border-radius:14px; background:rgba(255,255,255,0.035);";
        panel.innerHTML = `
            <div style="font-weight:900; margin-bottom:8px;">Invite member</div>
            <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                <input id="sharedSpaceInviteFp" class="mono" placeholder="Fingerprint" style="flex:1; min-width:260px;" />
                <select id="sharedSpaceInviteRole" style="min-width:120px;">
                    <option value="viewer">viewer</option>
                    <option value="editor" selected>editor</option>
                    <option value="owner">owner</option>
                </select>
                <button id="sharedSpaceInviteBtn" class="btn" type="button">Invite</button>
            </div>
            <div class="mono" style="opacity:.7; font-size:12px; margin-top:8px;">
                The invited user will see this under Shared Space invites.
            </div>
        `;

        body.insertBefore(panel, workspaceMembersList);

        const inviteBtn = panel.querySelector("#sharedSpaceInviteBtn");
        inviteBtn?.addEventListener("click", async () => {
            const fpEl = panel.querySelector("#sharedSpaceInviteFp");
            const roleEl = panel.querySelector("#sharedSpaceInviteRole");
            const fp = String(fpEl?.value || "").trim();
            const role = String(roleEl?.value || "viewer").trim();
            const workspaceId = FM.scope.workspaceId || "";

            if (!workspaceId || !fp) {
                if (workspaceMembersStatus) workspaceMembersStatus.textContent = "Invite failed: missing fingerprint.";
                return;
            }

            const old = inviteBtn.textContent;
            inviteBtn.disabled = true;
            inviteBtn.textContent = "Inviting…";

            try {
                await apiInviteWorkspaceMember(workspaceId, fp, role);
                if (fpEl) fpEl.value = "";
                await openWorkspaceMembersModal();
            } catch (e) {
                if (workspaceMembersStatus) {
                    workspaceMembersStatus.textContent = `Invite failed: ${String(e && e.message ? e.message : e)}`;
                }
            } finally {
                inviteBtn.disabled = false;
                inviteBtn.textContent = old;
            }
        });
    }

    function updateLegacyWorkspaceManagementFooter() {
        if (!workspaceMembersModal) return;

        const canManage = canCurrentScopeManageMembers();
        const footers = Array.from(workspaceMembersModal.querySelectorAll(".modalBody > div, .modalBody > section"));

        for (const el of footers) {
            const text = String(el.textContent || "");
            if (text.includes("Workspace member changes are managed outside File Manager")) {
                el.style.display = canManage ? "none" : "";
            }
        }
    }

    async function openWorkspaceMembersModal() {
        if (!isWorkspaceScope()) return;
        if (!workspaceMembersModal) return;

        workspaceMembersModal.classList.add("show");
        workspaceMembersModal.setAttribute("aria-hidden", "false");

        if (workspaceMembersTitle) {
            workspaceMembersTitle.textContent = canCurrentScopeManageMembers() ? "Manage Shared Space members" : `${currentWorkspaceKindLabel()} members`;
        }
        if (workspaceMembersSub) {
            workspaceMembersSub.textContent = `${FM.scope.workspaceName || FM.scope.workspaceId}`;
        }
        if (workspaceMembersStatus) {
            workspaceMembersStatus.textContent = "Loading members…";
        }
        ensureSharedSpaceInvitePanel();
        ensureExternalWorkspaceAccessPanel();

        const invitePanel = document.getElementById("sharedSpaceInvitePanel");
        if (invitePanel) {
            invitePanel.style.display = canCurrentScopeManageMembers() ? "block" : "none";
        }

        const externalPanel = document.getElementById("sharedSpaceExternalAccessPanel");
        if (externalPanel) {
            externalPanel.style.display = "block";
            const externalInviteControls = externalPanel.querySelector("#sharedSpaceExternalInviteControls");
            if (externalInviteControls) {
                externalInviteControls.style.display =
                    String(FM.scope.workspaceRole || "") === "owner" ? "block" : "none";
            }
        }

        updateLegacyWorkspaceManagementFooter();

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

    function ensureCreateSharedSpaceModalStyle() {
        if (document.getElementById("sharedSpaceCreateModalWideStyle")) return;

        const st = document.createElement("style");
        st.id = "sharedSpaceCreateModalWideStyle";
        st.textContent = `
            #sharedSpaceCreateModal .modalCard{
                width: min(760px, calc(100vw - 48px)) !important;
                max-width: 760px !important;
            }
            #sharedSpaceCreateModal .modalBody{
                padding: 18px !important;
            }
            #sharedSpaceCreateModal .ssCreateForm{
                display: grid !important;
                gap: 16px !important;
                width: 100% !important;
                max-width: none !important;
            }
            #sharedSpaceCreateModal .ssFormField{
                display: grid !important;
                gap: 8px !important;
                width: 100% !important;
                max-width: none !important;
                min-width: 0 !important;
            }
            #sharedSpaceCreateModal .ssInput,
            #sharedSpaceCreateModal .ssTextarea{
                display: block !important;
                width: 100% !important;
                max-width: none !important;
                min-width: 0 !important;
                box-sizing: border-box !important;
                padding: 11px 12px !important;
                border-radius: 12px !important;
                border: 1px solid rgba(var(--fg-rgb),0.24) !important;
                background: rgba(255,255,255,0.06) !important;
                color: var(--fg) !important;
                font-size: 14px !important;
            }
            #sharedSpaceCreateModal .ssInput{
                min-height: 44px !important;
            }
            #sharedSpaceCreateModal .ssTextarea{
                min-height: 125px !important;
                resize: vertical !important;
                line-height: 1.35 !important;
                font-family: var(--sans) !important;
            }
        `;
        document.head.appendChild(st);
    }

    function openCreateSharedSpaceModal() {
        return new Promise((resolve) => {
            // Important: File Manager iframes can stay alive in the shell.
            // Remove any older/narrow modal DOM before creating the current one.
            const oldModal = document.getElementById("sharedSpaceCreateModal");
            if (oldModal) oldModal.remove();

            ensureCreateSharedSpaceModalStyle();

            const modal = document.createElement("div");
            modal.id = "sharedSpaceCreateModal";
            modal.className = "modal";
            modal.setAttribute("aria-hidden", "true");

            modal.innerHTML = `
                <div class="modalCard" role="dialog" aria-modal="true" aria-labelledby="sharedSpaceCreateTitle">
                    <div class="modalHead">
                        <div>
                            <div id="sharedSpaceCreateTitle" class="modalTitle">New Shared Space</div>
                            <div class="modalSub mono">Create a private collaboration space</div>
                        </div>
                        <button class="btn secondary" type="button" data-ss-cancel>Close</button>
                    </div>

                    <div class="modalBody">
                        <div class="ssCreateForm">
                            <label class="ssFormField">
                                <span style="font-weight:900;">Name</span>
                                <input class="ssInput"
                                       data-ss-name
                                       maxlength="80"
                                       autocomplete="off"
                                       placeholder="Family photos, Project files, Trip planning…" />
                            </label>

                            <label class="ssFormField">
                                <span style="font-weight:900;">Notes <span style="opacity:.65; font-weight:700;">optional</span></span>
                                <textarea class="ssTextarea"
                                          data-ss-notes
                                          maxlength="300"
                                          rows="4"
                                          placeholder="What is this Shared Space for?"></textarea>
                            </label>

                            <div data-ss-status class="mono" style="min-height:18px; opacity:.85;"></div>
                        </div>
                    </div>

                    <div class="modalFoot" style="display:flex; justify-content:flex-end; gap:10px;">
                        <button class="btn secondary" type="button" data-ss-cancel>Cancel</button>
                        <button class="btn" type="button" data-ss-create>Create Shared Space</button>
                    </div>
                </div>
            `;

            document.body.appendChild(modal);

            const nameInput = modal.querySelector("[data-ss-name]");
            const notesInput = modal.querySelector("[data-ss-notes]");
            const statusEl = modal.querySelector("[data-ss-status]");
            const createBtn = modal.querySelector("[data-ss-create]");
            const cancelBtns = modal.querySelectorAll("[data-ss-cancel]");

            // Force modal form sizing directly. Some global File Manager/theme
            // control styles can otherwise keep inputs at their old small width.
            const card = modal.querySelector(".modalCard");
            const body = modal.querySelector(".modalBody");
            const form = modal.querySelector(".ssCreateForm");

            function forceStyle(el, props) {
                if (!el) return;
                for (const [k, v] of Object.entries(props)) {
                    el.style.setProperty(k, v, "important");
                }
            }

            forceStyle(card, {
                "width": "min(760px, calc(100vw - 48px))",
                "max-width": "760px"
            });

            forceStyle(body, {
                "display": "block",
                "width": "100%",
                "max-width": "none",
                "padding": "18px"
            });

            forceStyle(form, {
                "display": "grid",
                "gap": "16px",
                "width": "100%",
                "max-width": "none",
                "min-width": "0"
            });

            for (const label of modal.querySelectorAll(".ssFormField")) {
                forceStyle(label, {
                    "display": "grid",
                    "gap": "8px",
                    "width": "100%",
                    "max-width": "none",
                    "min-width": "0"
                });
            }

            forceStyle(nameInput, {
                "display": "block",
                "width": "100%",
                "max-width": "none",
                "min-width": "0",
                "box-sizing": "border-box",
                "min-height": "44px",
                "padding": "11px 12px",
                "font-size": "14px"
            });

            forceStyle(notesInput, {
                "display": "block",
                "width": "100%",
                "max-width": "none",
                "min-width": "0",
                "box-sizing": "border-box",
                "min-height": "125px",
                "padding": "11px 12px",
                "font-size": "14px",
                "line-height": "1.35",
                "resize": "vertical"
            });

            let done = false;

            function close(result) {
                if (done) return;
                done = true;
                modal.classList.remove("show");
                modal.setAttribute("aria-hidden", "true");
                modal.remove();
                resolve(result || null);
            }

            function submit() {
                const name = String(nameInput?.value || "").trim();
                const notes = String(notesInput?.value || "").trim();

                if (!name) {
                    if (statusEl) statusEl.textContent = "Shared Space name is required.";
                    nameInput?.focus();
                    return;
                }

                close({ name, notes });
            }

            createBtn?.addEventListener("click", submit);

            for (const btn of cancelBtns) {
                btn.addEventListener("click", () => close(null));
            }

            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) close(null);
            });

            modal.addEventListener("keydown", (ev) => {
                if (ev.key === "Escape") close(null);
                if (ev.key === "Enter" && ev.ctrlKey) submit();
            });

            modal.classList.add("show");
            modal.setAttribute("aria-hidden", "false");

            setTimeout(() => nameInput?.focus(), 30);
        });
    }

    workspaceCreateSharedBtn?.addEventListener("click", async () => {
        const payload = await openCreateSharedSpaceModal();
        if (!payload) return;

        const old = workspaceCreateSharedBtn.textContent;
        workspaceCreateSharedBtn.disabled = true;
        workspaceCreateSharedBtn.textContent = "Creating…";

        try {
            const j = await apiCreateSharedSpace(payload.name, payload.notes);
            const ws = j && j.workspace ? j.workspace : null;
            if (!ws || !ws.workspace_id) {
                throw new Error("create response did not include workspace");
            }

            FM.scope.mode = "workspace";
            FM.scope.workspaceId = String(ws.workspace_id || "");
            FM.scope.workspaceName = String(ws.name || ws.workspace_id || "");
            FM.scope.workspaceRole = String(ws.role || "owner");
            FM.scope.workspaceKind = String(ws.kind || "personal");
            saveScope();

            const workspaces = await fetchWorkspaces().catch(() => []);
            if (scopeBar) scopeBar.classList.remove("hidden");
            populateScopeSelect(workspaces);
            applyScopeUi();

            if (FM.clearSelection) FM.clearSelection();
            if (FM.setPathAndLoad) FM.setPathAndLoad("");
        } catch (e) {
            alert("Create Shared Space failed:\\n" + String(e && e.message ? e.message : e));
        } finally {
            workspaceCreateSharedBtn.disabled = false;
            workspaceCreateSharedBtn.textContent = old;
        }
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
                scopeBar.classList.remove("hidden");
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
                    FM.scope.workspaceKind = opt ? String(opt.dataset.kind || "admin") : "admin";
                    FM.scope.workspaceDisplayKind = opt ? String(opt.dataset.displayKind || "") : "";
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

            // Fail open during UI/runtime issues: users should still see the
            // Location bar and the New Shared Space button instead of the whole
            // workspace toolbar disappearing.
            if (scopeBar) scopeBar.classList.remove("hidden");
            if (scopeRole) {
                scopeRole.textContent = "Workspace UI error";
                scopeRole.classList.remove("hidden");
                scopeRole.title = String(e && e.message ? e.message : e);
            }

            resetToUserScope();
            applyScopeUi();
        }
    }
    FM.isWorkspaceScope = isWorkspaceScope;
    FM.getWorkspaceId = () => FM.scope.workspaceId || "";
    FM.getWorkspaceRole = () => FM.scope.workspaceRole || "";
    FM.getWorkspaceKind = () => FM.scope.workspaceKind || "";
    FM.isPersonalSharedSpaceScope = isCurrentScopePersonalSharedSpace;
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
        copyUrl,
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