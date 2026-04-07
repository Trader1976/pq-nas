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

    const workspaceNewBtn = document.getElementById("workspaceNewBtn");
    const workspaceRenameBtn = document.getElementById("workspaceRenameBtn");
    const workspaceMembersBtn = document.getElementById("workspaceMembersBtn");
    const workspaceDeleteBtn = document.getElementById("workspaceDeleteBtn");

    const SCOPE_KEY = "pqnas_filemgr_scope_v1";

    FM.scope = FM.scope || {
        mode: "user",            // "user" | "workspace"
        workspaceId: "",
        workspaceName: "",
        workspaceRole: ""
    };

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
            shares: false,
            pqShares: false,
            textEdit: true,
            imagePreview: true,
            properties: true,
            zipFolder: false,
            zipSelection: false
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

        if (workspaceNewBtn) {
            workspaceNewBtn.classList.toggle("hidden", inWorkspace);
        }

        if (workspaceRenameBtn) {
            workspaceRenameBtn.classList.toggle("hidden", !inWorkspace);
        }

        if (workspaceMembersBtn) {
            workspaceMembersBtn.classList.toggle("hidden", !inWorkspace);
        }

        if (workspaceDeleteBtn) {
            workspaceDeleteBtn.classList.toggle("hidden", !inWorkspace);
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
        if (!isWorkspaceScope()) {
            const qs = new URLSearchParams();
            qs.set("path", path || "");
            return `/api/v4/files/read_text?${qs.toString()}`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        qs.set("path", path || "");
        return `/api/v4/workspaces/files/read_text?${qs.toString()}`;
    }

    function writeTextUrl() {
        if (!isWorkspaceScope()) {
            return `/api/v4/files/write_text`;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", FM.scope.workspaceId);
        return `/api/v4/workspaces/files/write_text?${qs.toString()}`;
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

    workspaceNewBtn?.addEventListener("click", async () => {
        alert("Next step: create workspace modal / API call");
    });

    workspaceRenameBtn?.addEventListener("click", async () => {
        if (!isWorkspaceScope()) return;
        alert(`Next step: rename workspace ${FM.scope.workspaceName || FM.scope.workspaceId}`);
    });

    workspaceMembersBtn?.addEventListener("click", async () => {
        if (!isWorkspaceScope()) return;
        alert(`Next step: manage members for ${FM.scope.workspaceName || FM.scope.workspaceId}`);
    });

    workspaceDeleteBtn?.addEventListener("click", async () => {
        if (!isWorkspaceScope()) return;
        alert(`Next step: delete workspace ${FM.scope.workspaceName || FM.scope.workspaceId}`);
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
        readTextUrl,
        writeTextUrl
    };

    initWorkspaces();
})();