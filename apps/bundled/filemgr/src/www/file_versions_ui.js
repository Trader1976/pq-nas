window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (FM.fileVersions) return;

    const state = {
        item: null,
        relPath: "",
        versions: [],
        loading: false,
        restoringVersionId: "",
        closeAfterRestore: false,
    };

    let rootEl = null;
    let panelEl = null;
    let titleEl = null;
    let pathEl = null;
    let statusEl = null;
    let bodyEl = null;
    let refreshBtn = null;
    let closeBtn = null;
    let closeAfterRestoreCb = null;

    function isWorkspaceScope() {
        return !!(FM && typeof FM.isWorkspaceScope === "function" && FM.isWorkspaceScope());
    }

    function getWorkspaceId() {
        if (!FM || typeof FM.getWorkspaceId !== "function") return "";
        return String(FM.getWorkspaceId() || "").trim();
    }

    function getCurrentRelPathFor(item) {
        if (FM && typeof FM.currentRelPathFor === "function") {
            return String(FM.currentRelPathFor(item) || "");
        }
        return item && item.name ? String(item.name) : "";
    }

    function fmtSize(n) {
        if (FM && typeof FM.fmtSize === "function") return FM.fmtSize(n);
        const v = Number(n || 0);
        return `${v} B`;
    }

    function actorDisplay(row) {
        return String(
            row.actor_display ||
            row.actor_name_snapshot ||
            row.actor_fp ||
            "Unknown"
        );
    }

    function kindLabel(row) {
        if (row.is_deleted_event) return "Deleted file snapshot";
        if (row.event_kind === "overwrite_preserve") return "Before overwrite";
        if (row.event_kind === "delete_preserve") return "Before delete";
        return String(row.event_kind || "Version");
    }

    function detailLine(row) {
        const parts = [];
        if (row.created_at) parts.push(row.created_at);
        else if (row.created_epoch) parts.push(String(row.created_epoch));
        parts.push(actorDisplay(row));
        parts.push(fmtSize(row.bytes || 0));
        return parts.join(" • ");
    }

    function shortSha(sha) {
        const s = String(sha || "");
        if (!s) return "";
        if (s.length <= 32) return s;
        return `${s.slice(0, 16)}…${s.slice(-12)}`;
    }

    function setGlobalStatus(text, badgeKind) {
        if (FM && typeof FM.setBadge === "function" && badgeKind) {
            FM.setBadge(badgeKind, badgeKind === "warn" ? "working…" : badgeKind);
        }
        const st = FM && typeof FM.getStatusEl === "function" ? FM.getStatusEl() : null;
        if (st) st.textContent = text || "";
    }

    function buildListUrl(relPath, limit = 100) {
        const p = encodeURIComponent(relPath || "");
        if (isWorkspaceScope()) {
            const ws = getWorkspaceId();
            return `/api/v4/workspaces/files/versions/list?workspace_id=${encodeURIComponent(ws)}&path=${p}&limit=${limit}`;
        }
        return `/api/v4/files/versions/list?path=${p}&limit=${limit}`;
    }

    function buildRestoreUrl() {
        return isWorkspaceScope()
            ? `/api/v4/workspaces/files/restore_version`
            : `/api/v4/files/restore_version`;
    }

    function buildRestoreBody(relPath, versionId) {
        if (isWorkspaceScope()) {
            return {
                workspace_id: getWorkspaceId(),
                path: relPath,
                version_id: versionId,
            };
        }
        return {
            path: relPath,
            version_id: versionId,
        };
    }

    function ensureDom() {
        if (rootEl) return;

        rootEl = document.createElement("div");
        rootEl.className = "pqfvRoot uiOverlay";
        rootEl.setAttribute("aria-hidden", "true");

        panelEl = document.createElement("div");
        panelEl.className = "pqfvPanel uiDialog";

        const headEl = document.createElement("div");
        headEl.className = "pqfvHead uiDialogHeader";

        const headLeftEl = document.createElement("div");
        headLeftEl.className = "pqfvHeadLeft";

        titleEl = document.createElement("div");
        titleEl.className = "pqfvTitle";
        titleEl.textContent = "File versions";

        pathEl = document.createElement("div");
        pathEl.className = "pqfvPath mono";

        headLeftEl.appendChild(titleEl);
        headLeftEl.appendChild(pathEl);

        const headRightEl = document.createElement("div");
        headRightEl.className = "pqfvHeadRight";

        const closeAfterWrap = document.createElement("label");
        closeAfterWrap.className = "pqfvCloseAfter";

        closeAfterRestoreCb = document.createElement("input");
        closeAfterRestoreCb.type = "checkbox";
        closeAfterRestoreCb.checked = !!state.closeAfterRestore;
        closeAfterRestoreCb.addEventListener("change", () => {
            state.closeAfterRestore = !!closeAfterRestoreCb.checked;
        });

        const closeAfterTxt = document.createElement("span");
        closeAfterTxt.textContent = "Close after restore";

        closeAfterWrap.appendChild(closeAfterRestoreCb);
        closeAfterWrap.appendChild(closeAfterTxt);

        refreshBtn = document.createElement("button");
        refreshBtn.type = "button";
        refreshBtn.className = "btn secondary";
        refreshBtn.textContent = "Refresh";
        refreshBtn.addEventListener("click", () => {
            loadVersions().catch((e) => {
                setModalError(String(e && e.message ? e.message : e));
            });
        });

        closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "btn secondary";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", close);

        headRightEl.appendChild(closeAfterWrap);
        headRightEl.appendChild(refreshBtn);
        headRightEl.appendChild(closeBtn);

        headEl.appendChild(headLeftEl);
        headEl.appendChild(headRightEl);

        statusEl = document.createElement("div");
        statusEl.className = "pqfvStatus";

        bodyEl = document.createElement("div");
        bodyEl.className = "pqfvBody";

        panelEl.appendChild(headEl);
        panelEl.appendChild(statusEl);
        panelEl.appendChild(bodyEl);

        rootEl.appendChild(panelEl);
        document.body.appendChild(rootEl);

        rootEl.addEventListener("click", (e) => {
            if (e.target === rootEl) close();
        });

        document.addEventListener("keydown", (e) => {
            if (!rootEl || !rootEl.classList.contains("show")) return;
            if (e.key === "Escape") {
                e.preventDefault();
                close();
            }
        });
    }

    function open() {
        ensureDom();
        rootEl.classList.add("show");
        rootEl.setAttribute("aria-hidden", "false");
    }

    function close() {
        if (!rootEl) return;
        rootEl.classList.remove("show");
        rootEl.setAttribute("aria-hidden", "true");
        state.restoringVersionId = "";
    }

    function setModalStatus(text, kind = "") {
        if (!statusEl) return;
        statusEl.className = `pqfvStatus${kind ? " " + kind : ""}`;
        statusEl.textContent = text || "";
    }

    function setModalLoading(text) {
        if (!bodyEl) return;
        setModalStatus(text || "Loading…", "warn");
        bodyEl.innerHTML = "";
        const div = document.createElement("div");
        div.className = "pqfvEmpty";
        div.textContent = text || "Loading…";
        bodyEl.appendChild(div);
    }

    function setModalError(text) {
        if (!bodyEl) return;
        setModalStatus(text || "Failed to load versions", "err");
        bodyEl.innerHTML = "";
        const div = document.createElement("div");
        div.className = "pqfvEmpty err";
        div.textContent = text || "Failed to load versions";
        bodyEl.appendChild(div);
    }

    async function fetchVersions() {
        const r = await fetch(buildListUrl(state.relPath, 100), {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" },
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || "failed to load versions");
        }

        return Array.isArray(j.versions) ? j.versions : [];
    }

    function renderVersions() {
        if (!bodyEl) return;

        bodyEl.innerHTML = "";

        if (!state.versions.length) {
            setModalStatus("No preserved versions for this file.");
            const div = document.createElement("div");
            div.className = "pqfvEmpty";
            div.textContent = "No preserved versions for this file yet.";
            bodyEl.appendChild(div);
            return;
        }

        setModalStatus(`${state.versions.length} version(s)`);

        const listEl = document.createElement("div");
        listEl.className = "pqfvList";

        for (const row of state.versions) {
            listEl.appendChild(renderRow(row));
        }

        bodyEl.appendChild(listEl);
    }

    function renderRow(row) {
        const rowEl = document.createElement("div");
        rowEl.className = "pqfvRow" + (row.is_deleted_event ? " deleted" : "");

        const topEl = document.createElement("div");
        topEl.className = "pqfvRowTop";

        const leftEl = document.createElement("div");
        leftEl.className = "pqfvRowLeft";

        const kindEl = document.createElement("div");
        kindEl.className = "pqfvKind";
        kindEl.textContent = kindLabel(row);

        const metaEl = document.createElement("div");
        metaEl.className = "pqfvMeta";
        metaEl.textContent = detailLine(row);

        leftEl.appendChild(kindEl);
        leftEl.appendChild(metaEl);

        const actionsEl = document.createElement("div");
        actionsEl.className = "pqfvActions";

        const restoreBtn = document.createElement("button");
        restoreBtn.type = "button";
        restoreBtn.className = "btn";
        restoreBtn.textContent = state.restoringVersionId === row.version_id ? "Restoring…" : "Restore";
        restoreBtn.disabled = !!state.restoringVersionId;
        restoreBtn.addEventListener("click", () => {
            restoreVersion(row).catch((e) => {
                setModalStatus(String(e && e.message ? e.message : e), "err");
            });
        });

        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "btn secondary";
        copyBtn.textContent = "Copy SHA";
        copyBtn.disabled = !row.sha256_hex;
        copyBtn.addEventListener("click", async () => {
            if (!row.sha256_hex) return;
            const ok = FM && typeof FM.copyText === "function"
                ? await FM.copyText(row.sha256_hex)
                : false;
            copyBtn.textContent = ok ? "Copied" : "Copy failed";
            setTimeout(() => { copyBtn.textContent = "Copy SHA"; }, 1000);
        });

        actionsEl.appendChild(restoreBtn);
        actionsEl.appendChild(copyBtn);

        topEl.appendChild(leftEl);
        topEl.appendChild(actionsEl);

        const bottomEl = document.createElement("div");
        bottomEl.className = "pqfvRowBottom";

        const idEl = document.createElement("div");
        idEl.className = "pqfvMini mono";
        idEl.textContent = `version_id: ${row.version_id || ""}`;

        const shaEl = document.createElement("div");
        shaEl.className = "pqfvMini mono";
        shaEl.textContent = `sha256: ${shortSha(row.sha256_hex || "")}`;

        bottomEl.appendChild(idEl);
        bottomEl.appendChild(shaEl);

        rowEl.appendChild(topEl);
        rowEl.appendChild(bottomEl);

        return rowEl;
    }

    async function loadVersions() {
        state.loading = true;
        setModalLoading("Loading versions…");

        try {
            state.versions = await fetchVersions();
            renderVersions();
        } catch (e) {
            setModalError(String(e && e.message ? e.message : e));
        } finally {
            state.loading = false;
        }
    }
    async function restoreVersion(row) {
        const label = kindLabel(row);
        const ok = window.confirm(
            `Restore this version?\n\n` +
            `Path: ${state.relPath}\n` +
            `Kind: ${label}\n` +
            `Created: ${row.created_at || ""}`
        );
        if (!ok) return;

        const successMsg = "Version restored. Current file replaced successfully.";

        state.restoringVersionId = row.version_id;
        renderVersions();
        setModalStatus("Restoring version…", "warn");
        setGlobalStatus(`Restoring version: ${state.relPath}`, "warn");

        try {
            const r = await fetch(buildRestoreUrl(), {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body: JSON.stringify(buildRestoreBody(state.relPath, row.version_id)),
            });

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || "restore failed");
            }

            const loadFn = FM && typeof FM.getLoadFn === "function" ? FM.getLoadFn() : null;
            if (typeof loadFn === "function") {
                await loadFn();
            }

            if (state.closeAfterRestore) {
                setGlobalStatus(`Restored version: ${state.relPath}`, "ok");
                close();
                return;
            }
        } finally {
            state.restoringVersionId = "";
        }

        await loadVersions();
        renderVersions();
        setModalStatus(successMsg, "ok");
        setGlobalStatus(`Restored version: ${state.relPath}`, "ok");
    }

    FM.fileVersions = {
        canOpenFor(item) {
            return !!item && item.type === "file";
        },

        open(item) {
            if (!item || item.type !== "file") return;
            ensureDom();

            state.item = item;
            state.relPath = getCurrentRelPathFor(item);
            state.versions = [];
            state.restoringVersionId = "";

            titleEl.textContent = "File versions";
            pathEl.textContent = "/" + state.relPath;

            if (closeAfterRestoreCb) {
                closeAfterRestoreCb.checked = !!state.closeAfterRestore;
            }

            open();
            loadVersions().catch((e) => {
                setModalError(String(e && e.message ? e.message : e));
            });
        },

        close,
    };
})();