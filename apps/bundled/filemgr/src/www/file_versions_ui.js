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
        deletingVersionId: "",
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

    function flagSummary(row) {
        const flags = Array.isArray(row.flags) ? row.flags : [];
        const count = Number(row.flag_count || flags.length || 0);
        if (!count) return "";

        const names = flags
            .map((f) => String(f.actor_display || f.actor_name_snapshot || f.actor_fp || "").trim())
            .filter(Boolean);

        if (names.length === 1) return `⭐ ${names[0]} flagged this version`;
        if (names.length === 2) return `⭐ ${names[0]} and ${names[1]} flagged this version`;
        if (names.length > 2) return `⭐ ${names[0]}, ${names[1]} and ${names.length - 2} more flagged this version`;

        return `⭐ Flagged by ${count} user${count === 1 ? "" : "s"}`;
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

    function buildDeleteUrl() {
        return isWorkspaceScope()
            ? `/api/v4/workspaces/files/versions/delete`
            : `/api/v4/files/versions/delete`;
    }


    function buildFlagUrl(flaggedByMe) {
        if (isWorkspaceScope()) {
            return flaggedByMe
                ? `/api/v4/workspaces/files/versions/unflag`
                : `/api/v4/workspaces/files/versions/flag`;
        }

        return flaggedByMe
            ? `/api/v4/files/versions/unflag`
            : `/api/v4/files/versions/flag`;
    }

    function buildFlagBody(relPath, versionId) {
        const body = {
            path: relPath,
            version_id: versionId,
            note: "",
        };

        if (isWorkspaceScope()) {
            body.workspace_id = getWorkspaceId();
        }

        return body;
    }

    function buildDownloadUrl(relPath, versionId) {
        const qs = new URLSearchParams();
        qs.set("path", String(relPath || ""));
        qs.set("version_id", String(versionId || ""));

        if (isWorkspaceScope()) {
            qs.set("workspace_id", getWorkspaceId());
            return `/api/v4/workspaces/files/versions/download?${qs.toString()}`;
        }

        return `/api/v4/files/versions/download?${qs.toString()}`;
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

    function injectFlagCss() {
        if (document.getElementById("pqFileVersionFlagCss")) return;

        const style = document.createElement("style");
        style.id = "pqFileVersionFlagCss";
        style.textContent = `
.pqfvFlagSummary{
    display:inline-flex;
    align-items:center;
    width:max-content;
    max-width:100%;
    margin:6px 0 4px;
    padding:4px 9px;
    border:1px solid rgba(180,120,0,.55);
    border-radius:999px;
    background:rgba(255,190,0,.20);
    color:var(--fg,#111);
    font-weight:850;
    box-shadow:inset 0 0 0 1px rgba(255,255,255,.25);
}
html[data-theme="bright"] .pqfvFlagSummary,
html[data-theme="win_classic"] .pqfvFlagSummary{
    background:#fff0b8;
    border-color:#b87900;
    color:#111;
    box-shadow:none;
}
html[data-theme="dark"] .pqfvFlagSummary,
html[data-theme="cpunk_orange"] .pqfvFlagSummary,
html[data-theme="orange"] .pqfvFlagSummary{
    background:rgba(255,170,0,.18);
    border-color:rgba(255,190,0,.65);
    color:var(--fg,#f4f4f4);
}
`;
        document.head.appendChild(style);
    }

    function ensureDom() {
        injectFlagCss();
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
                if (document.querySelector(".pqfvConfirmModal.show")) return;
                e.preventDefault();
                close();
            }
        });
    }

    function confirmVersionAction(opts) {
        return new Promise((resolve) => {
            const options = opts || {};
            const modal = document.createElement("div");
            modal.className = "modal show pqfvConfirmModal";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(560px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || "Confirm action";

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "130px 1fr";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "k";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "v mono" : "v";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.warning) {
                const warn = document.createElement("div");
                warn.className = "v";
                warn.style.gridColumn = "1 / -1";
                warn.style.padding = "10px 12px";
                warn.style.border = "1px solid rgba(var(--warn-rgb),0.35)";
                warn.style.borderRadius = "14px";
                warn.style.background = "rgba(var(--warn-rgb),0.10)";
                warn.style.color = "var(--fg)";
                warn.style.fontWeight = "850";
                warn.textContent = String(options.warning || "");
                body.appendChild(warn);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "v";
                note.style.gridColumn = "1 / -1";
                note.style.opacity = "0.9";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || "Cancel";

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || "OK";

            if (options.danger) {
                okBtn.style.borderColor = "rgba(var(--fail-rgb),0.45)";
                okBtn.style.background = "rgba(var(--fail-rgb),0.14)";
                okBtn.style.color = "var(--fg)";
            }

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

            const onKey = (e) => {
                if (e.key === "Escape") {
                    e.preventDefault();
                    e.stopPropagation();
                    finish(false);
                    return;
                }
                if (e.key === "Enter") {
                    e.preventDefault();
                    e.stopPropagation();
                    finish(true);
                }
            };

            document.addEventListener("keydown", onKey, true);

            modal.addEventListener("click", (e) => {
                if (e.target === modal) finish(false);
            });

            cancelBtn.addEventListener("click", () => finish(false));
            okBtn.addEventListener("click", () => finish(true));

            setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }

    function open() {
        ensureDom();
        rootEl.classList.add("show");
        rootEl.setAttribute("aria-hidden", "false");
    }

    function buildDeleteBody(relPath, versionId) {

        const body = {

            path: relPath,

            version_id: versionId,

        };


        if (isWorkspaceScope()) {

            body.workspace_id = getWorkspaceId();

        }


        return body;

    }


    function close() {
        if (!rootEl) return;
        rootEl.classList.remove("show");
        rootEl.setAttribute("aria-hidden", "true");
        state.restoringVersionId = "";
        state.deletingVersionId = "";
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

        const compareBtn = document.createElement("button");
        compareBtn.type = "button";
        compareBtn.className = "btn secondary";
        compareBtn.textContent = "Compare";
        compareBtn.disabled = !(
            FM &&
            FM.fileVersionCompare &&
            typeof FM.fileVersionCompare.canCompare === "function" &&
            FM.fileVersionCompare.canCompare(state.item)
        );
        compareBtn.title = compareBtn.disabled
            ? "Compare is available for text-based files"
            : "Compare this version with the current file";
        compareBtn.addEventListener("click", () => {
            if (!FM || !FM.fileVersionCompare || typeof FM.fileVersionCompare.open !== "function") return;
            FM.fileVersionCompare.open(state.item, row);
            close();
        });

        const downloadBtn = document.createElement("button");
        downloadBtn.type = "button";
        downloadBtn.className = "btn secondary";
        downloadBtn.textContent = "Download";
        downloadBtn.title = "Download this preserved version without restoring it";
        downloadBtn.addEventListener("click", () => {
            const url = buildDownloadUrl(state.relPath, row.version_id);
            const a = document.createElement("a");
            a.href = url;
            a.rel = "noopener";
            a.style.display = "none";
            document.body.appendChild(a);
            a.click();
            a.remove();
        });

        const flagBtn = document.createElement("button");
        flagBtn.type = "button";
        flagBtn.className = row.flagged_by_me ? "btn" : "btn secondary";
        flagBtn.textContent = row.flagged_by_me ? "⭐ Unflag" : "☆ Flag";
        flagBtn.title = row.flagged_by_me
            ? "Remove your flag from this version"
            : "Flag this version so other workspace members can see it";
        flagBtn.addEventListener("click", () => {
            toggleFlag(row).catch((e) => {
                setModalStatus(String(e && e.message ? e.message : e), "err");
            });
        });

        const deleteBtn = document.createElement("button");

        deleteBtn.type = "button";

        deleteBtn.className = "btn secondary";

        deleteBtn.textContent = state.deletingVersionId === row.version_id ? "Deleting…" : "Delete";

        deleteBtn.title = "Delete this preserved version permanently";

        deleteBtn.disabled = !!state.restoringVersionId || !!state.deletingVersionId;

        deleteBtn.addEventListener("click", () => {

            deleteVersion(row).catch((e) => {

                setModalStatus(String(e && e.message ? e.message : e), "err");

            });

        });


        actionsEl.appendChild(compareBtn);
        actionsEl.appendChild(restoreBtn);
        actionsEl.appendChild(downloadBtn);
        actionsEl.appendChild(deleteBtn);
        actionsEl.appendChild(flagBtn);
        actionsEl.appendChild(copyBtn);

        topEl.appendChild(leftEl);
        topEl.appendChild(actionsEl);

        const bottomEl = document.createElement("div");
        bottomEl.className = "pqfvRowBottom";

        const flagText = flagSummary(row);
        if (flagText) {
            const flagEl = document.createElement("div");
            flagEl.className = "pqfvMini pqfvFlagSummary";
            flagEl.textContent = flagText;
            bottomEl.appendChild(flagEl);
        }

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
    async function toggleFlag(row) {
        if (!row || !row.version_id) return;

        const wasFlagged = !!row.flagged_by_me;
        setModalStatus(wasFlagged ? "Removing flag…" : "Flagging version…", "warn");

        const r = await fetch(buildFlagUrl(wasFlagged), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify(buildFlagBody(state.relPath, row.version_id)),
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || "flag update failed");
        }

        await loadVersions();
        setModalStatus(wasFlagged ? "Flag removed." : "Version flagged.", "ok");
    }

    async function deleteVersion(row) {

        if (!row || !row.version_id) return;


        const label = kindLabel(row);

        const flagCount = Number(row.flag_count || 0);        const ok = await confirmVersionAction({
            title: "Delete preserved version?",
            subtitle: "This removes only this saved version from history.",
            rows: [
                { label: "Path", value: state.relPath, mono: true },
                { label: "Kind", value: label },
                { label: "Created", value: row.created_at || "" },
                { label: "Size", value: fmtSize(row.bytes || 0) },
            ],
            warning: flagCount > 0
                ? `This version is flagged by ${flagCount} user(s). Delete anyway?`
                : "",
            note: "This cannot be undone.",
            confirmText: "Delete version",
            cancelText: "Keep version",
            danger: true,
        });
        if (!ok) return;


        state.deletingVersionId = row.version_id;

        renderVersions();

        setModalStatus("Deleting version…", "warn");

        setGlobalStatus(`Deleting version: ${state.relPath}`, "warn");


        try {

            const r = await fetch(buildDeleteUrl(), {

                method: "POST",

                credentials: "include",

                cache: "no-store",

                headers: {

                    "Content-Type": "application/json",

                    "Accept": "application/json",

                },

                body: JSON.stringify(buildDeleteBody(state.relPath, row.version_id)),

            });


            const j = await r.json().catch(() => null);

            if (!r.ok || !j || !j.ok) {

                const msg = j && (j.message || j.error)

                    ? `${j.error || ""} ${j.message || ""}`.trim()

                    : `HTTP ${r.status}`;

                throw new Error(msg || "delete failed");

            }


            state.deletingVersionId = "";

            await loadVersions();


            const freed = fmtSize(j.version_bytes_deleted || j.bytes_deleted || row.bytes || 0);

            setModalStatus(`Version deleted. Freed ${freed}.`, "ok");

            setGlobalStatus(`Deleted version: ${state.relPath}`, "ok");

        } finally {

            state.deletingVersionId = "";

        }

    }


    async function restoreVersion(row) {
        const label = kindLabel(row);        const ok = await confirmVersionAction({
            title: "Restore this version?",
            subtitle: "The current file will be replaced by the selected version.",
            rows: [
                { label: "Path", value: state.relPath, mono: true },
                { label: "Kind", value: label },
                { label: "Created", value: row.created_at || "" },
                { label: "Size", value: fmtSize(row.bytes || 0) },
            ],
            note: "A preserved copy of the current file may be created before restore, depending on server versioning rules.",
            confirmText: "Restore version",
            cancelText: "Cancel",
            danger: false,
        });
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
            state.deletingVersionId = "";
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
            state.deletingVersionId = "";

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