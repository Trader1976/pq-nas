(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (!FM) return;

    function tr(key, vars = null, fallback = "") {
        try {
            if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
                return window.PQNAS_I18N.t(key, vars, fallback || key);
            }
        } catch (_) {}
        return fallback || key;
    }

    function fmApi() {
        return (FM && FM.api) ? FM.api : null;
    }

    function apiReadTextUrl(path) {
        const api = fmApi();
        if (api && typeof api.readTextUrl === "function") return api.readTextUrl(path || "");
        const qs = new URLSearchParams();
        qs.set("path", path || "");
        return `/api/v4/files/read_text?${qs.toString()}`;
    }

    function apiWriteTextUrl() {
        const api = fmApi();
        if (api && typeof api.writeTextUrl === "function") return api.writeTextUrl();
        return `/api/v4/files/write_text`;
    }
    function isWorkspaceScope() {
        return !!(FM && typeof FM.isWorkspaceScope === "function" && FM.isWorkspaceScope());
    }

    function currentWorkspaceId() {
        return (FM && typeof FM.getWorkspaceId === "function")
            ? String(FM.getWorkspaceId() || "")
            : "";
    }

    function currentWorkspaceSessionId() {
        return (FM && typeof FM.getWorkspaceEditorSessionId === "function")
            ? String(FM.getWorkspaceEditorSessionId() || "")
            : "";
    }

    function apiEditLeaseAcquireUrl() {
        const api = fmApi();
        if (api && typeof api.workspaceEditLeaseAcquireUrl === "function") {
            return api.workspaceEditLeaseAcquireUrl(currentWorkspaceId() || "");
        }
        return `/api/v4/workspaces/files/edit_lease/acquire`;
    }

    function apiEditLeaseRefreshUrl() {
        const api = fmApi();
        if (api && typeof api.workspaceEditLeaseRefreshUrl === "function") {
            return api.workspaceEditLeaseRefreshUrl(currentWorkspaceId() || "");
        }
        return `/api/v4/workspaces/files/edit_lease/refresh`;
    }

    function apiEditLeaseReleaseUrl() {
        const api = fmApi();
        if (api && typeof api.workspaceEditLeaseReleaseUrl === "function") {
            return api.workspaceEditLeaseReleaseUrl(currentWorkspaceId() || "");
        }
        return `/api/v4/workspaces/files/edit_lease/release`;
    }
    const textEditModal = document.getElementById("textEditModal");
    const textEditClose = document.getElementById("textEditClose");
    const textEditTitle = document.getElementById("textEditTitle");
    const textEditPath = document.getElementById("textEditPath");
    const textEditInfo = document.getElementById("textEditInfo");
    const textEditArea = document.getElementById("textEditArea");
    const textEditReloadBtn = document.getElementById("textEditReloadBtn");
    const textEditSaveBtn = document.getElementById("textEditSaveBtn");
    const textEditStatus = document.getElementById("textEditStatus");
    const textEditCard = document.getElementById("textEditCard");
    const textEditHead = document.getElementById("textEditHead");
    const textEditFindInput = document.getElementById("textEditFindInput");
    const textEditFindPrevBtn = document.getElementById("textEditFindPrevBtn");
    const textEditFindNextBtn = document.getElementById("textEditFindNextBtn");
    const textEditFindCaseBtn = document.getElementById("textEditFindCaseBtn");
    const textEditFindStatus = document.getElementById("textEditFindStatus");
    const textEditFindBar = document.getElementById("textEditFindBar");
    const textEditFindToggleBtn = document.getElementById("textEditFindToggleBtn");
    const textEditFindCloseBtn = document.getElementById("textEditFindCloseBtn");

    let state = {
        relPath: "",
        originalText: "",
        mtimeEpoch: 0,
        sha256: "",
        encoding: "utf-8",
        dirty: false,
        loading: false,
        saving: false,
        readOnly: false,
        lease: null,
        leaseTimer: 0
    };
    let dragState = {
        active: false,
        startX: 0,
        startY: 0,
        cardLeft: 0,
        cardTop: 0,
        moved: false
    };
    let findState = {
        query: "",
        matchCase: false,
        lastIndex: -1
    };
    function openModal() {
        if (!textEditModal) return;
        textEditModal.classList.add("show");
        textEditModal.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        if (!textEditModal) return;
        textEditModal.classList.remove("show");
        textEditModal.setAttribute("aria-hidden", "true");
    }

    function ensureTextEditConfirmCss() {
        if (document.getElementById("fmTextEditConfirmCss")) return;

        const style = document.createElement("style");
        style.id = "fmTextEditConfirmCss";
        style.textContent = `
.fmTextEditConfirmBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}
.fmTextEditConfirmCard{
    width:min(560px, calc(100vw - 24px));
    border:1px solid var(--border2, rgba(120,120,120,.42));
    border-radius:18px;
    overflow:hidden;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    color:var(--fg, #111);
    box-shadow:0 18px 70px rgba(0,0,0,.42);
}
.fmTextEditConfirmHead{
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,.32));
    background:rgba(0,0,0,.08);
}
.fmTextEditConfirmTitle{
    font-weight:950;
    letter-spacing:.2px;
}
.fmTextEditConfirmBody{
    padding:16px;
}
.fmTextEditConfirmNote{
    padding:10px 12px;
    border-radius:14px;
    border:1px solid rgba(var(--warn-rgb, 180,120,20),.35);
    background:rgba(var(--warn-rgb, 180,120,20),.10);
}
.fmTextEditConfirmFoot{
    display:flex;
    justify-content:flex-end;
    gap:10px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,.32));
    background:rgba(0,0,0,.08);
}
html[data-theme="bright"] .fmTextEditConfirmCard{
    background:linear-gradient(180deg, #fff, #f2f4f7) !important;
    color:#111827 !important;
}
`;
        document.head.appendChild(style);
    }

    function openTextEditConfirmModal(opts = {}) {
        ensureTextEditConfirmCss();

        return new Promise((resolve) => {
            const options = opts || {};
            const modal = document.createElement("div");
            modal.className = "fmTextEditConfirmBackdrop";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "fmTextEditConfirmCard";

            const head = document.createElement("div");
            head.className = "fmTextEditConfirmHead";

            const title = document.createElement("div");
            title.className = "fmTextEditConfirmTitle";
            title.textContent = options.title || tr("filemgr.textedit.confirm_title", null, "Confirm action");
            head.appendChild(title);

            const body = document.createElement("div");
            body.className = "fmTextEditConfirmBody";

            const note = document.createElement("div");
            note.className = "fmTextEditConfirmNote";
            note.textContent = options.message || "";
            body.appendChild(note);

            const foot = document.createElement("div");
            foot.className = "fmTextEditConfirmFoot";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || tr("common.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn danger";
            okBtn.textContent = options.confirmText || tr("filemgr.textedit.discard_changes", null, "Discard changes");

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

            window.setTimeout(() => cancelBtn.focus(), 0);
        });
    }

    function openFindBar(selectText = true) {
        if (!textEditFindBar) return;
        textEditFindBar.classList.remove("hidden");
        if (textEditFindInput) {
            textEditFindInput.focus();
            if (selectText) textEditFindInput.select();
        }
        refreshFindStatus();
    }

    function closeFindBar() {
        if (!textEditFindBar) return;
        textEditFindBar.classList.add("hidden");
        setFindStatus("");
        if (textEditArea) textEditArea.focus();
    }

    function isFindBarOpen() {
        return !!(textEditFindBar && !textEditFindBar.classList.contains("hidden"));
    }
    function refreshSaveButton() {
        if (textEditSaveBtn) {
            textEditSaveBtn.disabled =
                !!state.readOnly || !state.dirty || state.loading || state.saving;
        }
    }

    function setDirty(on) {
        state.dirty = !!on;
        refreshSaveButton();
    }

    function setReadOnly(on) {
        state.readOnly = !!on;
        if (textEditArea) {
            textEditArea.readOnly = !!on || !!state.loading;
        }
        refreshSaveButton();
    }

    function setStatus(msg) {
        if (textEditStatus) textEditStatus.textContent = String(msg || "");
    }

    function setInfo(msg) {
        if (textEditInfo) textEditInfo.textContent = String(msg || "");
    }

    function clearLeaseTimer() {
        if (state.leaseTimer) {
            clearInterval(state.leaseTimer);
            state.leaseTimer = 0;
        }
    }

    function shortLeaseHolder(fp) {
        const s = String(fp || "").trim();
        if (!s) return tr("filemgr.textedit.another_user", null, "another user");
        if (s.length <= 24) return s;
        return `${s.slice(0, 10)}…${s.slice(-8)}`;
    }

    function leaseSummaryFrom(details) {
        const lease = details && details.lease ? details.lease : null;
        if (!lease) {
            return tr("filemgr.textedit.readonly_generic", null, "This file can only be opened in read-only mode right now.");
        }

        const holder =
            lease.holder_fp
                ? tr("filemgr.textedit.locked_by_fp", { fp: String(lease.holder_fp).slice(0, 12) }, ` by ${String(lease.holder_fp).slice(0, 12)}…`)
                : tr("filemgr.textedit.locked_by_session", null, " by another session");

        const until =
            lease.expires_at
                ? tr("filemgr.textedit.editable_after", { time: lease.expires_at }, ` It should become editable again after ${lease.expires_at}.`)
                : "";

        return tr("filemgr.textedit.locked_readonly", { holder, until }, `This file is currently being edited${holder}. Opened in read-only mode.${until}`);
    }

    async function acquireWorkspaceLease(relPath) {
        const workspaceId = currentWorkspaceId();
        const sessionId = currentWorkspaceSessionId();

        if (!workspaceId || !sessionId) {
            throw new Error(tr("filemgr.textedit.missing_workspace_session", null, "missing workspace editor session"));
        }

        const r = await fetch(apiEditLeaseAcquireUrl(), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({
                workspace_id: workspaceId,
                path: relPath,
                session_id: sessionId,
                lease_seconds: 60
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            const err = new Error(msg || tr("filemgr.textedit.lease_acquire_failed", null, "edit lease acquire failed"));
            err.code = j && j.error ? String(j.error) : "";
            err.details = j;
            throw err;
        }

        state.lease = {
            workspaceId,
            relPath,
            sessionId,
            lease: j.lease || null
        };
        return j;
    }

    async function refreshWorkspaceLease() {
        if (!state.lease) return null;

        const r = await fetch(apiEditLeaseRefreshUrl(), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({
                workspace_id: state.lease.workspaceId,
                path: state.lease.relPath,
                session_id: state.lease.sessionId,
                lease_seconds: 60
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            const err = new Error(msg || tr("filemgr.textedit.lease_refresh_failed", null, "edit lease refresh failed"));
            err.code = j && j.error ? String(j.error) : "";
            err.details = j;
            throw err;
        }

        state.lease.lease = j.lease || state.lease.lease || null;
        return j;
    }

    async function releaseWorkspaceLeaseBestEffort() {
        if (!state.lease) return;

        const lease = state.lease;
        state.lease = null;
        clearLeaseTimer();

        try {
            await fetch(apiEditLeaseReleaseUrl(), {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({
                    workspace_id: lease.workspaceId,
                    path: lease.relPath,
                    session_id: lease.sessionId
                })
            });
        } catch (_) {}
    }

    function startLeaseTimer() {
        clearLeaseTimer();
        if (!state.lease) return;

        state.leaseTimer = window.setInterval(async () => {
            if (!textEditModal || !textEditModal.classList.contains("show")) return;

            try {
                await refreshWorkspaceLease();
            } catch (e) {
                clearLeaseTimer();
                state.lease = null;
                setReadOnly(true);
                setStatus(tr("filemgr.textedit.reload_try_editing", { reason: leaseSummaryFrom(e && e.details ? e.details : null) }, `${leaseSummaryFrom(e && e.details ? e.details : null)} Reload to try editing again.`));
            }
        }, 20000);
    }
    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function getCardRect() {
        return textEditCard ? textEditCard.getBoundingClientRect() : null;
    }

    function placeCardCentered() {
        if (!textEditCard) return;

        textEditCard.style.transform = "translateX(-50%)";
        textEditCard.style.left = "50%";
        textEditCard.style.top = "80px";
    }

    function clampCardIntoViewport() {
        if (!textEditCard) return;

        const rect = textEditCard.getBoundingClientRect();
        const pad = 8;

        let left = rect.left;
        let top = rect.top;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        left = clamp(left, pad, maxLeft);
        top = clamp(top, pad, maxTop);

        textEditCard.style.transform = "none";
        textEditCard.style.left = `${left}px`;
        textEditCard.style.top = `${top}px`;
    }
    function updateFindUi() {
        if (textEditFindCaseBtn) {
            textEditFindCaseBtn.classList.toggle("active", !!findState.matchCase);
        }
    }

    function setFindStatus(msg) {
        if (textEditFindStatus) textEditFindStatus.textContent = String(msg || "");
    }

    function normalizeFindHaystack(text) {
        return findState.matchCase ? text : text.toLowerCase();
    }

    function normalizeFindNeedle(text) {
        return findState.matchCase ? text : text.toLowerCase();
    }

    function getFindMatches(fullText, query) {
        if (!query) return [];

        const hay = normalizeFindHaystack(fullText);
        const needle = normalizeFindNeedle(query);
        const out = [];

        let pos = 0;
        while (true) {
            const idx = hay.indexOf(needle, pos);
            if (idx < 0) break;
            out.push(idx);
            pos = idx + Math.max(1, needle.length);
        }
        return out;
    }

    function selectMatchAt(start, len) {
        if (!textEditArea) return;

        textEditArea.focus();
        textEditArea.setSelectionRange(start, start + len);

        const lineHeight = 20;
        const before = textEditArea.value.slice(0, start);
        const line = before.split("\n").length - 1;
        textEditArea.scrollTop = Math.max(0, line * lineHeight - textEditArea.clientHeight / 2);
    }

    function updateFindStatusForSelection(matches, query, selectedStart) {
        if (!query) {
            setFindStatus("");
            return;
        }
        if (!matches.length) {
            setFindStatus(tr("filemgr.textedit.not_found", null, "Not found"));
            return;
        }

        let cur = matches.indexOf(selectedStart);
        if (cur < 0) {
            cur = matches.findIndex((x) => x >= 0);
        }
        if (cur < 0) {
            setFindStatus(`0 / ${matches.length}`);
            return;
        }

        setFindStatus(`${cur + 1} / ${matches.length}`);
    }

    function findNext(wrap = true) {
        if (!textEditArea) return;

        const query = String(textEditFindInput?.value || "");
        findState.query = query;

        if (!query) {
            setFindStatus("");
            return;
        }

        const full = String(textEditArea.value || "");
        const matches = getFindMatches(full, query);
        if (!matches.length) {
            setFindStatus(tr("filemgr.textedit.not_found", null, "Not found"));
            return;
        }

        const startPos = textEditArea.selectionEnd || 0;
        let idx = matches.find((m) => m >= startPos);

        if (idx == null && wrap) idx = matches[0];
        if (idx == null) {
            setFindStatus(`0 / ${matches.length}`);
            return;
        }

        findState.lastIndex = idx;
        selectMatchAt(idx, query.length);
        updateFindStatusForSelection(matches, query, idx);
    }

    function findPrev(wrap = true) {
        if (!textEditArea) return;

        const query = String(textEditFindInput?.value || "");
        findState.query = query;

        if (!query) {
            setFindStatus("");
            return;
        }

        const full = String(textEditArea.value || "");
        const matches = getFindMatches(full, query);
        if (!matches.length) {
            setFindStatus(tr("filemgr.textedit.not_found", null, "Not found"));
            return;
        }

        const startPos = Math.max(0, (textEditArea.selectionStart || 0) - 1);
        let idx = null;

        for (let i = matches.length - 1; i >= 0; i--) {
            if (matches[i] <= startPos) {
                idx = matches[i];
                break;
            }
        }

        if (idx == null && wrap) idx = matches[matches.length - 1];
        if (idx == null) {
            setFindStatus(`0 / ${matches.length}`);
            return;
        }

        findState.lastIndex = idx;
        selectMatchAt(idx, query.length);
        updateFindStatusForSelection(matches, query, idx);
    }

    function refreshFindStatus() {
        if (!textEditArea) return;

        const query = String(textEditFindInput?.value || "");
        if (!query) {
            setFindStatus("");
            return;
        }

        const full = String(textEditArea.value || "");
        const matches = getFindMatches(full, query);
        const selStart = textEditArea.selectionStart || 0;
        updateFindStatusForSelection(matches, query, selStart);
    }
    async function fetchTextFile(relPath) {
        const r = await fetch(apiReadTextUrl(relPath), {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || tr("filemgr.textedit.read_failed", null, "read text failed"));
        }
        return j;
    }

    async function saveTextFile(relPath, text, expectedMtimeEpoch, expectedSha256) {
        const body = {
            path: relPath,
            text,
            expected_mtime_epoch: expectedMtimeEpoch || 0,
            expected_sha256: expectedSha256 || ""
        };

        if (isWorkspaceScope()) {
            body.workspace_id = currentWorkspaceId();
            body.session_id = currentWorkspaceSessionId();
        }

        const r = await fetch(apiWriteTextUrl(), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(body)
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            const err = new Error(msg || tr("filemgr.textedit.write_failed", null, "write text failed"));
            err.details = j;
            err.code = j && j.error ? String(j.error) : "";
            throw err;
        }
        return j;
    }

    async function openEditorFor(itemOrRelPath) {
        console.log("[textedit.open] arg =", itemOrRelPath);
        console.log("[textedit.open] typeof =", typeof itemOrRelPath);
        const rel = (typeof itemOrRelPath === "string")
            ? String(itemOrRelPath || "")
            : (itemOrRelPath && itemOrRelPath.type === "file"
                ? FM.currentRelPathFor(itemOrRelPath)
                : "");
        console.log("[textedit.open] rel =", rel);
        console.log("[textedit.open] readTextUrl =", apiReadTextUrl(rel));
        console.log("[textedit.open] workspace? =", FM.isWorkspaceScope ? FM.isWorkspaceScope() : "(no fn)");
        console.log("[textedit.open] workspaceId =", FM.getWorkspaceId ? FM.getWorkspaceId() : "(no fn)");
        console.log("[textedit.open] FM.api =", FM.api);
        if (!rel) return;

        clearLeaseTimer();

        state = {
            relPath: rel,
            originalText: "",
            mtimeEpoch: 0,
            sha256: "",
            encoding: "utf-8",
            dirty: false,
            loading: true,
            saving: false,
            readOnly: true,
            lease: null,
            leaseTimer: 0
        };

        if (textEditTitle) textEditTitle.textContent = tr("filemgr.textedit.title", null, "Edit text file");
        if (textEditPath) textEditPath.textContent = "/" + rel;
        if (textEditArea) {
            textEditArea.value = "";
            textEditArea.readOnly = true;
        }

        setInfo(tr("filemgr.textedit.loading", null, "Loading…"));
        setStatus("");
        setDirty(false);
        placeCardCentered();
        findState.query = "";
        findState.lastIndex = -1;
        if (textEditFindInput) textEditFindInput.value = "";
        setFindStatus("");
        updateFindUi();
        closeFindBar();
        openModal();

        try {
            const j = await fetchTextFile(rel);

            state.relPath = rel;
            state.originalText = String(j.text || "");
            state.mtimeEpoch = Number(j.mtime_epoch || 0);
            state.sha256 = String(j.sha256 || "");
            state.encoding = String(j.encoding || "utf-8");
            state.loading = false;

            if (textEditArea) {
                textEditArea.value = state.originalText;
                textEditArea.readOnly = true;
                textEditArea.focus();
            }

            const bytes = new Blob([state.originalText]).size;
            let info = tr("filemgr.textedit.encoding_info", { encoding: state.encoding, size: FM.fmtSize(bytes) }, `Encoding: ${state.encoding} • ${FM.fmtSize(bytes)}`);

            if (isWorkspaceScope()) {
                const canWrite = !!(FM && typeof FM.canCurrentScopeWrite === "function" && FM.canCurrentScopeWrite());

                if (!canWrite) {
                    setReadOnly(true);
                    setStatus(tr("filemgr.textedit.readonly_role", null, "This file can only be opened in read-only mode because your workspace role does not allow editing."));
                } else {
                    try {
                        const leasej = await acquireWorkspaceLease(rel);
                        setReadOnly(false);
                        setStatus("");
                        startLeaseTimer();

                        if (leasej && leasej.lease && leasej.lease.expires_at) {
                            info += tr("filemgr.textedit.edit_lock_until", { time: leasej.lease.expires_at }, ` • edit lock until ${leasej.lease.expires_at}`);
                        }
                    } catch (e) {
                        setReadOnly(true);
                        if (e && e.code === "edit_locked") {
                            setStatus(leaseSummaryFrom(e.details));
                        } else {
                            console.warn("[textedit] lease acquire failed:", e);
                            setStatus(tr("filemgr.textedit.readonly_generic", null, "This file can only be opened in read-only mode right now."));
                        }
                    }
                }
            } else {
                setReadOnly(false);
                setStatus("");
            }

            setInfo(info);
            setDirty(false);
            refreshFindStatus();
        } catch (e) {
            state.loading = false;
            setInfo(tr("filemgr.textedit.failed_load", null, "Failed to load"));
            setStatus(String(e && e.message ? e.message : e));
            setReadOnly(true);
        }
    }

    async function saveCurrent() {
        if (!textEditArea || !state.relPath) return;
        if (state.loading || state.saving) return;

        if (state.readOnly) {
            setStatus(tr("filemgr.textedit.readonly_save", null, "Read-only: cannot save."));
            return;
        }

        if (isWorkspaceScope()) {
            if (!state.lease) {
                setReadOnly(true);
                setStatus(tr("filemgr.textedit.readonly_open", null, "This file is currently open in read-only mode. Reload to try acquiring edit access again."));
                return;
            }

            try {
                await refreshWorkspaceLease();
            } catch (e) {
                setReadOnly(true);
                setStatus(tr("filemgr.textedit.reload_try_editing", { reason: leaseSummaryFrom(e && e.details ? e.details : null) }, `${leaseSummaryFrom(e && e.details ? e.details : null)} Reload to try editing again.`));
                return;
            }
        }

        state.saving = true;
        setDirty(false);
        setStatus(tr("filemgr.textedit.saving", null, "Saving…"));

        try {
            const newText = String(textEditArea.value || "");
            const j = await saveTextFile(
                state.relPath,
                newText,
                state.mtimeEpoch,
                state.sha256
            );

            state.originalText = newText;
            state.mtimeEpoch = Number(j.mtime_epoch || state.mtimeEpoch || 0);
            state.sha256 = String(j.sha256 || state.sha256 || "");
            state.saving = false;

            setStatus(tr("filemgr.textedit.saved", null, "Saved."));
            setDirty(false);

            FM.setBadge("ok", "ready");
            const statusEl = FM.getStatusEl();
            if (statusEl) statusEl.textContent = tr("filemgr.textedit.saved_file", { path: state.relPath }, `Saved: ${state.relPath}`);

            const load = FM.getLoadFn();
            if (load) await load();
        } catch (e) {
            state.saving = false;
            setDirty(textEditArea.value !== state.originalText);

            if (e && (e.code === "changed_on_server" || (e.details && e.details.error === "changed_on_server"))) {
                setStatus(tr("filemgr.textedit.changed_on_server", null, "File changed on server. Reload and review before saving again."));
            } else if (e && (e.code === "edit_locked" || e.code === "edit_lock_missing")) {
                setReadOnly(true);
                setStatus(tr("filemgr.textedit.reload_try_editing", { reason: leaseSummaryFrom(e && e.details ? e.details : null) }, `${leaseSummaryFrom(e && e.details ? e.details : null)} Reload to try editing again.`));
            } else {
                setStatus(String(e && e.message ? e.message : e));
            }

            FM.setBadge("err", "error");
            const statusEl = FM.getStatusEl();
            if (statusEl) statusEl.textContent = tr("filemgr.textedit.save_failed", { error: String(e && e.message ? e.message : e) }, `Save failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function reloadCurrent() {
        if (!state.relPath) return;

        if (state.dirty) {
            const ok = await openTextEditConfirmModal({
                title: tr("filemgr.textedit.reload_title", null, "Reload from server?"),
                message: tr("filemgr.textedit.discard_reload", null, "Discard unsaved changes and reload from server?"),
                confirmText: tr("filemgr.textedit.reload_anyway", null, "Reload anyway"),
                cancelText: tr("common.cancel", null, "Cancel")
            });
            if (!ok) return;
        }

        await openEditorFor(state.relPath);
    }

    async function tryClose() {
        if (state.dirty) {
            const ok = await openTextEditConfirmModal({
                title: tr("filemgr.textedit.close_title", null, "Close text editor?"),
                message: tr("filemgr.textedit.discard_close", null, "Discard unsaved changes?"),
                confirmText: tr("filemgr.textedit.discard_changes", null, "Discard changes"),
                cancelText: tr("common.cancel", null, "Cancel")
            });
            if (!ok) return;
        }

        await releaseWorkspaceLeaseBestEffort();
        closeModal();
    }

    textEditClose?.addEventListener("click", () => {
        void tryClose();
    });

    textEditFindNextBtn?.addEventListener("click", () => findNext(true));
    textEditFindPrevBtn?.addEventListener("click", () => findPrev(true));

    textEditFindCaseBtn?.addEventListener("click", () => {
        findState.matchCase = !findState.matchCase;
        updateFindUi();
        refreshFindStatus();
    });
    textEditFindToggleBtn?.addEventListener("click", () => {
        if (isFindBarOpen()) closeFindBar();
        else openFindBar(true);
    });

    textEditFindCloseBtn?.addEventListener("click", () => {
        closeFindBar();
    });
    textEditFindInput?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            if (e.shiftKey) findPrev(true);
            else findNext(true);
        }
    });
    textEditFindInput?.addEventListener("input", () => {
        refreshFindStatus();
    });
    textEditModal?.addEventListener("click", (e) => {
        if (dragState.moved) {
            dragState.moved = false;
            return;
        }
        if (e.target === textEditModal) {
            void tryClose();
        }
    });

    textEditArea?.addEventListener("input", () => {
        const now = String(textEditArea.value || "");
        setDirty(now !== String(state.originalText || ""));
        refreshFindStatus();
    });

    textEditSaveBtn?.addEventListener("click", saveCurrent);
    textEditReloadBtn?.addEventListener("click", reloadCurrent);

    document.addEventListener("keydown", (e) => {
        if (!textEditModal || !textEditModal.classList.contains("show")) return;

        if (e.key === "Escape" && isFindBarOpen() && document.activeElement === textEditFindInput) {
            e.preventDefault();
            closeFindBar();
            return;
        }
        if (e.key === "Escape") {
            e.preventDefault();
            void tryClose();
            return;
        }
        if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === "f") {
            e.preventDefault();
            openFindBar(true);
            return;
        }
        if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === "s") {
            e.preventDefault();
            void saveCurrent();
        }
    });
    textEditHead?.addEventListener("pointerdown", (e) => {
        if (!textEditCard) return;
        if (e.target && e.target.closest && e.target.closest("button")) return;

        const rect = textEditCard.getBoundingClientRect();

        dragState.active = true;
        dragState.startX = e.clientX;
        dragState.startY = e.clientY;
        dragState.cardLeft = rect.left;
        dragState.cardTop = rect.top;
        dragState.moved = false;

        textEditCard.style.transform = "none";
        textEditCard.style.left = `${rect.left}px`;
        textEditCard.style.top = `${rect.top}px`;

        e.preventDefault();
    });

    document.addEventListener("pointermove", (e) => {
        if (!dragState.active || !textEditCard) return;

        const dx = e.clientX - dragState.startX;
        const dy = e.clientY - dragState.startY;

        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragState.moved = true;

        const rect = textEditCard.getBoundingClientRect();
        const pad = 8;

        const nextLeft = clamp(
            dragState.cardLeft + dx,
            pad,
            Math.max(pad, window.innerWidth - rect.width - pad)
        );

        const nextTop = clamp(
            dragState.cardTop + dy,
            pad,
            Math.max(pad, window.innerHeight - rect.height - pad)
        );

        textEditCard.style.left = `${nextLeft}px`;
        textEditCard.style.top = `${nextTop}px`;
    });

    function endDrag() {
        dragState.active = false;
    }

    document.addEventListener("pointerup", endDrag);
    document.addEventListener("pointercancel", endDrag);
    window.addEventListener("resize", () => {
        if (textEditModal && textEditModal.classList.contains("show")) {
            clampCardIntoViewport();
        }
    });
    FM.textEdit = {
        open: openEditorFor
    };
})();