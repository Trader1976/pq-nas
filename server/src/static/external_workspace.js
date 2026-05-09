(() => {
    "use strict";

    const params = new URLSearchParams(location.search);
    const workspaceId = String(params.get("workspace_id") || "").trim();

    const shell = document.getElementById("shell");
    const fileSurface = document.getElementById("fileSurface");
    const workspacePill = document.getElementById("workspacePill");
    const rolePill = document.getElementById("rolePill");
    const accessPill = document.getElementById("accessPill");
    const accessSub = document.getElementById("accessSub");
    const qrBox = document.getElementById("qrBox");
    const statusEl = document.getElementById("status");
    const filesEl = document.getElementById("files");
    const fileSub = document.getElementById("fileSub");
    const breadcrumbsEl = document.getElementById("breadcrumbs");
    const uploadBox = document.getElementById("uploadBox");
    const uploadFile = document.getElementById("uploadFile");
    const uploadFolderFile = document.getElementById("uploadFolderFile");
    const editorTools = document.getElementById("editorTools");
    const newFolderName = document.getElementById("newFolderName");
    const btnUpload = document.getElementById("btnUpload");
    const btnToggleUpload = document.getElementById("btnToggleUpload");
    const btnNewQr = document.getElementById("btnNewQr");
    const btnRefreshFiles = document.getElementById("btnRefreshFiles");
    const btnReload = document.getElementById("btnReload");
    const btnUp = document.getElementById("btnUp");
    const btnNewFolder = document.getElementById("btnNewFolder");
    const topReadyBadge = document.getElementById("topReadyBadge");
    const btnViewMode = document.getElementById("btnViewMode");
    const btnDirsFirst = document.getElementById("btnDirsFirst");
    const sortModeSelect = document.getElementById("sortMode");
    const emptyContextMenu = document.getElementById("emptyContextMenu");
    const itemContextMenu = document.getElementById("itemContextMenu");
    const selectionContextMenu = document.getElementById("selectionContextMenu");
    const propsModal = document.getElementById("propsModal");
    const propsTitle = document.getElementById("propsTitle");
    const propsPath = document.getElementById("propsPath");
    const propsBody = document.getElementById("propsBody");
    const propsClose = document.getElementById("propsClose");
    const textPreviewModal = document.getElementById("textPreviewModal");
    const textPreviewTitle = document.getElementById("textPreviewTitle");
    const textPreviewPath = document.getElementById("textPreviewPath");
    const textPreviewMeta = document.getElementById("textPreviewMeta");
    const textPreviewBody = document.getElementById("textPreviewBody");
    const textPreviewClose = document.getElementById("textPreviewClose");
    const textEditModal = document.getElementById("textEditModal");
    const textEditCard = document.getElementById("textEditCard") ||
        (textEditModal ? textEditModal.querySelector(".textEditCard, [role='dialog']") : null);
    const textEditHead = document.getElementById("textEditHead") ||
        (textEditModal ? textEditModal.querySelector(".textEditHead, .textPreviewHead, .modalHead") : null);
    const textEditTitle = document.getElementById("textEditTitle");
    const textEditPath = document.getElementById("textEditPath");
    const textEditInfo = document.getElementById("textEditInfo");
    const textEditStatus = document.getElementById("textEditStatus");
    const textEditArea = document.getElementById("textEditArea");
    const textEditClose = document.getElementById("textEditClose");
    const textEditReloadBtn = document.getElementById("textEditReloadBtn");
    const textEditFindToggleBtn = document.getElementById("textEditFindToggleBtn");
    const textEditFindBar = document.getElementById("textEditFindBar");
    const textEditFindInput = document.getElementById("textEditFindInput");
    const textEditFindPrevBtn = document.getElementById("textEditFindPrevBtn");
    const textEditFindNextBtn = document.getElementById("textEditFindNextBtn");
    const textEditFindCaseBtn = document.getElementById("textEditFindCaseBtn");
    const textEditFindStatus = document.getElementById("textEditFindStatus");
    const textEditFindCloseBtn = document.getElementById("textEditFindCloseBtn");
    const textEditSaveBtn = document.getElementById("textEditSaveBtn");
    const extPickerOverlay = document.getElementById("extPickerOverlay");
    const extPickerCard = extPickerOverlay ? extPickerOverlay.querySelector(".extPickerCard") : null;
    const extPickerHead = extPickerOverlay ? extPickerOverlay.querySelector(".extPickerHead") : null;
    const extPickerTitle = document.getElementById("extPickerTitle");
    const extPickerSub = document.getElementById("extPickerSub");
    const extPickerSource = document.getElementById("extPickerSource");
    const extPickerCrumbs = document.getElementById("extPickerCrumbs");
    const extPickerList = document.getElementById("extPickerList");
    const extPickerDest = document.getElementById("extPickerDest");
    const extPickerStatus = document.getElementById("extPickerStatus");
    const extPickerClose = document.getElementById("extPickerClose");
    const extPickerCancel = document.getElementById("extPickerCancel");
    const extPickerChoose = document.getElementById("extPickerChoose");
    const extPickerNewFolder = document.getElementById("extPickerNewFolder");

    let currentSessionId = "";
    let pollTimer = null;
    let currentPath = "";
    let canEdit = false;
    let currentRole = "";
    let signedIn = false;
    let uploadOpen = false;
    let uploadCancelRequested = false;
    let uploadCurrentXhr = null;
    let uploadDragDepth = 0;
    let contextItem = null;
    let pickerResolve = null;
    let pickerPath = "";
    let pickerMode = "move";
    let pickerItem = null;
    let pickerDrag = null;
    const hashCache = new Map();

    const EXT_VIEW_PREF_KEY = "pqnas_external_workspace_view_v1";
    const EXT_DIRS_FIRST_PREF_KEY = "pqnas_external_workspace_dirs_first_v1";
    const EXT_SORT_PREF_KEY = "pqnas_external_workspace_sort_v1";
    const CHUNKED_UPLOAD_THRESHOLD_BYTES = 64 * 1024 * 1024;

    let externalViewMode = (() => {
        try { return localStorage.getItem(EXT_VIEW_PREF_KEY) === "list" ? "list" : "grid"; }
        catch (_) { return "grid"; }
    })();

    let externalDirsFirst = (() => {
        try { return localStorage.getItem(EXT_DIRS_FIRST_PREF_KEY) !== "0"; }
        catch (_) { return true; }
    })();

    let externalSortMode = (() => {
        try { return localStorage.getItem(EXT_SORT_PREF_KEY) || "name-asc"; }
        catch (_) { return "name-asc"; }
    })();
    let textEditState = null;
    let textEditDrag = null;
    let textEditFindMatchCase = false;
    let textEditFindMatches = [];
    let textEditFindIndex = -1;

    function setStatus(text, kind) {
        statusEl.textContent = text || "";
        statusEl.classList.toggle("good", kind === "good");
        statusEl.classList.toggle("bad", kind === "bad");

        if (topReadyBadge) {
            topReadyBadge.classList.toggle("good", kind === "good");
            topReadyBadge.classList.toggle("bad", kind === "bad");
            topReadyBadge.classList.toggle("loading", /loading|uploading|moving|copying|saving|creating|checking|scan/i.test(String(text || "")));
        }
    }

    function setTopReadyBadge(text, kind) {
        if (!topReadyBadge) return;
        topReadyBadge.textContent = text || "ready";
        topReadyBadge.classList.toggle("good", kind === "good");
        topReadyBadge.classList.toggle("bad", kind === "bad");
        topReadyBadge.classList.toggle("loading", kind === "loading");
    }

    function applyExternalViewPrefs() {
        if (filesEl) filesEl.classList.toggle("listView", externalViewMode === "list");

        if (btnViewMode) {
            btnViewMode.textContent = externalViewMode === "list" ? "Grid" : "List";
            btnViewMode.title = externalViewMode === "list" ? "Switch to grid view" : "Switch to list view";
        }

        if (btnDirsFirst) {
            btnDirsFirst.classList.toggle("active", !!externalDirsFirst);
            btnDirsFirst.title = externalDirsFirst ? "Folders first is on" : "Folders first is off";
        }

        if (sortModeSelect && sortModeSelect.value !== externalSortMode) {
            sortModeSelect.value = externalSortMode;
        }
    }

    function workspaceItemIsDir(it) {
        const type = String((it && it.type) || (it && it.is_dir ? "dir" : "")).toLowerCase();
        return type === "dir" || type === "folder" || (it && it.is_dir === true);
    }

    function workspaceItemName(it) {
        return String((it && (it.name || it.path)) || "").toLowerCase();
    }

    function workspaceItemSize(it) {
        if (workspaceItemIsDir(it)) return -1;
        return Number((it && (it.size_bytes ?? it.size ?? it.bytes)) || 0);
    }

    function workspaceItemMtime(it) {
        return Number((it && (it.mtime_unix ?? it.mtime_epoch ?? it.mtime)) || 0);
    }

    function compareWorkspaceItems(a, b) {
        const ad = workspaceItemIsDir(a);
        const bd = workspaceItemIsDir(b);

        if (externalDirsFirst && ad !== bd) return ad ? -1 : 1;

        const mode = String(externalSortMode || "name-asc");
        let out = 0;

        if (mode === "name-desc" || mode === "name-asc") {
            out = workspaceItemName(a).localeCompare(workspaceItemName(b), undefined, { sensitivity:"base" });
            if (mode === "name-desc") out = -out;
        } else if (mode === "mtime-desc" || mode === "mtime-asc") {
            out = workspaceItemMtime(a) - workspaceItemMtime(b);
            if (mode === "mtime-desc") out = -out;
        } else if (mode === "size-desc" || mode === "size-asc") {
            out = workspaceItemSize(a) - workspaceItemSize(b);
            if (mode === "size-desc") out = -out;
        }

        if (out === 0) {
            out = workspaceItemName(a).localeCompare(workspaceItemName(b), undefined, { sensitivity:"base" });
        }

        return out;
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
        const units = ["B", "KiB", "MiB", "GiB", "TiB"];
        let v = Number(n || 0);
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return i === 0 ? `${v | 0} ${units[i]}` : `${v.toFixed(1)} ${units[i]}`;
    }

    function fmtTime(epoch) {
        const n = Number(epoch || 0);
        if (!Number.isFinite(n) || n <= 0) return "";
        try {
            return new Date(n * 1000).toLocaleString();
        } catch (_) {
            return "";
        }
    }

    async function apiJson(path, opts = {}) {
        const r = await fetch(path, {
            credentials: "include",
            cache: "no-store",
            ...opts,
            headers: {
                "Accept": "application/json",
                ...(opts.headers || {})
            }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
            throw new Error(msg);
        }
        return j;
    }


    // ---- External Workspace upload progress / drag-drop helpers -------------

    function safeUploadRelativePath(rel) {
        const parts = String(rel || "")
            .replaceAll("\\", "/")
            .split("/")
            .map((p) => p.trim())
            .filter((p) => p && p !== "." && p !== "..");
        return parts.join("/");
    }

    function uploadTargetPath(rel) {
        const clean = safeUploadRelativePath(rel);
        return normalizeRelPath(currentPath ? `${currentPath}/${clean}` : clean);
    }

    function ensureDropOverlay() {
        let overlay = document.getElementById("dropOverlay");
        if (overlay) return overlay;

        overlay = document.createElement("div");
        overlay.id = "dropOverlay";
        overlay.className = "dropOverlay";
        overlay.setAttribute("aria-hidden", "true");
        overlay.innerHTML = `
            <div class="dropOverlayCard">
                <div class="big">Drop files or folders to upload</div>
                <div class="small">Uploads will land in the current workspace folder.</div>
            </div>
        `;
        document.body.appendChild(overlay);
        return overlay;
    }

    function showDropOverlay(show) {
        const overlay = ensureDropOverlay();
        overlay.classList.toggle("show", !!show);
        overlay.setAttribute("aria-hidden", show ? "false" : "true");
    }

    function ensureUploadProgressModal() {
        let backdrop = document.getElementById("fmUploadProgressBackdrop");
        if (backdrop) return backdrop;

        backdrop = document.createElement("div");
        backdrop.id = "fmUploadProgressBackdrop";
        backdrop.className = "fmUploadProgressBackdrop";
        backdrop.hidden = true;
        backdrop.innerHTML = `
            <div class="fmUploadProgressCard" role="dialog" aria-modal="true" aria-labelledby="fmUploadProgressTitle">
                <div class="fmUploadProgressHead">
                    <div>
                        <div class="fmUploadProgressKicker">DNA-Nexus upload</div>
                        <div id="fmUploadProgressTitle" class="fmUploadProgressTitle">Uploading files</div>
                        <p id="fmUploadProgressSub">Preparing upload…</p>
                    </div>
                    <button id="fmUploadProgressCancelTop" class="fmUploadProgressX" type="button" title="Cancel upload">×</button>
                </div>
                <div class="fmUploadProgressBody">
                    <div id="fmUploadProgressFile" class="fmUploadProgressFile">Preparing upload…</div>
                    <div class="fmUploadProgressLine">
                        <div id="fmUploadProgressText">Starting…</div>
                        <div id="fmUploadProgressPct" class="fmUploadProgressPct">0%</div>
                    </div>
                    <div class="fmUploadProgressBar">
                        <div id="fmUploadProgressFill" class="fmUploadProgressFill"></div>
                    </div>
                    <div id="fmUploadProgressMeta" class="fmUploadProgressMeta"></div>
                </div>
                <div class="fmUploadProgressActions">
                    <button id="fmUploadProgressCloseBtn" class="fmUploadProgressBtn secondary" type="button" hidden>Close</button>
                    <button id="fmUploadProgressCancel" class="fmUploadProgressBtn secondary" type="button">Cancel upload</button>
                </div>
            </div>
        `;

        document.body.appendChild(backdrop);

        backdrop.querySelector("#fmUploadProgressCancel")?.addEventListener("click", requestUploadCancel);
        backdrop.querySelector("#fmUploadProgressCancelTop")?.addEventListener("click", requestUploadCancel);
        backdrop.querySelector("#fmUploadProgressCloseBtn")?.addEventListener("click", () => {
            backdrop.hidden = true;
        });

        return backdrop;
    }

    function setUploadModalProgress({ title, sub, file, text, pct, meta, done }) {
        const backdrop = ensureUploadProgressModal();
        const titleEl = backdrop.querySelector("#fmUploadProgressTitle");
        const subEl = backdrop.querySelector("#fmUploadProgressSub");
        const fileEl = backdrop.querySelector("#fmUploadProgressFile");
        const textEl = backdrop.querySelector("#fmUploadProgressText");
        const pctEl = backdrop.querySelector("#fmUploadProgressPct");
        const fillEl = backdrop.querySelector("#fmUploadProgressFill");
        const metaEl = backdrop.querySelector("#fmUploadProgressMeta");
        const closeBtn = backdrop.querySelector("#fmUploadProgressCloseBtn");
        const cancelBtn = backdrop.querySelector("#fmUploadProgressCancel");
        const cancelTop = backdrop.querySelector("#fmUploadProgressCancelTop");

        const safePct = Math.max(0, Math.min(100, Number(pct || 0)));

        if (titleEl && title != null) titleEl.textContent = String(title);
        if (subEl && sub != null) subEl.textContent = String(sub);
        if (fileEl && file != null) fileEl.textContent = String(file);
        if (textEl && text != null) textEl.textContent = String(text);
        if (pctEl) pctEl.textContent = `${Math.round(safePct)}%`;
        if (fillEl) fillEl.style.width = `${safePct.toFixed(1)}%`;
        if (metaEl && meta != null) metaEl.textContent = String(meta);

        if (closeBtn) closeBtn.hidden = !done;
        if (cancelBtn) cancelBtn.hidden = !!done;
        if (cancelTop) cancelTop.hidden = !!done;

        backdrop.hidden = false;
    }

    function requestUploadCancel() {
        uploadCancelRequested = true;
        setStatus("Cancelling upload…", "bad");

        try {
            if (uploadCurrentXhr) uploadCurrentXhr.abort();
        } catch (_) {}

        setUploadModalProgress({
            title: "Cancelling upload",
            sub: "Stopping the current transfer…",
            text: "Cancelling…",
            meta: "Already uploaded files remain stored.",
            pct: 100,
            done: false
        });
    }

    function parseUploadJsonText(text) {
        try {
            return text ? JSON.parse(text) : {};
        } catch (_) {
            return {};
        }
    }

    function uploadErrorMessageFromXhr(xhr) {
        const j = parseUploadJsonText(xhr && xhr.responseText);
        return (j && (j.message || j.error))
            ? `${j.error || ""} ${j.message || ""}`.trim()
            : `HTTP ${xhr ? xhr.status : 0}`;
    }


    async function postUploadJson(url, body) {
        const r = await fetch(url, {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(body || {})
        });

        const text = await r.text().catch(() => "");
        let j = null;
        try { j = text ? JSON.parse(text) : null; } catch (_) {}

        if (!r.ok || !j || j.ok !== true) {
            throw new Error(
                j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : (text ? text.replace(/\s+/g, " ").slice(0, 220) : `HTTP ${r.status}`)
            );
        }

        return j;
    }

    function xhrPutBlob(url, blob, onProgress) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            uploadCurrentXhr = xhr;

            const clearActive = () => {
                if (uploadCurrentXhr === xhr) uploadCurrentXhr = null;
            };

            xhr.open("PUT", url, true);
            xhr.withCredentials = true;
            xhr.timeout = 60 * 60 * 1000;
            xhr.setRequestHeader("Accept", "application/json");
            xhr.setRequestHeader("Content-Type", "application/octet-stream");

            xhr.upload.onprogress = (e) => {
                if (!onProgress) return;
                if (e.lengthComputable) onProgress(e.loaded, e.total);
                else onProgress(e.loaded, blob.size || 0);
            };

            xhr.onload = () => {
                clearActive();
                const j = parseUploadJsonText(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300 && j && j.ok) {
                    resolve(j);
                    return;
                }
                reject(new Error(uploadErrorMessageFromXhr(xhr)));
            };

            xhr.onerror = () => {
                clearActive();
                reject(new Error("upload chunk failed: network error"));
            };

            xhr.ontimeout = () => {
                clearActive();
                reject(new Error("upload chunk failed: timeout"));
            };

            xhr.onabort = () => {
                clearActive();
                reject(Object.assign(new Error(uploadCancelRequested ? "upload cancelled" : "upload chunk aborted"), {
                    kind: uploadCancelRequested ? "cancelled" : "network"
                }));
            };

            xhr.send(blob);
        });
    }

    async function cancelWorkspaceChunkedUploadBestEffort(uploadId) {
        if (!uploadId) return;

        try {
            await postUploadJson("/api/v4/workspaces/uploads/cancel", {
                workspace_id: workspaceId,
                upload_id: uploadId
            });
        } catch (_) {}
    }

    async function uploadFileToWorkspaceChunked(relPath, file, onProgress) {
        const size = Number(file && file.size != null ? file.size : 0);
        let uploadId = "";
        let uploadedCommitted = 0;

        try {
            const start = await postUploadJson("/api/v4/workspaces/uploads/start", {
                workspace_id: workspaceId,
                path: relPath,
                size_bytes: size,
                overwrite: false
            });

            uploadId = String(start.upload_id || "");
            const chunkSize = Math.max(1, Number(start.chunk_size || CHUNKED_UPLOAD_THRESHOLD_BYTES));
            const chunksTotal = Math.max(0, Number(start.chunks_total || Math.ceil(size / chunkSize)));

            if (!uploadId || chunksTotal < 1) {
                throw new Error("invalid chunked upload session");
            }

            for (let index = 0; index < chunksTotal; index++) {
                if (uploadCancelRequested) {
                    throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
                }

                const begin = index * chunkSize;
                const end = Math.min(size, begin + chunkSize);
                const blob = file.slice(begin, end);

                const url =
                    `/api/v4/workspaces/uploads/chunk?workspace_id=${encodeURIComponent(workspaceId)}` +
                    `&upload_id=${encodeURIComponent(uploadId)}` +
                    `&index=${encodeURIComponent(String(index))}`;

                await xhrPutBlob(url, blob, (loaded) => {
                    const totalLoaded = uploadedCommitted + Math.max(0, Number(loaded || 0));
                    if (onProgress) onProgress(totalLoaded, size, {
                        chunkIndex: index,
                        chunksTotal,
                        chunkLoaded: loaded,
                        chunkSize: blob.size
                    });
                });

                uploadedCommitted += blob.size;
                if (onProgress) onProgress(uploadedCommitted, size, {
                    chunkIndex: index,
                    chunksTotal,
                    chunkLoaded: blob.size,
                    chunkSize: blob.size
                });
            }

            if (uploadCancelRequested) {
                throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
            }

            const finish = await postUploadJson("/api/v4/workspaces/uploads/finish", {
                workspace_id: workspaceId,
                upload_id: uploadId
            });

            uploadId = "";
            return finish;
        } catch (e) {
            if (uploadId) await cancelWorkspaceChunkedUploadBestEffort(uploadId);
            throw e;
        }
    }

    async function uploadFileSmartToWorkspace(relPath, file, onProgress) {
        const size = Number(file && file.size != null ? file.size : 0);
        if (size > CHUNKED_UPLOAD_THRESHOLD_BYTES) {
            return await uploadFileToWorkspaceChunked(relPath, file, onProgress);
        }
        return await uploadFileToWorkspacePut(relPath, file, onProgress);
    }


    function uploadFileToWorkspacePut(relPath, file, onProgress) {
        return new Promise((resolve, reject) => {
            const qs = new URLSearchParams();
            qs.set("workspace_id", workspaceId);
            qs.set("path", relPath);

            const xhr = new XMLHttpRequest();
            uploadCurrentXhr = xhr;

            xhr.open("PUT", `/api/v4/workspaces/files/put?${qs.toString()}`, true);
            xhr.withCredentials = true;
            xhr.timeout = 0;
            xhr.setRequestHeader("Accept", "application/json");
            xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");

            xhr.upload.onprogress = (e) => {
                if (!e.lengthComputable) return;
                onProgress(Math.max(0, Number(e.loaded || 0)), Math.max(1, Number(e.total || file.size || 1)));
            };

            xhr.onload = () => {
                uploadCurrentXhr = null;
                const j = parseUploadJsonText(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300 && (!j || j.ok !== false)) {
                    resolve(j || {});
                    return;
                }
                reject(new Error(uploadErrorMessageFromXhr(xhr)));
            };

            xhr.onerror = () => {
                uploadCurrentXhr = null;
                reject(new Error("upload failed: network error"));
            };

            xhr.onabort = () => {
                uploadCurrentXhr = null;
                reject(Object.assign(new Error(uploadCancelRequested ? "upload cancelled" : "upload aborted"), {
                    kind: uploadCancelRequested ? "cancelled" : "network"
                }));
            };

            xhr.send(file);
        });
    }

    async function uploadRelFiles(relFiles) {
        if (!canEdit) {
            setStatus("Upload requires editor access.", "bad");
            return;
        }

        const files = (relFiles || [])
            .filter((x) => x && x.file)
            .map((x) => ({
                rel: safeUploadRelativePath(x.rel || x.file.webkitRelativePath || x.file.name),
                file: x.file
            }))
            .filter((x) => x.rel && x.file);

        if (!files.length) {
            setStatus("No files selected for upload.", "bad");
            return;
        }

        uploadCancelRequested = false;

        const totalBytes = files.reduce((sum, x) => sum + Math.max(0, Number(x.file.size || 0)), 0) || 1;
        let committedBytes = 0;
        let completed = 0;

        setStatus(`Uploading ${files.length} file(s)…`, "good");

        for (let i = 0; i < files.length; i++) {
            if (uploadCancelRequested) break;

            const item = files[i];
            const target = uploadTargetPath(item.rel);
            const displayName = item.rel || item.file.name;
            let lastLoaded = 0;

            setUploadModalProgress({
                title: "Uploading files",
                sub: `${i + 1} / ${files.length}`,
                file: displayName,
                text: `Uploading ${fmtSize(item.file.size || 0)}…`,
                pct: (committedBytes / totalBytes) * 100,
                meta: `Destination: /${target}`,
                done: false
            });

            try {
                await uploadFileSmartToWorkspace(target, item.file, (loaded, total, ctx) => {
                    lastLoaded = Math.max(0, Number(loaded || 0));
                    const pct = ((committedBytes + lastLoaded) / totalBytes) * 100;
                    setUploadModalProgress({
                        title: "Uploading files",
                        sub: `${i + 1} / ${files.length}`,
                        file: displayName,
                        text: `${fmtSize(loaded)} / ${fmtSize(total)}`,
                        pct,
                        meta: `Destination: /${target}`,
                        done: false
                    });
                });

                committedBytes += Math.max(Number(item.file.size || 0), lastLoaded);
                completed++;

                setUploadModalProgress({
                    title: "Uploading files",
                    sub: `${completed} / ${files.length} uploaded`,
                    file: displayName,
                    text: "Uploaded",
                    pct: (committedBytes / totalBytes) * 100,
                    meta: `Stored at /${target}`,
                    done: false
                });
            } catch (e) {
                const msg = e && e.message ? e.message : String(e || "upload failed");
                const cancelled = e && e.kind === "cancelled";

                setUploadModalProgress({
                    title: cancelled ? "Upload cancelled" : "Upload failed",
                    sub: cancelled ? `${completed} file(s) uploaded before cancel.` : `${completed} file(s) uploaded before failure.`,
                    file: displayName,
                    text: cancelled ? "Cancelled" : "Failed",
                    pct: cancelled ? 100 : (committedBytes / totalBytes) * 100,
                    meta: msg,
                    done: true
                });

                setStatus(cancelled ? "Upload cancelled." : `Upload failed: ${msg}`, "bad");

                try { await loadFiles(currentPath); } catch (_) {}
                uploadCancelRequested = false;
                uploadCurrentXhr = null;
                return;
            }
        }

        uploadCancelRequested = false;
        uploadCurrentXhr = null;

        setUploadModalProgress({
            title: "Upload complete",
            sub: `${completed} file(s) uploaded.`,
            file: "Finished",
            text: "Uploaded",
            pct: 100,
            meta: "Workspace file list refreshed.",
            done: true
        });

        setStatus(`Uploaded ${completed} file(s).`, "good");
        await loadFiles(currentPath);
    }

    async function uploadSelectedFolderFiles() {
        const selected = Array.from((uploadFolderFile && uploadFolderFile.files) || []);
        const relFiles = selected.map((file) => ({
            rel: file.webkitRelativePath || file.name,
            file
        }));

        try {
            await uploadRelFiles(relFiles);
        } finally {
            if (uploadFolderFile) uploadFolderFile.value = "";
        }
    }

    function fileFromEntry(entry) {
        return new Promise((resolve, reject) => {
            entry.file(resolve, reject);
        });
    }

    function readDirectoryEntries(reader) {
        return new Promise((resolve) => {
            const out = [];

            function readBatch() {
                reader.readEntries((batch) => {
                    if (!batch || !batch.length) {
                        resolve(out);
                        return;
                    }
                    out.push(...batch);
                    readBatch();
                }, () => resolve(out));
            }

            readBatch();
        });
    }

    async function walkDroppedEntry(entry, prefix, out) {
        if (!entry) return;

        if (entry.isFile) {
            const file = await fileFromEntry(entry);
            out.push({
                rel: safeUploadRelativePath(prefix + file.name),
                file
            });
            return;
        }

        if (entry.isDirectory) {
            const reader = entry.createReader();
            const children = await readDirectoryEntries(reader);
            const nextPrefix = prefix + entry.name + "/";
            for (const child of children) {
                await walkDroppedEntry(child, nextPrefix, out);
            }
        }
    }

    async function droppedFilesFromDataTransfer(dataTransfer) {
        const out = [];
        const items = Array.from((dataTransfer && dataTransfer.items) || []);
        const entries = items
            .map((item) => item && typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null)
            .filter(Boolean);

        if (entries.length) {
            for (const entry of entries) {
                await walkDroppedEntry(entry, "", out);
            }
            return out;
        }

        const files = Array.from((dataTransfer && dataTransfer.files) || []);
        for (const file of files) {
            out.push({
                rel: file.webkitRelativePath || file.name,
                file
            });
        }
        return out;
    }

    function wireExternalDragDropUpload() {
        if (window.__externalWorkspaceUploadDndWired) return;
        window.__externalWorkspaceUploadDndWired = true;

        const hasFiles = (ev) => {
            const dt = ev && ev.dataTransfer;
            if (!dt) return false;

            try {
                const types = Array.from(dt.types || []);
                if (types.includes("Files")) return true;
            } catch (_) {}

            try {
                return Array.from(dt.items || []).some((it) => it && it.kind === "file");
            } catch (_) {}

            return false;
        };

        const shouldAcceptDrop = (ev) => {
            if (!hasFiles(ev)) return false;
            if (!signedIn || !canEdit) return false;
            return true;
        };

        const stopBrowserFileDrop = (ev) => {
            if (!hasFiles(ev)) return;
            ev.preventDefault();
            ev.stopPropagation();
        };

        window.addEventListener("dragenter", (ev) => {
            if (!hasFiles(ev)) return;
            stopBrowserFileDrop(ev);

            if (!signedIn || !canEdit) {
                if (ev.dataTransfer) ev.dataTransfer.dropEffect = "none";
                setStatus("Upload requires editor access.", "bad");
                return;
            }

            uploadDragDepth++;
            showDropOverlay(true);
            if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
        }, true);

        window.addEventListener("dragover", (ev) => {
            if (!hasFiles(ev)) return;
            stopBrowserFileDrop(ev);

            if (!signedIn || !canEdit) {
                if (ev.dataTransfer) ev.dataTransfer.dropEffect = "none";
                return;
            }

            showDropOverlay(true);
            if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
        }, true);

        window.addEventListener("dragleave", (ev) => {
            if (!hasFiles(ev)) return;

            uploadDragDepth = Math.max(0, uploadDragDepth - 1);

            // When leaving the browser window, clientX/Y usually hit 0 or viewport edge.
            const leavingWindow =
                ev.clientX <= 0 ||
                ev.clientY <= 0 ||
                ev.clientX >= window.innerWidth ||
                ev.clientY >= window.innerHeight;

            if (uploadDragDepth === 0 || leavingWindow) {
                uploadDragDepth = 0;
                showDropOverlay(false);
            }
        }, true);

        window.addEventListener("drop", async (ev) => {
            if (!hasFiles(ev)) return;
            stopBrowserFileDrop(ev);

            uploadDragDepth = 0;
            showDropOverlay(false);

            if (!signedIn || !canEdit) {
                setStatus("Upload requires editor access.", "bad");
                return;
            }

            try {
                setStatus("Reading dropped files…", "good");

                const relFiles = await droppedFilesFromDataTransfer(ev.dataTransfer);

                if (!relFiles.length) {
                    setStatus("Drag & drop did not provide files. Use Upload instead.", "bad");
                    return;
                }

                setStatus(`Preparing ${relFiles.length} dropped file(s)…`, "good");
                await uploadRelFiles(relFiles);
            } catch (err) {
                setStatus(`Drop upload failed: ${err && err.message ? err.message : err}`, "bad");
            }
        }, true);
    }


    function normalizeRelPath(p) {
        let v = String(p || "").trim();
        v = v.replaceAll("\\", "/");
        while (v.startsWith("/")) v = v.slice(1);
        while (v.endsWith("/") && v.length > 1) v = v.slice(0, -1);
        if (v === "." || v === "/") return "";
        return v;
    }

    function childPath(base, name) {
        const b = normalizeRelPath(base);
        const n = normalizeRelPath(name);
        return b ? `${b}/${n}` : n;
    }

    function parentPath(p) {
        const v = normalizeRelPath(p);
        const i = v.lastIndexOf("/");
        if (i < 0) return "";
        return v.slice(0, i);
    }

    function downloadUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/get?${qs.toString()}`;
    }

    function deleteUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/delete?${qs.toString()}`;
    }

    function syncUploadPanel() {
        if (uploadBox) uploadBox.classList.add("hidden");
        if (btnToggleUpload) btnToggleUpload.textContent = "Upload";
    }

    function applyAccessInfo(j) {
        signedIn = true;
        currentRole = String(j.role || "");
        canEdit = !!j.can_edit;

        const roleLabel = currentRole ? currentRole[0].toUpperCase() + currentRole.slice(1) : "Member";
        const accessLabel = canEdit ? "Editor access" : "View-only access";

        rolePill.textContent = `Role: ${roleLabel}`;
        rolePill.classList.remove("hidden", "edit", "readonly");
        rolePill.classList.add(canEdit ? "edit" : "readonly");

        accessPill.textContent = accessLabel;
        accessPill.classList.remove("good", "edit", "readonly");
        accessPill.classList.add(canEdit ? "edit" : "readonly");

        if (editorTools) editorTools.classList.toggle("hidden", !canEdit);
        if (!canEdit) uploadOpen = false;
        syncUploadPanel();

        if (fileSub) {
            fileSub.textContent = canEdit
                ? "You can browse, download, upload, and create folders in this workspace."
                : "You can browse and download files in this workspace.";
        }
    }

    function hideContextMenus() {
        if (emptyContextMenu) emptyContextMenu.classList.add("hidden");
        if (itemContextMenu) itemContextMenu.classList.add("hidden");
        if (selectionContextMenu) selectionContextMenu.classList.add("hidden");
        contextItem = null;
    }


    function resetMarqueeVisual() {
        const boxes = document.querySelectorAll(".marqueeBox, .selectionBox, .selectionRect, #marqueeBox, #selectionBox, #selectionRect");
        boxes.forEach((box) => {
            box.classList.add("hidden");
            box.style.display = "none";
            box.style.left = "0px";
            box.style.top = "0px";
            box.style.width = "0px";
            box.style.height = "0px";
        });
    }

    function placeContextMenu(menu, x, y) {
        if (!menu) return;
        menu.classList.remove("hidden");

        const pad = 8;
        const rect = menu.getBoundingClientRect();
        let left = x;
        let top = y;

        if (left + rect.width + pad > window.innerWidth) {
            left = Math.max(pad, window.innerWidth - rect.width - pad);
        }
        if (top + rect.height + pad > window.innerHeight) {
            top = Math.max(pad, window.innerHeight - rect.height - pad);
        }

        menu.style.left = `${left}px`;
        menu.style.top = `${top}px`;
    }

    function showPlaceholder(label) {
        setStatus(`${label} is not enabled for external workspace access yet.`, "bad");
    }

    function itemFromRow(row) {
        if (!row) return null;
        const isDir = row.hasAttribute("data-dir");
        const rel = isDir ? (row.dataset.dir || "") : (row.dataset.file || "");
        return {
            isDir,
            rel,
            name: row.dataset.name || rel.split("/").pop() || "item",
            type: row.dataset.type || (isDir ? "dir" : "file"),
            size: row.dataset.size || "",
            mtime: row.dataset.mtime || ""
        };
    }

    function kvRow(k, v) {
        const kEl = document.createElement("div");
        kEl.className = "k";
        kEl.textContent = k;

        const vEl = document.createElement("div");
        vEl.className = "v mono";
        vEl.textContent = v == null ? "" : String(v);

        return [kEl, vEl];
    }

    function openPropsModal() {
        if (!propsModal) return;
        propsModal.classList.add("show");
        propsModal.setAttribute("aria-hidden", "false");
    }

    function closePropsModal() {
        if (!propsModal) return;
        propsModal.classList.remove("show");
        propsModal.setAttribute("aria-hidden", "true");
    }

    const TEXT_PREVIEW_EXTS = new Set([
        "txt", "text", "log", "md", "markdown", "rst",
        "json", "jsonl", "xml", "html", "htm", "css", "scss", "sass",
        "js", "mjs", "cjs", "ts", "tsx", "jsx",
        "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx",
        "java", "kt", "kts", "go", "rs", "py", "rb", "php", "pl", "pm", "lua",
        "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd",
        "ini", "cfg", "conf", "cnf", "env", "properties",
        "yaml", "yml", "toml", "sql", "csv", "tsv",
        "cmake", "mk", "make", "gradle", "dockerfile",
        "service", "timer", "socket", "desktop", "rules",
        "srt", "vtt", "svg"
    ]);

    const TEXT_PREVIEW_SPECIAL_NAMES = new Set([
        "makefile", "dockerfile", "cmakelists.txt",
        "readme", "license", "copying", "changelog",
        ".gitignore", ".gitattributes", ".editorconfig", ".env"
    ]);

    function isTextPreviewableName(name) {
        const n = String(name || "").trim().toLowerCase();
        if (!n) return false;
        if (TEXT_PREVIEW_SPECIAL_NAMES.has(n)) return true;

        const clean = n.split("?")[0].split("#")[0];
        const i = clean.lastIndexOf(".");
        if (i < 0 || i === clean.length - 1) return false;

        return TEXT_PREVIEW_EXTS.has(clean.slice(i + 1));
    }

    function isTextFileItem(item) {
        return !!item && !item.isDir && isTextPreviewableName(item.name || item.rel || "");
    }

    function configureExternalItemContextMenu(item) {
        if (!itemContextMenu || !item) return;

        const openBtn = itemContextMenu.querySelector('[data-action="open"]');
        const previewBtn = itemContextMenu.querySelector('[data-action="preview"]');
        const isText = isTextFileItem(item);

        if (previewBtn) {
            previewBtn.classList.remove("hidden");
            previewBtn.style.display = "";
            previewBtn.textContent = isText ? "Open / edit text?" : "Open preview";
            previewBtn.disabled = item.isDir || !isText;
        }

        if (openBtn) {
            if (isText) {
                // For text/code files, this old row must disappear.
                // The preview action becomes the smart File Manager-style Open / edit text? row.
                openBtn.classList.add("hidden");
                openBtn.style.display = "none";
                openBtn.disabled = true;
            } else {
                openBtn.classList.remove("hidden");
                openBtn.style.display = "";
                openBtn.disabled = false;
                openBtn.textContent = item.isDir ? "Open folder" : "Open original";
            }
        }
    }

    function textPreviewUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/read_text?${qs.toString()}`;
    }

    function openTextPreviewModal() {
        if (!textPreviewModal) return;
        textPreviewModal.classList.add("show");
        textPreviewModal.setAttribute("aria-hidden", "false");
    }

    function closeTextPreviewModal() {
        if (!textPreviewModal) return;
        textPreviewModal.classList.remove("show");
        textPreviewModal.setAttribute("aria-hidden", "true");
    }

    function pickTextPreviewBody(j) {
        if (!j || typeof j !== "object") return "";
        for (const key of ["text", "content", "body", "data"]) {
            if (typeof j[key] === "string") return j[key];
        }
        return "";
    }

    async function openTextPreview(item) {
        if (!item || item.isDir) {
            showPlaceholder("Preview");
            return;
        }

        const rel = normalizeRelPath(item.rel || "");
        const name = item.name || basenameFromPath(rel);

        if (!isTextPreviewableName(name)) {
            setStatus("Preview is enabled for text/code files only.", "bad");
            return;
        }

        if (textPreviewTitle) textPreviewTitle.textContent = "Text preview";
        if (textPreviewPath) textPreviewPath.textContent = "/" + rel;
        if (textPreviewMeta) textPreviewMeta.textContent = "Loading…";
        if (textPreviewBody) textPreviewBody.textContent = "";

        openTextPreviewModal();

        let j = null;
        try {
            j = await apiJson(textPreviewUrl(rel));
        } catch (e) {
            if (textPreviewMeta) textPreviewMeta.textContent = "Preview failed.";
            if (textPreviewBody) textPreviewBody.textContent = String(e && e.message ? e.message : e);
            throw e;
        }

        const body = pickTextPreviewBody(j);
        const bits = [];

        if (j.bytes != null) bits.push(fmtSize(j.bytes));
        else if (item.size) bits.push(fmtSize(item.size));

        if (j.mime) bits.push(String(j.mime));
        if (j.mtime_epoch) bits.push("Modified " + fmtUnixLocal(j.mtime_epoch));
        else if (item.mtime) bits.push("Modified " + fmtUnixLocal(item.mtime));

        if (j.sha256) bits.push("SHA-256 " + String(j.sha256).slice(0, 16) + "…");

        if (textPreviewMeta) textPreviewMeta.textContent = bits.join(" · ") || "Text file";
        if (textPreviewBody) textPreviewBody.textContent = body;
    }


    async function copyText(text) {
        const value = String(text || "");
        if (!value) return false;

        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(value);
                return true;
            }
        } catch (_) {}

        try {
            const ta = document.createElement("textarea");
            ta.value = value;
            ta.setAttribute("readonly", "readonly");
            ta.style.position = "fixed";
            ta.style.left = "-9999px";
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand("copy");
            ta.remove();
            return !!ok;
        } catch (_) {
            return false;
        }
    }

    function miniCopyButton(getTextFn) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "propsMiniBtn";
        b.textContent = "Copy";
        b.onclick = async () => {
            const text = getTextFn ? String(getTextFn() || "") : "";
            const ok = text ? await copyText(text) : false;
            b.textContent = ok ? "Copied" : "Copy failed";
            setTimeout(() => { b.textContent = "Copy"; }, 1100);
        };
        return b;
    }

    function addPropsRow(k, v, opts = {}) {
        if (!propsBody) return;
        if (v === undefined || v === null || v === "") return;

        const [kEl, vEl] = kvRow(k, v);

        if (opts.copy) {
            vEl.textContent = "";
            vEl.classList.remove("mono");
            const wrap = document.createElement("div");
            wrap.className = "propsValueRow";

            const line = document.createElement("span");
            line.className = "mono";
            line.textContent = String(v);

            wrap.appendChild(line);
            wrap.appendChild(miniCopyButton(() => line.textContent));
            vEl.appendChild(wrap);
        }

        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
    }

    function fmtUnixLocal(sec) {
        if (!sec) return "";
        const d = new Date(Number(sec) * 1000);
        if (isNaN(d.getTime())) return String(sec);

        const pad2 = (n) => String(n).padStart(2, "0");
        return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    }

    function permsFromOctal(modeStr) {
        if (!modeStr || typeof modeStr !== "string") return "";
        const s = modeStr.trim();
        if (!/^[0-7]{3,4}$/.test(s)) return "";
        const oct = s.length === 4 ? s.slice(1) : s;
        const bits = oct.split("").map((c) => parseInt(c, 8));
        if (bits.length !== 3 || bits.some((x) => Number.isNaN(x))) return "";

        const rwx = (b) => {
            const r = (b & 4) ? "r" : "-";
            const w = (b & 2) ? "w" : "-";
            const x = (b & 1) ? "x" : "-";
            return r + w + x;
        };

        return rwx(bits[0]) + rwx(bits[1]) + rwx(bits[2]);
    }

    function statUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath) || ".");
        return `/api/v4/workspaces/files/stat?${qs.toString()}`;
    }

    function hashUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        qs.set("algo", "sha256");
        return `/api/v4/workspaces/files/hash?${qs.toString()}`;
    }

    function hashCacheKey(relPath, mtimeEpoch, sizeBytes) {
        return [
            workspaceId,
            normalizeRelPath(relPath),
            String(mtimeEpoch || 0),
            String(sizeBytes || 0)
        ].join("|");
    }

    function pickSha256FromHashResponse(j) {
        if (!j || typeof j !== "object") return "";
        if (typeof j.digest_hex === "string" && j.digest_hex) return j.digest_hex;
        if (typeof j.sha256 === "string" && j.sha256) return j.sha256;
        if (j.hashes && typeof j.hashes.sha256 === "string") return j.hashes.sha256;
        if (j.digests && typeof j.digests.sha256 === "string") return j.digests.sha256;
        if (typeof j.hash === "string" && j.hash) return j.hash;
        return "";
    }

    async function fetchSha256ForRelPath(relPath) {
        const p = normalizeRelPath(relPath);
        if (!p) throw new Error("missing path");

        const r = await fetch(hashUrl(p), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" },
            body: ""
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || `HTTP ${r.status}`);
        }

        const sha256 = pickSha256FromHashResponse(j);
        if (!sha256) throw new Error("server did not return sha256");
        return { sha256, raw:j };
    }


    function writeTextUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/write_text?${qs.toString()}`;
    }

    function pickTextFromReadResponse(j) {
        if (!j || typeof j !== "object") return "";
        if (typeof j.text === "string") return j.text;
        if (typeof j.content === "string") return j.content;
        if (typeof j.body === "string") return j.body;
        if (typeof j.data === "string") return j.data;
        return "";
    }

    function setTextEditStatus(msg, kind) {
        if (!textEditStatus) return;
        textEditStatus.textContent = msg || "";
        textEditStatus.style.color = kind === "bad"
            ? "var(--bad)"
            : (kind === "good" ? "var(--good)" : "");
    }

    function textEditDirty() {
        return !!(textEditState && textEditArea && textEditArea.value !== textEditState.originalText);
    }

    function syncTextEditDirty() {
        if (!textEditSaveBtn || !textEditArea || !textEditState) return;

        const dirty = textEditDirty();
        textEditSaveBtn.disabled = !canEdit || !dirty || textEditArea.readOnly;

        if (textEditInfo) {
            const bytes = new Blob([textEditArea.value || ""]).size;
            const dirtyText = dirty ? "modified" : "clean";
            textEditInfo.textContent = `${fmtSize(bytes)} in editor · ${dirtyText}`;
        }
    }

    function openTextEditorModal() {
        if (!textEditModal) return;
        document.body.classList.add("externalTextEditorOpen");
        textEditModal.classList.add("show");
        textEditModal.setAttribute("aria-hidden", "false");
        setTimeout(() => {
            try { textEditArea && textEditArea.focus({ preventScroll:true }); } catch (_) {}
        }, 0);
    }

    function closeTextEditor(force = false) {
        if (!force && textEditDirty()) {
            const ok = confirm("Close text editor?\n\nUnsaved changes will be lost.");
            if (!ok) return false;
        }

        if (textEditModal) {
            textEditModal.classList.remove("show");
            textEditModal.setAttribute("aria-hidden", "true");
        }

        document.body.classList.remove("externalTextEditorOpen");

        textEditState = null;
        textEditFindMatches = [];
        textEditFindIndex = -1;
        return true;
    }

    function textEditorClampPosition(left, top) {
        if (!textEditCard) return { left, top };
        const rect = textEditCard.getBoundingClientRect();
        const pad = 6;
        return {
            left: Math.min(Math.max(pad, left), Math.max(pad, window.innerWidth - rect.width - pad)),
            top: Math.min(Math.max(pad, top), Math.max(pad, window.innerHeight - rect.height - pad))
        };
    }

    function beginTextEditorDrag(ev) {
        if (!textEditCard || !textEditHead) return;
        if (ev.button !== 0) return;
        if (ev.target.closest("button, input, textarea, select, a")) return;

        const rect = textEditCard.getBoundingClientRect();
        textEditDrag = {
            pointerId: ev.pointerId,
            dx: ev.clientX - rect.left,
            dy: ev.clientY - rect.top
        };

        textEditCard.classList.add("dragging");
        textEditCard.style.position = "fixed";
        textEditCard.style.left = `${rect.left}px`;
        textEditCard.style.top = `${rect.top}px`;
        textEditCard.style.transform = "none";

        try { textEditHead.setPointerCapture(ev.pointerId); } catch (_) {}

        window.addEventListener("pointermove", moveTextEditorDrag, true);
        window.addEventListener("pointerup", endTextEditorDrag, true);
        window.addEventListener("pointercancel", endTextEditorDrag, true);

        ev.preventDefault();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();
        else ev.stopPropagation();
    }

    function moveTextEditorDrag(ev) {
        if (!textEditDrag || !textEditCard) return;
        if (ev.pointerId !== textEditDrag.pointerId) return;

        const pos = textEditorClampPosition(
            ev.clientX - textEditDrag.dx,
            ev.clientY - textEditDrag.dy
        );

        textEditCard.style.left = `${pos.left}px`;
        textEditCard.style.top = `${pos.top}px`;
        textEditCard.style.transform = "none";
    }

    function endTextEditorDrag(ev) {
        if (!textEditDrag) return;
        if (ev.pointerId !== textEditDrag.pointerId) return;

        if (textEditCard) textEditCard.classList.remove("dragging");
        try { textEditHead && textEditHead.releasePointerCapture(ev.pointerId); } catch (_) {}

        window.removeEventListener("pointermove", moveTextEditorDrag, true);
        window.removeEventListener("pointerup", endTextEditorDrag, true);
        window.removeEventListener("pointercancel", endTextEditorDrag, true);

        textEditDrag = null;
    }

    function resetTextEditorPosition() {
        if (!textEditCard) return;
        textEditCard.style.position = "";
        textEditCard.style.left = "";
        textEditCard.style.top = "";
        textEditCard.style.transform = "";
    }

    async function openTextEditor(item) {
        if (!item || !item.rel) return;

        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        const rel = normalizeRelPath(item.rel);
        const name = item.name || basenameFromPath(rel);

        if (!isTextPreviewableName(name)) {
            setStatus("Text editor is only enabled for text/code files.", "bad");
            return;
        }

        if (textEditDirty()) {
            const ok = confirm("Open another file?\n\nUnsaved changes in the current editor will be lost.");
            if (!ok) return;
        }

        resetTextEditorPosition();

        if (textEditTitle) textEditTitle.textContent = "Edit text file";
        if (textEditPath) textEditPath.textContent = "/" + rel;
        if (textEditArea) {
            textEditArea.value = "";
            textEditArea.readOnly = true;
        }
        setTextEditStatus("Loading…");

        openTextEditorModal();

        const j = await apiJson(textPreviewUrl(rel));
        const text = pickTextFromReadResponse(j);

        textEditState = {
            item,
            rel,
            originalText: text,
            mtimeEpoch: Number(j.mtime_epoch || j.mtime_unix || 0),
            sha256: pickSha256FromHashResponse(j)
        };

        if (textEditArea) {
            textEditArea.value = text;
            textEditArea.readOnly = false;
        }

        const bytes = j.bytes != null ? Number(j.bytes) : new Blob([text]).size;
        if (textEditInfo) textEditInfo.textContent = `${fmtSize(bytes)} · ${j.mime || "text"} · editable`;
        setTextEditStatus("Ready.", "good");
        syncTextEditDirty();
        updateTextEditorFind();
    }

    async function reloadTextEditor() {
        if (!textEditState) return;
        if (textEditDirty()) {
            const ok = confirm("Reload from server?\n\nUnsaved changes will be lost.");
            if (!ok) return;
        }

        const item = textEditState.item || {
            rel: textEditState.rel,
            name: basenameFromPath(textEditState.rel),
            isDir: false
        };

        await openTextEditor(item);
    }

    async function saveTextEditor() {
        if (!canEdit) {
            setTextEditStatus("This workspace session is view-only.", "bad");
            return;
        }
        if (!textEditState || !textEditArea) return;

        const rel = normalizeRelPath(textEditState.rel);
        const text = textEditArea.value;

        setTextEditStatus("Saving…");
        if (textEditSaveBtn) textEditSaveBtn.disabled = true;

        const body = {
            workspace_id: workspaceId,
            path: rel,
            text
        };

        if (textEditState.mtimeEpoch) body.expected_mtime_epoch = textEditState.mtimeEpoch;
        if (textEditState.sha256) body.expected_sha256 = textEditState.sha256;

        const j = await apiJson(writeTextUrl(rel), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        textEditState.originalText = text;
        textEditState.mtimeEpoch = Number(j.mtime_epoch || j.new_mtime_epoch || textEditState.mtimeEpoch || 0);
        textEditState.sha256 = j.sha256 || j.new_sha256 || j.digest_hex || textEditState.sha256 || "";

        setTextEditStatus("Saved.", "good");
        syncTextEditDirty();
        await loadFiles(currentPath);
    }

    function updateTextEditorFind() {
        if (!textEditArea || !textEditFindInput || !textEditFindStatus) return;

        const qRaw = textEditFindInput.value || "";
        if (!qRaw) {
            textEditFindMatches = [];
            textEditFindIndex = -1;
            textEditFindStatus.textContent = "";
            return;
        }

        const hay = textEditFindMatchCase ? textEditArea.value : textEditArea.value.toLowerCase();
        const needle = textEditFindMatchCase ? qRaw : qRaw.toLowerCase();

        const matches = [];
        let pos = 0;
        while (needle && pos <= hay.length) {
            const i = hay.indexOf(needle, pos);
            if (i < 0) break;
            matches.push(i);
            pos = i + Math.max(1, needle.length);
            if (matches.length > 5000) break;
        }

        textEditFindMatches = matches;

        if (!matches.length) {
            textEditFindIndex = -1;
            textEditFindStatus.textContent = "0/0";
            return;
        }

        if (textEditFindIndex < 0 || textEditFindIndex >= matches.length) {
            textEditFindIndex = 0;
        }

        const start = matches[textEditFindIndex];
        textEditArea.focus({ preventScroll:true });
        textEditArea.setSelectionRange(start, start + qRaw.length);
        textEditFindStatus.textContent = `${textEditFindIndex + 1}/${matches.length}`;
    }

    function stepTextEditorFind(delta) {
        if (!textEditFindMatches.length) {
            updateTextEditorFind();
            return;
        }

        textEditFindIndex += delta;
        if (textEditFindIndex < 0) textEditFindIndex = textEditFindMatches.length - 1;
        if (textEditFindIndex >= textEditFindMatches.length) textEditFindIndex = 0;
        updateTextEditorFind();
    }

    function showTextEditorFind() {
        if (!textEditFindBar) return;
        textEditFindBar.classList.remove("hidden");
        setTimeout(() => {
            try {
                textEditFindInput && textEditFindInput.focus({ preventScroll:true });
                textEditFindInput && textEditFindInput.select();
            } catch (_) {}
        }, 0);
        updateTextEditorFind();
    }

    function hideTextEditorFind() {
        if (textEditFindBar) textEditFindBar.classList.add("hidden");
        textEditFindMatches = [];
        textEditFindIndex = -1;
        if (textEditFindStatus) textEditFindStatus.textContent = "";
        try { textEditArea && textEditArea.focus({ preventScroll:true }); } catch (_) {}
    }

    async function showProperties(item) {
        if (!item) return;

        const rel = normalizeRelPath(item.rel || "");
        const name = item.name || basenameFromPath(rel);
        const isDirHint = !!item.isDir;

        if (propsTitle) propsTitle.textContent = isDirHint ? "Folder properties" : "File properties";
        if (propsPath) propsPath.textContent = "/" + rel;
        if (propsBody) propsBody.innerHTML = "";

        addPropsRow("Name", name);
        addPropsRow("Type", isDirHint ? "Folder" : "File");
        addPropsRow("Path", "/" + rel, { copy:true });
        if (!isDirHint) addPropsRow("Size", fmtSize(item.size || 0));
        if (item.mtime) addPropsRow("Modified", fmtUnixLocal(item.mtime));
        addPropsRow("Details", "Loading…");

        openPropsModal();

        let st = null;
        try {
            st = await apiJson(statUrl(rel));
        } catch (e) {
            st = {
                ok:false,
                error:"client_error",
                message:String(e && e.message ? e.message : e)
            };
        }

        if (!propsBody) return;
        propsBody.innerHTML = "";

        if (!st || !st.ok) {
            addPropsRow("Name", name);
            addPropsRow("Type", isDirHint ? "Folder" : "File");
            addPropsRow("Path", "/" + rel, { copy:true });
            addPropsRow("Error", st && (st.message || st.error) ? `${st.error || "error"}: ${st.message || ""}`.trim() : "Failed to load properties");
            return;
        }

        const isDir = st.type === "dir";
        const isFile = st.type === "file";

        if (propsTitle) {
            propsTitle.textContent = isDir ? "Folder properties" : (isFile ? "File properties" : "Item properties");
        }
        if (propsPath) propsPath.textContent = st.path_norm || ("/" + rel);

        addPropsRow("Name", st.name || name);
        addPropsRow("Type", isDir ? "Folder" : (isFile ? "File" : "Other"));
        addPropsRow("Path", st.path_norm || ("/" + rel), { copy:true });
        addPropsRow("Workspace ID", st.workspace_id || workspaceId, { copy:true });

        if (st.mode_octal) {
            const rwx = permsFromOctal(st.mode_octal);
            addPropsRow("Permissions", rwx ? `${st.mode_octal} (${rwx})` : st.mode_octal);
        }

        if (st.mtime_epoch) addPropsRow("Modified", fmtUnixLocal(st.mtime_epoch));

        if (isFile) {
            if (st.bytes != null) addPropsRow("Size", fmtSize(st.bytes));
            if (st.mime) addPropsRow("MIME", st.mime);
            if (typeof st.is_text === "boolean") addPropsRow("Looks like text", st.is_text ? "Yes" : "No");

            const kEl = document.createElement("div");
            kEl.className = "k";
            kEl.textContent = "SHA-256";

            const vEl = document.createElement("div");
            vEl.className = "v";
            vEl.innerHTML = "";
            vEl.style.display = "flex";
            vEl.style.gap = "10px";
            vEl.style.alignItems = "center";
            vEl.style.flexWrap = "wrap";

            const line = document.createElement("div");
            line.className = "mono";
            line.style.wordBreak = "break-all";
            line.style.opacity = "0.92";
            line.textContent = "Computing…";

            const btnCopy = miniCopyButton(() => line.textContent);
            btnCopy.disabled = true;

            vEl.appendChild(line);
            vEl.appendChild(btnCopy);

            propsBody.appendChild(kEl);
            propsBody.appendChild(vEl);

            const cacheKey = hashCacheKey(rel, st.mtime_epoch, st.bytes);
            const cached = hashCache.get(cacheKey);

            if (cached && cached.sha256) {
                line.textContent = cached.sha256;
                btnCopy.disabled = false;
            } else {
                const expectedPath = propsPath ? propsPath.textContent : (st.path_norm || ("/" + rel));

                fetchSha256ForRelPath(rel)
                    .then((out) => {
                        hashCache.set(cacheKey, { sha256:out.sha256, raw:out.raw, atMs:Date.now() });

                        const nowPath = propsPath ? propsPath.textContent : "";
                        if (nowPath && nowPath !== expectedPath) return;

                        line.textContent = out.sha256;
                        btnCopy.disabled = false;
                    })
                    .catch((e) => {
                        line.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
                        line.style.opacity = "0.85";
                    });
            }
        }

        if (isDir) {
            if (st.children) {
                const parts = [];
                if (st.children.files != null) parts.push(`${st.children.files} files`);
                if (st.children.dirs != null) parts.push(`${st.children.dirs} folders`);
                if (st.children.other != null && st.children.other !== 0) parts.push(`${st.children.other} other`);
                addPropsRow("Children", parts.join(", "));
            }

            if (st.bytes_recursive != null) addPropsRow("Size (recursive)", fmtSize(st.bytes_recursive));
            if (st.recursive_scanned_entries != null) addPropsRow("Scanned entries", String(st.recursive_scanned_entries));
            if (typeof st.recursive_complete === "boolean") addPropsRow("Scan complete", st.recursive_complete ? "Yes" : "No");
            if (st.scan_cap != null) addPropsRow("Scan cap", String(st.scan_cap));
            if (st.time_cap_ms != null) addPropsRow("Time cap", `${st.time_cap_ms} ms`);
        }

        {
            const kEl = document.createElement("div");
            kEl.className = "k";
            kEl.textContent = "Details";

            const vEl = document.createElement("div");
            vEl.className = "v";
            const details = document.createElement("details");
            details.style.width = "100%";

            const summary = document.createElement("summary");
            summary.textContent = "Raw JSON";
            summary.style.cursor = "pointer";
            summary.style.userSelect = "none";

            const pre = document.createElement("pre");
            pre.className = "mono pre";
            pre.textContent = JSON.stringify(st, null, 2);

            details.appendChild(summary);
            details.appendChild(pre);
            vEl.appendChild(details);

            propsBody.appendChild(kEl);
            propsBody.appendChild(vEl);
        }
    }

    function renderBreadcrumbs() {
        const p = normalizeRelPath(currentPath);
        const parts = p ? p.split("/").filter(Boolean) : [];

        const html = [];
        html.push(`<button class="crumb" type="button" data-crumb="">Workspace root</button>`);

        let acc = "";
        for (const part of parts) {
            acc = acc ? `${acc}/${part}` : part;
            html.push(`<span class="crumbSep">/</span>`);
            html.push(`<button class="crumb" type="button" data-crumb="${escapeHtml(acc)}">${escapeHtml(part)}</button>`);
        }

        breadcrumbsEl.innerHTML = html.join("");
        btnUp.disabled = !p;
    }

    function showSignedInState() {
        if (shell) shell.classList.add("signedIn");

        if (accessSub) {
            accessSub.textContent = "You are signed in with DNA Connect. Use a new QR only when this session expires or you want to sign in again.";
        }
        qrBox.innerHTML = `
            <div class="hint" style="text-align:center; color:#444;">
                Workspace session is active.<br>
                Use “New sign-in QR” only when you want to sign in again.
            </div>
        `;
    }

    async function startSession() {
        if (!workspaceId) {
            setStatus("Missing workspace_id in URL.", "bad");
            qrBox.innerHTML = `<div class="hint">Missing workspace_id.</div>`;
            return;
        }

        clearInterval(pollTimer);
        currentSessionId = "";
        signedIn = false;
        canEdit = false;
        uploadOpen = false;
        syncUploadPanel();
        if (shell) shell.classList.remove("signedIn");

        if (accessSub) {
            accessSub.textContent = "Scan the QR code with DNA Connect to prove your identity and open this workspace.";
        }

        setStatus("Creating a fresh QR login session…");

        const j = await apiJson("/api/v4/workspaces/external-sessions/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ workspace_id: workspaceId })
        });

        currentSessionId = String(j.session && j.session.session_id || "");
        const qrPath = String(j.qr_svg || "");

        if (!currentSessionId || !qrPath) {
            throw new Error("Server did not return session QR.");
        }

        qrBox.innerHTML = `<img alt="DNA Connect QR" src="${escapeHtml(qrPath)}">`;
        setStatus("Scan the QR with DNA Connect. Waiting for approval…");

        pollTimer = setInterval(() => pollStatus().catch((e) => {
            setStatus(`Status check failed: ${e.message || e}`, "bad");
        }), 1800);
    }

    async function pollStatus() {
        if (!currentSessionId) return;

        const j = await apiJson(`/api/v4/workspaces/external-sessions/status?session_id=${encodeURIComponent(currentSessionId)}`);
        const s = j.session || {};
        const state = String(s.status || "");

        if (state === "approved") {
            clearInterval(pollTimer);
            pollTimer = null;
            setStatus("QR approved. Opening workspace…", "good");
            await consumeSession();
            await loadFiles();
            return;
        }

        if (state === "denied" || state === "expired") {
            clearInterval(pollTimer);
            pollTimer = null;
            setStatus(`Login ${state}: ${s.reason || "try a new QR"}`, "bad");
            return;
        }

        setStatus("Waiting for DNA Connect scan…");
    }

    async function consumeSession() {
        if (!currentSessionId) throw new Error("missing session id");

        await apiJson("/api/v4/workspaces/external-sessions/consume", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: currentSessionId })
        });

        showSignedInState();
        setStatus("Workspace session ready.", "good");
    }

    async function loadFiles(pathOverride) {
        resetMarqueeVisual();
        setTopReadyBadge("loading…", "loading");
        if (!workspaceId) return;

        if (typeof pathOverride === "string") {
            currentPath = normalizeRelPath(pathOverride);
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        if (currentPath) qs.set("path", currentPath);

        const j = await apiJson(`/api/v4/workspaces/files/list?${qs.toString()}`);
        applyAccessInfo(j);
        renderBreadcrumbs();
        applyExternalViewPrefs();

        const items = Array.isArray(j.items) ? j.items.slice() : [];
        const pathLabel = currentPath || "workspace root";
        const countLabel = `${items.length} item${items.length === 1 ? "" : "s"} in ${pathLabel}.`;
        if (fileSub && !canEdit) {
            fileSub.textContent = `View-only access. ${countLabel}`;
        } else if (fileSub && canEdit) {
            fileSub.textContent = `Editor access. ${countLabel}`;
        }

        items.sort(compareWorkspaceItems);

        const rows = [];

        if (!items.length) {
            filesEl.innerHTML = `<div class="empty">This folder is empty.</div>`;
            setTopReadyBadge("ready", "good");
            return;
        }

        for (const it of items) {
            const name = String(it.name || it.path || "item");
            const type = String(it.type || (it.is_dir ? "dir" : "file")).toLowerCase();
            const isDir = type === "dir" || type === "folder" || it.is_dir === true;
            const rel = childPath(currentPath, name);
            const mtime = fmtTime(it.mtime_unix);
            const size = isDir ? "Folder" : fmtSize(it.size_bytes || it.size || it.bytes || 0);
            const meta = mtime ? `${size} · ${mtime}` : size;

            if (isDir) {
                rows.push(`
                    <div class="fileRow clickable" data-dir="${escapeHtml(rel)}" data-name="${escapeHtml(name)}" data-type="dir" data-size="0" data-mtime="${escapeHtml(it.mtime_unix || "")}" title="${escapeHtml(name)}">
                        <div class="fileMain">
                            <div class="fileIcon">📁</div>
                            <div class="fileText">
                                <div class="fileName">${escapeHtml(name)}</div>
                                <div class="fileMeta">${escapeHtml(meta)}</div>
                            </div>
                        </div>
                    </div>
                `);
            } else {
                rows.push(`
                    <div class="fileRow clickable" data-file="${escapeHtml(rel)}" data-name="${escapeHtml(name)}" data-type="file" data-size="${escapeHtml(it.size_bytes || it.size || it.bytes || 0)}" data-mtime="${escapeHtml(it.mtime_unix || "")}" title="${escapeHtml(name)}">
                        <div class="fileMain">
                            <div class="fileIcon">📄</div>
                            <div class="fileText">
                                <div class="fileName">${escapeHtml(name)}</div>
                                <div class="fileMeta">${escapeHtml(meta)}</div>
                            </div>
                        </div>
                        <a class="downloadLink" href="${escapeHtml(downloadUrl(rel))}" download>Download</a>
                    </div>
                `);
            }
        }

        filesEl.innerHTML = rows.join("");
        setTopReadyBadge("ready", "good");
    }

    async function uploadSelectedFile() {
        const selected = Array.from((uploadFile && uploadFile.files) || []);
        const relFiles = selected.map((file) => ({
            rel: file.webkitRelativePath || file.name,
            file
        }));

        try {
            uploadOpen = false;
            /* direct upload: old inline panel update not needed */
            await uploadRelFiles(relFiles);
        } finally {
            if (uploadFile) uploadFile.value = "";
            uploadOpen = false;
            /* direct upload: old inline panel update not needed */
        }
    }

    function basenameFromPath(rel) {
        const v = normalizeRelPath(rel);
        if (!v) return "";
        const i = v.lastIndexOf("/");
        return i < 0 ? v : v.slice(i + 1);
    }

    function validateSimpleRelPathInput(pathText) {
        const v = normalizeRelPath(pathText);
        if (!v) return { ok:false, message:"Path cannot be empty." };
        if (v.includes("\\")) return { ok:false, message:"Use forward slashes, not backslashes." };

        const parts = v.split("/").filter(Boolean);
        for (const part of parts) {
            if (part === "." || part === "..") {
                return { ok:false, message:"Path cannot contain . or .. segments." };
            }
        }

        return { ok:true, path:v };
    }

    function resetFolderPickerPosition() {
        if (!extPickerCard) return;
        extPickerCard.style.left = "50%";
        extPickerCard.style.top = "22px";
        extPickerCard.style.transform = "translateX(-50%)";
    }

    function clampPickerPosition(left, top) {
        if (!extPickerCard) return { left, top };

        const rect = extPickerCard.getBoundingClientRect();
        const pad = 6;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        return {
            left: Math.min(Math.max(pad, left), maxLeft),
            top: Math.min(Math.max(pad, top), maxTop)
        };
    }

    function beginFolderPickerDrag(ev) {
        if (!extPickerCard || !extPickerHead) return;
        if (ev.button !== 0) return;
        if (ev.target.closest("button, input, textarea, select, a")) return;

        const rect = extPickerCard.getBoundingClientRect();
        pickerDrag = {
            pointerId: ev.pointerId,
            dx: ev.clientX - rect.left,
            dy: ev.clientY - rect.top
        };

        extPickerCard.classList.add("dragging");
        extPickerCard.style.left = `${rect.left}px`;
        extPickerCard.style.top = `${rect.top}px`;
        extPickerCard.style.transform = "none";

        try { extPickerHead.setPointerCapture(ev.pointerId); } catch (_) {}
        ev.preventDefault();
    }

    function moveFolderPickerDrag(ev) {
        if (!pickerDrag || !extPickerCard) return;
        if (ev.pointerId !== pickerDrag.pointerId) return;

        const pos = clampPickerPosition(
            ev.clientX - pickerDrag.dx,
            ev.clientY - pickerDrag.dy
        );

        extPickerCard.style.left = `${pos.left}px`;
        extPickerCard.style.top = `${pos.top}px`;
        extPickerCard.style.transform = "none";
    }

    function endFolderPickerDrag(ev) {
        if (!pickerDrag) return;
        if (ev.pointerId !== pickerDrag.pointerId) return;

        if (extPickerCard) extPickerCard.classList.remove("dragging");
        try { extPickerHead && extPickerHead.releasePointerCapture(ev.pointerId); } catch (_) {}
        pickerDrag = null;
    }

    function pickerDestLabel() {
        return `Destination: Workspace ${pickerPath ? "/" + pickerPath : "/"}`;
    }

    function renderPickerCrumbs() {
        if (!extPickerCrumbs) return;
        const parts = normalizeRelPath(pickerPath).split("/").filter(Boolean);
        const rows = [];
        rows.push(`<button class="extPickerCrumb" type="button" data-path="">/</button>`);
        let acc = "";
        for (const part of parts) {
            acc = acc ? `${acc}/${part}` : part;
            rows.push(`<button class="extPickerCrumb" type="button" data-path="${escapeHtml(acc)}">${escapeHtml(part)}</button>`);
        }
        extPickerCrumbs.innerHTML = rows.join("");
    }

    async function loadPickerFolder(path) {
        pickerPath = normalizeRelPath(path);
        if (extPickerStatus) extPickerStatus.textContent = "Loading folders...";
        renderPickerCrumbs();
        if (extPickerDest) extPickerDest.textContent = pickerDestLabel();

        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        if (pickerPath) qs.set("path", pickerPath);

        const j = await apiJson(`/api/v4/workspaces/files/list?${qs.toString()}`);
        const items = Array.isArray(j.items) ? j.items : [];
        const dirs = items
            .filter((it) => {
                const type = String(it.type || (it.is_dir ? "dir" : "file")).toLowerCase();
                return type === "dir" || type === "folder" || it.is_dir === true;
            })
            .map((it) => String(it.name || it.path || ""))
            .filter(Boolean)
            .sort((a, b) => a.localeCompare(b));

        const rows = [];

        if (pickerPath) {
            rows.push(`
                <button class="extPickerDirRow" type="button" data-path="${escapeHtml(parentPath(pickerPath))}">
                    <span class="extPickerDirName">..</span>
                    <span class="extPickerDirMeta">Parent</span>
                </button>
            `);
        }

        for (const name of dirs) {
            const rel = childPath(pickerPath, name);

            // Prevent picking inside selected folder when moving a folder.
            let disabled = false;
            if (pickerMode === "move" && pickerItem && pickerItem.isDir) {
                const src = normalizeRelPath(pickerItem.rel);
                disabled = rel === src || rel.startsWith(src + "/");
            }

            rows.push(`
                <button class="extPickerDirRow" type="button" data-path="${escapeHtml(rel)}" ${disabled ? "disabled" : ""}>
                    <span class="extPickerDirName">${escapeHtml(name)}</span>
                    <span class="extPickerDirMeta">Folder</span>
                </button>
            `);
        }

        if (!rows.length) {
            rows.push(`<div class="hint" style="padding:12px;">No folders here.</div>`);
        }

        extPickerList.innerHTML = rows.join("");
        if (extPickerStatus) extPickerStatus.textContent = "";
    }

    function openFolderPicker(opts) {
        return new Promise((resolve) => {
            pickerResolve = resolve;
            pickerMode = opts.mode || "move";
            pickerItem = opts.item || null;
            pickerPath = normalizeRelPath(opts.initialPath || currentPath || "");

            if (extPickerTitle) extPickerTitle.textContent = pickerMode === "copy" ? "Copy" : "Move";
            if (extPickerSub) extPickerSub.textContent = "Select destination folder";
            if (extPickerSource) {
                const rel = pickerItem && pickerItem.rel ? pickerItem.rel : "";
                extPickerSource.textContent = `${pickerMode === "copy" ? "Copy" : "Move"}: /${rel}`;
            }
            if (extPickerChoose) extPickerChoose.textContent = pickerMode === "copy" ? "Copy here" : "Move here";
            if (extPickerStatus) extPickerStatus.textContent = "";

            extPickerOverlay.classList.add("show");
            extPickerOverlay.setAttribute("aria-hidden", "false");
            resetFolderPickerPosition();

            loadPickerFolder(pickerPath).catch((e) => {
                if (extPickerStatus) extPickerStatus.textContent = `Folder list failed: ${e.message || e}`;
            });
        });
    }

    function closeFolderPicker(value) {
        if (extPickerOverlay) {
            extPickerOverlay.classList.remove("show");
            extPickerOverlay.setAttribute("aria-hidden", "true");
        }

        const resolve = pickerResolve;
        pickerResolve = null;
        if (resolve) resolve(value);
    }

    async function chooseFolderForItem(item, mode) {
        if (!item || !item.rel) return null;

        const picked = await openFolderPicker({
            mode,
            item,
            initialPath: parentPath(item.rel)
        });

        if (picked === null) return null;

        const name = basenameFromPath(item.rel);
        const destFolder = normalizeRelPath(picked || "");
        return destFolder ? `${destFolder}/${name}` : name;
    }

    async function trashItem(item) {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        if (!item || !item.rel) {
            setStatus("No item selected.", "bad");
            return;
        }

        const kind = item.isDir ? "folder" : "file";
        const label = item.rel || item.name || "selected item";
        const ok = confirm(
            `Move ${kind} to trash?\n\n/${label}\n\n` +
            `The owner can restore it from Trash until retention expires.`
        );

        if (!ok) {
            setStatus("Move to trash cancelled.");
            return;
        }

        setStatus(`Moving ${item.name || label} to trash…`);

        await apiJson(deleteUrl(item.rel), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: ""
        });

        setStatus(`Moved ${item.name || label} to trash.`, "good");
        hideContextMenus();
        await loadFiles(currentPath);
    }

    async function copyItem(item) {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        if (!item || !item.rel) {
            setStatus("No item selected.", "bad");
            return;
        }

        const oldPath = normalizeRelPath(item.rel);
        const oldName = basenameFromPath(oldPath);

        const targetPath = await chooseFolderForItem(item, "copy");
        if (targetPath === null) {
            setStatus("Copy cancelled.");
            return;
        }

        if (targetPath === oldPath) {
            setStatus("Choose a different destination folder.", "bad");
            return;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("from", oldPath);
        qs.set("to", targetPath);

        setStatus(`Copying ${oldName}…`);

        await apiJson(`/api/v4/workspaces/files/copy?${qs.toString()}`, {
            method: "POST"
        });

        setStatus(`Copied ${oldName}.`, "good");
        await loadFiles(currentPath);
    }

    async function moveItem(item) {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        if (!item || !item.rel) {
            setStatus("No item selected.", "bad");
            return;
        }

        const oldPath = normalizeRelPath(item.rel);
        const oldName = basenameFromPath(oldPath);

        const targetPath = await chooseFolderForItem(item, "move");
        if (targetPath === null) {
            setStatus("Move cancelled.");
            return;
        }

        if (targetPath === oldPath) {
            setStatus("Choose a different destination folder.", "bad");
            return;
        }

        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("from", oldPath);
        qs.set("to", targetPath);

        setStatus(`Moving ${oldName}…`);

        await apiJson(`/api/v4/workspaces/files/move?${qs.toString()}`, {
            method: "POST"
        });

        setStatus(`Moved ${oldName}.`, "good");
        await loadFiles(currentPath);
    }

    async function renameItem(item) {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        if (!item || !item.rel) {
            setStatus("No item selected.", "bad");
            return;
        }

        const oldName = basenameFromPath(item.rel);
        const nextName = prompt("Rename item", oldName);
        if (nextName == null) return;

        const cleanName = String(nextName || "").trim();
        if (!cleanName) {
            setStatus("Name cannot be empty.", "bad");
            return;
        }

        if (cleanName === "." || cleanName === ".." || cleanName.includes("/") || cleanName.includes("\\")) {
            setStatus("Use a simple name without slashes.", "bad");
            return;
        }

        if (cleanName === oldName) {
            setStatus("Name did not change.");
            return;
        }

        const parent = parentPath(item.rel);
        const targetPath = childPath(parent, cleanName);

        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("from", item.rel);
        qs.set("to", targetPath);

        setStatus(`Renaming ${oldName}…`);

        await apiJson(`/api/v4/workspaces/files/move?${qs.toString()}`, {
            method: "POST"
        });

        setStatus(`Renamed ${oldName} to ${cleanName}.`, "good");
        await loadFiles(currentPath);
    }

    async function createFolder() {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        const raw = String(newFolderName.value || "").trim();
        if (!raw) {
            setStatus("Enter a folder name.", "bad");
            newFolderName.focus();
            return;
        }

        if (raw === "." || raw === ".." || raw.includes("/") || raw.includes("\\")) {
            setStatus("Use a simple folder name without slashes.", "bad");
            newFolderName.focus();
            return;
        }

        const targetPath = childPath(currentPath, raw);
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", targetPath);

        setStatus(`Creating folder ${raw}…`);

        await apiJson(`/api/v4/workspaces/files/mkdir?${qs.toString()}`, {
            method: "POST"
        });

        newFolderName.value = "";
        setStatus(`Created folder ${raw}.`, "good");
        await loadFiles(currentPath);
    }

    // ---- Selection model -----------------------------------------------------
    const selectedKeys = new Set();
    let selectionAnchorKey = "";
    let keyboardFocusKey = "";
    let selectionScopePath = "";
    let marqueeState = null;

    if (filesEl) {
        filesEl.tabIndex = 0;
        filesEl.setAttribute("role", "listbox");
        filesEl.setAttribute("aria-multiselectable", "true");
    }

    function selectableRows() {
        if (!filesEl) return [];
        return Array.from(filesEl.querySelectorAll(".fileRow"))
            .filter((row) => row && (row.dataset.file || row.dataset.dir) && row.dataset.name);
    }

    function isSelectionTypingTarget(el) {
        if (!el) return false;
        const tag = String(el.tagName || "").toLowerCase();
        return tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable;
    }

    function isInteractiveSelectionTarget(el) {
        if (!el || !el.closest) return false;
        return !!el.closest(
            "button,a,input,label,select,textarea," +
            ".fileRow,.contextMenu,.extPickerOverlay,.modal,.qrBox,.uploadBox"
        );
    }

    function rowKey(row) {
        if (!row) return "";
        if (row.dataset.dir) return "dir:" + normalizeRelPath(row.dataset.dir);
        if (row.dataset.file) return "file:" + normalizeRelPath(row.dataset.file);
        return "";
    }

    function rowByKey(key) {
        return selectableRows().find((row) => rowKey(row) === key) || null;
    }

    function itemFromKey(key) {
        const row = rowByKey(key);
        return row ? itemFromRow(row) : null;
    }

    function selectedItems() {
        const rows = selectableRows();
        const out = [];
        for (const row of rows) {
            const key = rowKey(row);
            if (!selectedKeys.has(key)) continue;
            const item = itemFromRow(row);
            if (item && item.rel) out.push(item);
        }
        return out;
    }

    function setKeyboardFocus(key) {
        keyboardFocusKey = key || "";
        for (const row of selectableRows()) {
            row.classList.toggle("keyboardFocus", rowKey(row) === keyboardFocusKey);
        }
    }

    function clearSelection() {
        selectedKeys.clear();
        selectionAnchorKey = "";
        keyboardFocusKey = "";
        syncSelectionUi();
    }

    function syncSelectionUi() {
        if (selectionScopePath !== currentPath) {
            selectedKeys.clear();
            selectionAnchorKey = "";
            keyboardFocusKey = "";
            selectionScopePath = currentPath;
        }

        const visible = new Set();
        for (const row of selectableRows()) visible.add(rowKey(row));

        for (const key of Array.from(selectedKeys)) {
            if (!visible.has(key)) selectedKeys.delete(key);
        }

        if (keyboardFocusKey && !visible.has(keyboardFocusKey)) keyboardFocusKey = "";
        if (selectionAnchorKey && !visible.has(selectionAnchorKey)) selectionAnchorKey = "";

        for (const row of selectableRows()) {
            const key = rowKey(row);
            const on = selectedKeys.has(key);
            row.classList.toggle("selected", on);
            row.classList.toggle("keyboardFocus", key === keyboardFocusKey);
            row.setAttribute("aria-selected", on ? "true" : "false");
        }

        if (selectedKeys.size > 0) {
            setStatus(`${selectedKeys.size} item${selectedKeys.size === 1 ? "" : "s"} selected.`);
        }
    }

    function selectOnlyKey(key) {
        if (!key) return;
        selectionScopePath = currentPath;
        selectedKeys.clear();
        selectedKeys.add(key);
        selectionAnchorKey = key;
        setKeyboardFocus(key);
        syncSelectionUi();
    }

    function toggleKey(key) {
        if (!key) return;
        selectionScopePath = currentPath;
        if (selectedKeys.has(key)) selectedKeys.delete(key);
        else selectedKeys.add(key);
        selectionAnchorKey = key;
        setKeyboardFocus(key);
        syncSelectionUi();
    }

    function selectRangeToKey(key, additive) {
        const rows = selectableRows();
        const keys = rows.map(rowKey).filter(Boolean);
        if (!key || !keys.includes(key)) return;

        const anchor = selectionAnchorKey && keys.includes(selectionAnchorKey)
            ? selectionAnchorKey
            : key;

        const a = keys.indexOf(anchor);
        const b = keys.indexOf(key);
        const lo = Math.min(a, b);
        const hi = Math.max(a, b);

        if (!additive) selectedKeys.clear();
        for (let i = lo; i <= hi; i++) selectedKeys.add(keys[i]);

        setKeyboardFocus(key);
        syncSelectionUi();
    }

    function openItem(item) {
        if (!item) return;
        if (item.isDir) {
            clearSelection();
            loadFiles(item.rel).catch((e) => setStatus(`Open folder failed: ${e.message || e}`, "bad"));
            return;
        }
        // Open text files in editor/preview instead of immediate download.
        if (isTextPreviewableName(item.name || item.rel || "")) {
            if (canEdit) {
                openTextEditor(item).catch((e) => setStatus(`Text editor failed: ${e.message || e}`, "bad"));
            } else {
                openTextPreview(item).catch((e) => setStatus(`Preview failed: ${e.message || e}`, "bad"));
            }
            return;
        }

        location.href = downloadUrl(item.rel);
    }

    function openSelectedPrimary() {
        const items = selectedItems();
        if (items.length !== 1) {
            setStatus(items.length ? "Use the context menu for multiple selected items." : "No item selected.");
            return;
        }
        openItem(items[0]);
    }

    function handleSelectionKeyboard(ev) {
        if (!signedIn) return false;
        if (isSelectionTypingTarget(ev.target)) return false;

        const rows = selectableRows();
        if (!rows.length) return false;

        const keys = rows.map(rowKey).filter(Boolean);
        let idx = keyboardFocusKey ? keys.indexOf(keyboardFocusKey) : -1;
        if (idx < 0 && selectedKeys.size) idx = keys.indexOf(Array.from(selectedKeys).at(-1));
        if (idx < 0) idx = 0;

        let next = idx;
        const pageStep = Math.max(1, Math.min(12, Math.floor(rows.length / 3)));

        if (ev.key === "ArrowDown" || ev.key === "ArrowRight") {
            next = Math.min(keys.length - 1, idx + 1);
        } else if (ev.key === "ArrowUp" || ev.key === "ArrowLeft") {
            next = Math.max(0, idx - 1);
        } else if (ev.key === "PageDown") {
            next = Math.min(keys.length - 1, idx + pageStep);
        } else if (ev.key === "PageUp") {
            next = Math.max(0, idx - pageStep);
        } else if (ev.key === "Home") {
            next = 0;
        } else if (ev.key === "End") {
            next = keys.length - 1;
        } else if (ev.key === "Enter") {
            ev.preventDefault();
            ev.stopPropagation();
            openSelectedPrimary();
            return true;
        } else if (ev.key === "Escape") {
            ev.preventDefault();
            ev.stopPropagation();
            clearSelection();
            hideContextMenus();
            setStatus("Selection cleared.");
            return true;
        } else {
            return false;
        }

        ev.preventDefault();
        ev.stopPropagation();

        const nextKey = keys[next];
        if (ev.shiftKey) selectRangeToKey(nextKey, false);
        else selectOnlyKey(nextKey);

        const row = rowByKey(nextKey);
        if (row) row.scrollIntoView({ block: "nearest" });
        return true;
    }

    async function trashSelectedItems() {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }

        const items = selectedItems();
        if (!items.length) {
            setStatus("No items selected.", "bad");
            return;
        }

        const ok = confirm(
            `Move ${items.length} selected item${items.length === 1 ? "" : "s"} to trash?\n\n` +
            `The owner can restore them from Trash until retention expires.`
        );
        if (!ok) {
            setStatus("Move to trash cancelled.");
            return;
        }

        let done = 0;
        let failed = 0;
        const errors = [];

        for (const item of items) {
            try {
                await apiJson(deleteUrl(item.rel), {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: ""
                });
                done++;
            } catch (e) {
                failed++;
                errors.push(`${item.rel}: ${e.message || e}`);
            }
            setStatus(`Moving to trash ${done + failed}/${items.length}…`);
        }

        clearSelection();
        hideContextMenus();
        await loadFiles(currentPath);

        if (failed) {
            setStatus(`Moved ${done}, failed ${failed}. ${errors.slice(0, 2).join(" | ")}`, "bad");
        } else {
            setStatus(`Moved ${done} item${done === 1 ? "" : "s"} to trash.`, "good");
        }
    }

    function showSelectionContextMenu(x, y) {
        if (!selectionContextMenu) return;

        const count = selectedKeys.size;
        const openBtn = selectionContextMenu.querySelector('[data-action="multi-open"]');
        const editorOnly = selectionContextMenu.querySelectorAll('[data-action="multi-copy"], [data-action="multi-move"], [data-action="multi-trash"]');

        if (openBtn) openBtn.disabled = count !== 1;
        editorOnly.forEach((btn) => { btn.disabled = !canEdit; });

        placeContextMenu(selectionContextMenu, x, y);
    }

    filesEl.addEventListener("click", (ev) => {
        const row = ev.target.closest(".fileRow");
        if (!row || !filesEl.contains(row)) return;
        if (ev.target.closest("a,button,input,label,select,textarea")) return;

        const key = rowKey(row);
        if (!key) return;

        ev.preventDefault();
        ev.stopImmediatePropagation();

        if (ev.shiftKey) {
            selectRangeToKey(key, ev.ctrlKey || ev.metaKey);
        } else if (ev.ctrlKey || ev.metaKey) {
            toggleKey(key);
        } else {
            selectOnlyKey(key);
        }

        filesEl.focus({ preventScroll: true });
    }, true);

    filesEl.addEventListener("dblclick", (ev) => {
        const row = ev.target.closest(".fileRow");
        if (!row || !filesEl.contains(row)) return;
        if (ev.target.closest("a,button,input,label,select,textarea")) return;

        const item = itemFromRow(row);
        if (!item) return;

        ev.preventDefault();
        ev.stopImmediatePropagation();

        openItem(item);
    }, true);

    filesEl.addEventListener("keydown", (ev) => {
        handleSelectionKeyboard(ev);
    });

    filesEl.addEventListener("contextmenu", (ev) => {
        const row = ev.target.closest(".fileRow");

        if (row && filesEl.contains(row)) {
            const key = rowKey(row);
            if (!key) return;

            ev.preventDefault();
            ev.stopImmediatePropagation();

            if (!selectedKeys.has(key)) {
                selectOnlyKey(key);
            } else {
                setKeyboardFocus(key);
                syncSelectionUi();
            }

            if (selectedKeys.size > 1) {
                showSelectionContextMenu(ev.clientX, ev.clientY);
                return;
            }

            contextItem = itemFromRow(row);
            if (!contextItem) return;

            const openBtn = itemContextMenu.querySelector('[data-action="open"]');
            const downloadBtn = itemContextMenu.querySelector('[data-action="download"]');
            const previewBtn = itemContextMenu.querySelector('[data-action="preview"]');
            const editorOnly = itemContextMenu.querySelectorAll('[data-action="copy"], [data-action="move"], [data-action="rename"], [data-action="trash-item"]');
            if (contextItem.isDir) {
                if (openBtn) openBtn.textContent = "Open folder";
                if (downloadBtn) downloadBtn.innerHTML = 'Download folder <span class="contextHint">zip soon</span>';
                if (previewBtn) {
                    previewBtn.innerHTML = "Open / edit text?";
                    previewBtn.disabled = true;
                }
            } else {
                const canTextPreview = isTextPreviewableName(contextItem.name || contextItem.rel || "");
                if (openBtn) openBtn.textContent = "Open original";
                if (downloadBtn) downloadBtn.textContent = "Download";
                if (previewBtn) {
                    previewBtn.innerHTML = canTextPreview
                        ? "Open / edit text?"
                        : "Open / edit text?";
                    previewBtn.disabled = !canTextPreview;
                }
            }

            editorOnly.forEach((btn) => { btn.disabled = !canEdit; });
            configureExternalItemContextMenu(contextItem);
            placeContextMenu(itemContextMenu, ev.clientX, ev.clientY);
            return;
        }

        // Let the existing empty-area context menu handler run.
    }, true);

    // Marquee selection is handled by the viewport-wide pointerdown handler below.
    // Keep only one marquee implementation so focus/selection state cannot fight itself.


    function handleSelectionKeyboardViewportFix(ev) {
        if (!signedIn) return false;
        const target = ev.target;
        if (target) {
            const tag = String(target.tagName || "").toLowerCase();
            if (tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable) {
                return false;
            }
        }

        const rows = selectableRows();
        if (!rows.length) return false;

        const visualRows = rows.slice().sort((a, b) => {
            const ra = a.getBoundingClientRect();
            const rb = b.getBoundingClientRect();
            const dy = ra.top - rb.top;
            if (Math.abs(dy) > 8) return dy;
            return ra.left - rb.left;
        });

        const keys = visualRows.map(rowKey).filter(Boolean);
        if (!keys.length) return false;

        let idx = keyboardFocusKey ? keys.indexOf(keyboardFocusKey) : -1;
        if (idx < 0 && selectedKeys.size) idx = keys.indexOf(Array.from(selectedKeys).at(-1));
        if (idx < 0) idx = 0;

        const firstTop = visualRows[0].getBoundingClientRect().top;
        let cols = 0;
        for (const row of visualRows) {
            const r = row.getBoundingClientRect();
            if (Math.abs(r.top - firstTop) <= 12) cols++;
        }
        cols = Math.max(1, cols || 1);

        let next = idx;
        if (ev.key === "ArrowRight") {
            next = Math.min(keys.length - 1, idx + 1);
        } else if (ev.key === "ArrowLeft") {
            next = Math.max(0, idx - 1);
        } else if (ev.key === "ArrowDown") {
            next = Math.min(keys.length - 1, idx + cols);
        } else if (ev.key === "ArrowUp") {
            next = Math.max(0, idx - cols);
        } else if (ev.key === "PageDown") {
            next = Math.min(keys.length - 1, idx + cols * 3);
        } else if (ev.key === "PageUp") {
            next = Math.max(0, idx - cols * 3);
        } else if (ev.key === "Home") {
            next = 0;
        } else if (ev.key === "End") {
            next = keys.length - 1;
        } else if (ev.key === "Enter") {
            ev.preventDefault();
            ev.stopPropagation();
            openSelectedPrimary();
            return true;
        } else if (ev.key === "Escape") {
            ev.preventDefault();
            ev.stopPropagation();
            clearSelection();
            hideContextMenus();
            setStatus("Selection cleared.");
            return true;
        } else {
            return false;
        }

        ev.preventDefault();
        ev.stopPropagation();

        const nextKey = keys[next];
        if (ev.shiftKey) selectRangeToKey(nextKey, false);
        else selectOnlyKey(nextKey);

        const row = rowByKey(nextKey);
        if (row) row.scrollIntoView({ block: "nearest", inline: "nearest" });
        return true;
    }

    window.addEventListener("keydown", (ev) => {
        handleSelectionKeyboardViewportFix(ev);
    }, true);



    function pointInsideElement(ev, el) {
        if (!ev || !el || typeof el.getBoundingClientRect !== "function") return false;
        const r = el.getBoundingClientRect();
        return ev.clientX >= r.left &&
            ev.clientX <= r.right &&
            ev.clientY >= r.top &&
            ev.clientY <= r.bottom;
    }

    function isPointerInsideOpenFloatingUi(ev) {
        if (textEditModal &&
            textEditModal.classList.contains("show") &&
            pointInsideElement(ev, textEditCard)) {
            return true;
        }

        if (textPreviewModal &&
            textPreviewModal.classList.contains("show") &&
            pointInsideElement(ev, textPreviewModal)) {
            return true;
        }

        if (propsModal &&
            propsModal.classList.contains("show") &&
            pointInsideElement(ev, propsModal)) {
            return true;
        }

        if (extPickerOverlay &&
            extPickerOverlay.classList.contains("show") &&
            pointInsideElement(ev, extPickerCard)) {
            return true;
        }

        return false;
    }

    function isViewportMarqueeBlockedTarget(el) {
        if (!el) return false;

        const tag = String(el.tagName || "").toLowerCase();
        if (tag === "button" || tag === "a" || tag === "input" || tag === "label" ||
            tag === "select" || tag === "textarea" || el.isContentEditable) {
            return true;
        }

        if (!el.closest) return false;

        return !!el.closest(
            ".fileRow,.contextMenu,.extPickerOverlay,.extPickerCard,.modal," +
            "#textEditModal,.textEditModal,#textEditCard,.textEditCard,#textEditHead,.textEditHead," +
            "#textPreviewModal,.textPreviewModal,#propsModal,.propsModal,.propsCard," +
            ".qrBox,.uploadBox,.toolbarGroup,.toolbar,.pathBar,.crumbs," +
            ".accessPanel,.rolePill,.accessPill"
        );
    }

    window.addEventListener("pointerdown", (ev) => {
        if (!signedIn) return;
        if (ev.button !== 0) return;

        // Text editor is detached/floating. While it is open, the global
        // marquee must not start at all, otherwise it steals the drag.
        if (document.body.classList.contains("externalTextEditorOpen")) return;
        if (isPointerInsideOpenFloatingUi(ev)) return;
        if (isViewportMarqueeBlockedTarget(ev.target)) return;

        ev.preventDefault();
        ev.stopPropagation();

        hideContextMenus();
        if (filesEl) filesEl.focus({ preventScroll: true });

        const box = document.createElement("div");
        box.className = "selectionBox";
        document.body.appendChild(box);

        marqueeState = {
            startX: ev.clientX,
            startY: ev.clientY,
            lastX: ev.clientX,
            lastY: ev.clientY,
            box,
            additive: ev.ctrlKey || ev.metaKey,
            base: new Set(selectedKeys)
        };

        let moved = false;

        const updateBox = () => {
            if (!marqueeState) return;

            const x1 = Math.min(marqueeState.startX, marqueeState.lastX);
            const y1 = Math.min(marqueeState.startY, marqueeState.lastY);
            const x2 = Math.max(marqueeState.startX, marqueeState.lastX);
            const y2 = Math.max(marqueeState.startY, marqueeState.lastY);

            if (Math.abs(x2 - x1) > 4 || Math.abs(y2 - y1) > 4) moved = true;

            box.style.left = `${x1}px`;
            box.style.top = `${y1}px`;
            box.style.width = `${Math.max(1, x2 - x1)}px`;
            box.style.height = `${Math.max(1, y2 - y1)}px`;

            const selRect = { left:x1, top:y1, right:x2, bottom:y2 };

            selectedKeys.clear();
            if (marqueeState.additive) {
                for (const k of marqueeState.base) selectedKeys.add(k);
            }

            for (const row of selectableRows()) {
                const r = row.getBoundingClientRect();
                const hit = !(
                    r.right < selRect.left ||
                    r.left > selRect.right ||
                    r.bottom < selRect.top ||
                    r.top > selRect.bottom
                );

                if (!hit) continue;

                const key = rowKey(row);
                if (!key) continue;

                selectedKeys.add(key);
                selectionAnchorKey = key;
                keyboardFocusKey = key;
            }

            syncSelectionUi();
        };

        const onMove = (moveEv) => {
            if (!marqueeState) return;
            marqueeState.lastX = moveEv.clientX;
            marqueeState.lastY = moveEv.clientY;
            updateBox();
        };

        const onUp = () => {
            if (marqueeState && marqueeState.box) marqueeState.box.remove();

            if (!moved && !(ev.ctrlKey || ev.metaKey)) {
                clearSelection();
            }

            marqueeState = null;
            window.removeEventListener("pointermove", onMove, true);
            window.removeEventListener("pointerup", onUp, true);
            syncSelectionUi();
        };

        window.addEventListener("pointermove", onMove, true);
        window.addEventListener("pointerup", onUp, true);

        updateBox();
    }, true);


    const selectionObserver = new MutationObserver(() => syncSelectionUi());
    selectionObserver.observe(filesEl, { childList: true, subtree: false });

    selectionContextMenu?.addEventListener("click", (ev) => {
        const btn = ev.target.closest("button[data-action]");
        if (!btn || btn.disabled) return;

        const action = btn.dataset.action || "";
        hideContextMenus();

        if (action === "multi-clear") {
            clearSelection();
            setStatus("Selection cleared.");
            return;
        }

        if (action === "multi-open") {
            openSelectedPrimary();
            return;
        }

        if (action === "multi-trash") {
            trashSelectedItems().catch((e) => setStatus(`Move to trash failed: ${e.message || e}`, "bad"));
            return;
        }

        if (action === "multi-download") return showPlaceholder("Download selection");
        if (action === "multi-copy") return showPlaceholder("Copy selected");
        if (action === "multi-move") return showPlaceholder("Move selected");
    });

    filesEl.addEventListener("click", (ev) => {
        if (ev.target.closest("a")) return;

        const rowDir = ev.target.closest(".fileRow[data-dir]");
        if (rowDir) {
            loadFiles(rowDir.dataset.dir || "").catch((e) => setStatus(`Open folder failed: ${e.message || e}`, "bad"));
            return;
        }

        const rowFile = ev.target.closest(".fileRow[data-file]");
        if (rowFile) {
            location.href = downloadUrl(rowFile.dataset.file || "");
        }
    });

    fileSurface.addEventListener("contextmenu", (ev) => {
        if (ev.target.closest(".contextMenu")) return;

        // Keep normal browser context menu for text/file inputs so paste/select still works.
        if (ev.target.closest("input, textarea, select")) return;

        ev.preventDefault();

        const row = ev.target.closest(".fileRow");
        hideContextMenus();

        if (row) {
            contextItem = itemFromRow(row);

            const openBtn = itemContextMenu.querySelector('[data-action="open"]');
            const downloadBtn = itemContextMenu.querySelector('[data-action="download"]');
            const previewBtn = itemContextMenu.querySelector('[data-action="preview"]');
            const editorOnly = itemContextMenu.querySelectorAll('[data-action="copy"], [data-action="move"], [data-action="rename"], [data-action="trash-item"]');
            if (contextItem && contextItem.isDir) {
                openBtn.textContent = "Open folder";
                downloadBtn.textContent = "Download folder (zip)";
                previewBtn.innerHTML = "Open / edit text?";
                previewBtn.disabled = true;
                downloadBtn.disabled = true;
            } else {
                const canTextPreview = isTextPreviewableName(contextItem && (contextItem.name || contextItem.rel) || "");
                openBtn.textContent = "Open original";
                downloadBtn.textContent = "Download";
                previewBtn.innerHTML = canTextPreview
                    ? "Open / edit text?"
                    : "Open / edit text?";
                previewBtn.disabled = !canTextPreview;
                downloadBtn.disabled = false;
            }

            editorOnly.forEach((btn) => { btn.disabled = !canEdit; });
            configureExternalItemContextMenu(contextItem);
            placeContextMenu(itemContextMenu, ev.clientX, ev.clientY);
            return;
        }

        const editorOnly = emptyContextMenu.querySelectorAll('[data-action="upload"], [data-action="upload-folder"], [data-action="new-folder"]');
        editorOnly.forEach((btn) => { btn.disabled = !canEdit; });
        placeContextMenu(emptyContextMenu, ev.clientX, ev.clientY);
    });

    breadcrumbsEl.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-crumb]");
        if (!btn) return;
        loadFiles(btn.dataset.crumb || "").catch((e) => setStatus(`Open path failed: ${e.message || e}`, "bad"));
    });

    emptyContextMenu.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-action]");
        if (!btn || btn.disabled) return;

        const action = btn.dataset.action;
        hideContextMenus();

        if (action === "upload") {
            if (!canEdit) return setStatus("This workspace session is view-only.", "bad");
            uploadOpen = true;
            syncUploadPanel();
            launchExternalUploadPicker(false);
            return;
        }

        if (action === "new-folder") {
            if (!canEdit) return setStatus("This workspace session is view-only.", "bad");
            newFolderName && newFolderName.focus();
            return;
        }

        if (action === "refresh") {
            refreshCurrent();
            return;
        }

        if (action === "upload-folder") {
            uploadOpen = false;
            /* direct upload: old inline panel update not needed */
            launchExternalUploadPicker(true);
            return;
        }
        if (action === "zip-folder") return showPlaceholder("Download current folder as zip");
        if (action === "trash") return showPlaceholder("Trash");
    });

    itemContextMenu.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-action]");
        if (!btn || btn.disabled || !contextItem) return;

        const action = btn.dataset.action;
        const item = contextItem;
        hideContextMenus();

        if (action === "open") {
            if (item.isDir) {
                loadFiles(item.rel).catch((e) => setStatus(`Open folder failed: ${e.message || e}`, "bad"));
            } else {
                window.open(downloadUrl(item.rel), "_blank", "noopener");
            }
            return;
        }

        if (action === "download") {
            if (item.isDir) return showPlaceholder("Download folder as zip");
            location.href = downloadUrl(item.rel);
            return;
        }

        if (action === "properties") {
            showProperties(item).catch((e) => setStatus(`Properties failed: ${e.message || e}`, "bad"));
            return;
        }

        if (action === "preview") {
            if (!isTextFileItem(item)) {
                return showPlaceholder("Preview");
            }

            if (canEdit) {
                openTextEditor(item).catch((e) => setStatus(`Text editor failed: ${e.message || e}`, "bad"));
            } else {
                openTextPreview(item).catch((e) => setStatus(`Preview failed: ${e.message || e}`, "bad"));
            }
            return;
        }

        if (action === "versions") return showPlaceholder("Versions");
        if (action === "share") return showPlaceholder("Create share link");
        if (action === "copy") {
            copyItem(item).catch((e) => setStatus(`Copy failed: ${e.message || e}`, "bad"));
            return;
        }
        if (action === "move") {
            moveItem(item).catch((e) => setStatus(`Move failed: ${e.message || e}`, "bad"));
            return;
        }
        if (action === "rename") {
            renameItem(item).catch((e) => setStatus(`Rename failed: ${e.message || e}`, "bad"));
            return;
        }
        if (action === "trash-item") {
            trashItem(item).catch((e) => setStatus(`Move to trash failed: ${e.message || e}`, "bad"));
            return;
        }
    });

    document.addEventListener("click", (ev) => {
        if (ev.target.closest(".contextMenu")) return;
        hideContextMenus();
    });

    document.addEventListener("keydown", (ev) => {
        if (ev.key !== "Escape") return;
        if (textEditModal && textEditModal.classList.contains("show")) {
            closeTextEditor();
            return;
        }
        if (propsModal && propsModal.classList.contains("show")) {
            closePropsModal();
            return;
        }
        if (textPreviewModal && textPreviewModal.classList.contains("show")) {
            closeTextPreviewModal();
            return;
        }
        if (extPickerOverlay && extPickerOverlay.classList.contains("show")) {
            closeFolderPicker(null);
            return;
        }
        hideContextMenus();
    });

    window.addEventListener("resize", hideContextMenus);
    window.addEventListener("scroll", hideContextMenus, true);

    propsClose.addEventListener("click", closePropsModal);
    propsModal.addEventListener("click", (ev) => {
        if (ev.target === propsModal) closePropsModal();
    });

    textPreviewClose.addEventListener("click", closeTextPreviewModal);
    textPreviewModal.addEventListener("click", (ev) => {
        if (ev.target === textPreviewModal) closeTextPreviewModal();
    });

    extPickerHead.addEventListener("pointerdown", beginFolderPickerDrag);
    extPickerHead.addEventListener("pointermove", moveFolderPickerDrag);
    extPickerHead.addEventListener("pointerup", endFolderPickerDrag);
    extPickerHead.addEventListener("pointercancel", endFolderPickerDrag);

    window.addEventListener("resize", () => {
        if (!extPickerOverlay || !extPickerOverlay.classList.contains("show") || !extPickerCard) return;
        const rect = extPickerCard.getBoundingClientRect();
        const pos = clampPickerPosition(rect.left, rect.top);
        extPickerCard.style.left = `${pos.left}px`;
        extPickerCard.style.top = `${pos.top}px`;
        extPickerCard.style.transform = "none";
    });

    extPickerList.addEventListener("click", (ev) => {
        const row = ev.target.closest("[data-path]");
        if (!row || row.disabled) return;
        loadPickerFolder(row.dataset.path || "").catch((e) => {
            if (extPickerStatus) extPickerStatus.textContent = `Open folder failed: ${e.message || e}`;
        });
    });

    extPickerCrumbs.addEventListener("click", (ev) => {
        const crumb = ev.target.closest("[data-path]");
        if (!crumb) return;
        loadPickerFolder(crumb.dataset.path || "").catch((e) => {
            if (extPickerStatus) extPickerStatus.textContent = `Open folder failed: ${e.message || e}`;
        });
    });

    extPickerChoose.addEventListener("click", () => {
        closeFolderPicker(pickerPath);
    });

    extPickerCancel.addEventListener("click", () => closeFolderPicker(null));
    extPickerClose.addEventListener("click", () => closeFolderPicker(null));

    extPickerNewFolder.addEventListener("click", async () => {
        if (!canEdit) {
            if (extPickerStatus) extPickerStatus.textContent = "This workspace session is view-only.";
            return;
        }

        const name = prompt("New folder name");
        if (name == null) return;

        const clean = String(name || "").trim();
        if (!clean || clean === "." || clean === ".." || clean.includes("/") || clean.includes("\\")) {
            if (extPickerStatus) extPickerStatus.textContent = "Use a simple folder name without slashes.";
            return;
        }

        const target = childPath(pickerPath, clean);
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", target);

        try {
            if (extPickerStatus) extPickerStatus.textContent = "Creating folder...";
            await apiJson(`/api/v4/workspaces/files/mkdir?${qs.toString()}`, { method:"POST" });
            await loadPickerFolder(target);
        } catch (e) {
            if (extPickerStatus) extPickerStatus.textContent = `Create folder failed: ${e.message || e}`;
        }
    });


    if (textEditArea) {
        textEditArea.addEventListener("input", () => {
            syncTextEditDirty();
            updateTextEditorFind();
        });

        textEditArea.addEventListener("keydown", (ev) => {
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s") {
                ev.preventDefault();
                saveTextEditor().catch((e) => setTextEditStatus(`Save failed: ${e.message || e}`, "bad"));
                return;
            }

            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "f") {
                ev.preventDefault();
                showTextEditorFind();
                return;
            }

            if (ev.key === "Tab") {
                ev.preventDefault();
                const start = textEditArea.selectionStart || 0;
                const end = textEditArea.selectionEnd || 0;
                const value = textEditArea.value || "";
                textEditArea.value = value.slice(0, start) + "    " + value.slice(end);
                textEditArea.setSelectionRange(start + 4, start + 4);
                syncTextEditDirty();
            }
        });
    }

    if (textEditClose) textEditClose.addEventListener("click", () => closeTextEditor());
    if (textEditReloadBtn) textEditReloadBtn.addEventListener("click", () => {
        reloadTextEditor().catch((e) => setTextEditStatus(`Reload failed: ${e.message || e}`, "bad"));
    });
    if (textEditSaveBtn) textEditSaveBtn.addEventListener("click", () => {
        saveTextEditor().catch((e) => setTextEditStatus(`Save failed: ${e.message || e}`, "bad"));
    });

    if (textEditFindToggleBtn) textEditFindToggleBtn.addEventListener("click", showTextEditorFind);
    if (textEditFindCloseBtn) textEditFindCloseBtn.addEventListener("click", hideTextEditorFind);
    if (textEditFindInput) {
        textEditFindInput.addEventListener("input", () => {
            textEditFindIndex = 0;
            updateTextEditorFind();
        });
        textEditFindInput.addEventListener("keydown", (ev) => {
            if (ev.key === "Enter") {
                ev.preventDefault();
                stepTextEditorFind(ev.shiftKey ? -1 : 1);
            } else if (ev.key === "Escape") {
                ev.preventDefault();
                hideTextEditorFind();
            }
        });
    }
    if (textEditFindPrevBtn) textEditFindPrevBtn.addEventListener("click", () => stepTextEditorFind(-1));
    if (textEditFindNextBtn) textEditFindNextBtn.addEventListener("click", () => stepTextEditorFind(1));
    if (textEditFindCaseBtn) textEditFindCaseBtn.addEventListener("click", () => {
        textEditFindMatchCase = !textEditFindMatchCase;
        textEditFindCaseBtn.classList.toggle("active", textEditFindMatchCase);
        textEditFindCaseBtn.textContent = textEditFindMatchCase ? "Aa✓" : "Aa";
        textEditFindIndex = 0;
        updateTextEditorFind();
    });

    if (textEditModal) {
        textEditModal.addEventListener("click", (ev) => {
            if (ev.target === textEditModal) closeTextEditor();
        });
    }

    if (textEditHead) {
        textEditHead.addEventListener("pointerdown", beginTextEditorDrag, true);
    }

    btnUp.addEventListener("click", () => {
        loadFiles(parentPath(currentPath)).catch((e) => setStatus(`Open parent failed: ${e.message || e}`, "bad"));
    });

    btnToggleUpload.addEventListener("click", () => {
        if (!canEdit) {
            setStatus("This workspace session is view-only.", "bad");
            return;
        }
        uploadOpen = !uploadOpen;
        syncUploadPanel();
    });

    btnUpload.addEventListener("click", () => {
        uploadSelectedFile().catch((e) => setStatus(`Upload failed: ${e.message || e}`, "bad"));
    });

    btnNewFolder.addEventListener("click", () => {
        createFolder().catch((e) => setStatus(`Create folder failed: ${e.message || e}`, "bad"));
    });

    newFolderName.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") {
            ev.preventDefault();
            createFolder().catch((e) => setStatus(`Create folder failed: ${e.message || e}`, "bad"));
        }
    });

    btnNewQr.addEventListener("click", () => {
        startSession().catch((e) => setStatus(`Failed to start QR session: ${e.message || e}`, "bad"));
    });

    function refreshCurrent() {
        loadFiles(currentPath).catch((e) => setStatus(`File refresh failed: ${e.message || e}`, "bad"));
    }

    btnRefreshFiles.addEventListener("click", refreshCurrent);
    btnReload.addEventListener("click", refreshCurrent);

    if (btnViewMode) {
        btnViewMode.addEventListener("click", () => {
            externalViewMode = externalViewMode === "list" ? "grid" : "list";
            try { localStorage.setItem(EXT_VIEW_PREF_KEY, externalViewMode); } catch (_) {}
            applyExternalViewPrefs();
        });
    }

    if (btnDirsFirst) {
        btnDirsFirst.addEventListener("click", () => {
            externalDirsFirst = !externalDirsFirst;
            try { localStorage.setItem(EXT_DIRS_FIRST_PREF_KEY, externalDirsFirst ? "1" : "0"); } catch (_) {}
            applyExternalViewPrefs();
            loadFiles(currentPath).catch((e) => setStatus(`Sort failed: ${e.message || e}`, "bad"));
        });
    }

    if (sortModeSelect) {
        sortModeSelect.value = externalSortMode;
        sortModeSelect.addEventListener("change", () => {
            externalSortMode = String(sortModeSelect.value || "name-asc");
            try { localStorage.setItem(EXT_SORT_PREF_KEY, externalSortMode); } catch (_) {}
            applyExternalViewPrefs();
            loadFiles(currentPath).catch((e) => setStatus(`Sort failed: ${e.message || e}`, "bad"));
        });
    }

    applyExternalViewPrefs();

    workspacePill.textContent = `workspace_id: ${workspaceId || "missing"}`;
    renderBreadcrumbs();

    // Try existing external cookie first. If it fails, show QR.
    loadFiles()
        .then(() => {
            showSignedInState();
            setStatus("Existing workspace session is active.", "good");
        })
        .catch(() => startSession().catch((e) => setStatus(`Failed to start QR session: ${e.message || e}`, "bad")));

    uploadFile?.addEventListener("change", () => {
        uploadSelectedFile().catch((e) => setStatus(`Upload failed: ${e.message || e}`, "bad"));
    });

    uploadFolderFile?.addEventListener("change", () => {
        uploadSelectedFolderFiles().catch((e) => setStatus(`Upload failed: ${e.message || e}`, "bad"));
    });

    wireExternalDragDropUpload();

    function updateAccessUi() {
        uploadOpen = false;
        if (uploadBox) uploadBox.classList.add("hidden");
        if (btnToggleUpload) btnToggleUpload.textContent = "Upload";
    }

    function launchExternalUploadPicker(folderMode) {
        if (!canEdit) {
            setStatus("Upload requires editor access.", "bad");
            return;
        }

        uploadOpen = false;
        updateAccessUi();

        const picker = document.createElement("input");
        picker.type = "file";
        picker.multiple = true;

        if (folderMode) {
            picker.setAttribute("webkitdirectory", "");
            picker.setAttribute("directory", "");
        }

        picker.style.position = "fixed";
        picker.style.left = "-10000px";
        picker.style.top = "-10000px";
        picker.style.width = "1px";
        picker.style.height = "1px";
        picker.style.opacity = "0";
        picker.style.pointerEvents = "none";

        picker.addEventListener("change", async () => {
            const selected = Array.from(picker.files || []);
            const relFiles = selected.map((file) => ({
                rel: file.webkitRelativePath || file.name,
                file
            }));

            try {
                await uploadRelFiles(relFiles);
            } finally {
                try { picker.remove(); } catch (_) {}
            }
        }, { once: true });

        document.body.appendChild(picker);
        picker.click();
    }

    function wireDirectUploadPicker() {
        if (!btnToggleUpload || btnToggleUpload.__externalDirectUploadWired) return;

        btnToggleUpload.__externalDirectUploadWired = true;
        btnToggleUpload.textContent = "Upload";

        btnToggleUpload.addEventListener("click", (ev) => {
            ev.preventDefault();
            ev.stopImmediatePropagation();
            launchExternalUploadPicker(false);
        }, true);
    }

    wireDirectUploadPicker();

})();
