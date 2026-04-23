(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};
    const el = (id) => document.getElementById(id);

    const gridWrap = el("gridWrap");
    const dropOverlay = el("dropOverlay");

    const filePick = el("filePick");
    const folderPick = el("folderPick");

    const uploadProg = el("uploadProg");
    const uploadProgText = el("uploadProgText");
    const uploadProgPill = el("uploadProgPill");
    const uploadProgPct = el("uploadProgPct");
    const uploadProgFill = el("uploadProgFill");
    const uploadCancelBtn = el("uploadCancelBtn");

    const uploadConflictModal = el("uploadConflictModal");
    const uploadConflictClose = el("uploadConflictClose");
    const uploadConflictPath = el("uploadConflictPath");
    const uploadConflictExisting = el("uploadConflictExisting");
    const uploadConflictIncoming = el("uploadConflictIncoming");
    const uploadConflictKeepOld = el("uploadConflictKeepOld");
    const uploadConflictReplace = el("uploadConflictReplace");
    const uploadConflictApplyAll = el("uploadConflictApplyAll");
    const uploadConflictCancelBtn = el("uploadConflictCancelBtn");
    const uploadConflictOkBtn = el("uploadConflictOkBtn");

    let activeUploadXhr = null;
    let uploadCancelRequested = false;

    function setStatus(text) {
        if (typeof PG.setStatus === "function") PG.setStatus(text);
    }

    function setBadge(kind, text) {
        if (typeof PG.setBadge === "function") PG.setBadge(kind, text);
    }

    function currentPath() {
        return typeof PG.getCurrentPath === "function"
            ? String(PG.getCurrentPath() || "")
            : "";
    }

    async function refreshGallery(forceSearch = true) {
        if (typeof PG.reload === "function") {
            await PG.reload(!!forceSearch);
        }
    }

    function normalizeRelPath(rel) {
        rel = String(rel || "").replace(/\\/g, "/");
        rel = rel.replace(/^\/+/, "");
        rel = rel.split("/").filter(Boolean).join("/");
        return rel;
    }

    function validateRelPath(rel) {
        const parts = String(rel || "").split("/").filter(Boolean);
        if (!parts.length) return false;
        for (const p of parts) {
            if (p === "." || p === "..") return false;
            if (p.includes("/") || p.includes("\\")) return false;
        }
        return true;
    }

    function parentPath(p) {
        if (!p) return "";
        const i = p.lastIndexOf("/");
        return i < 0 ? "" : p.slice(0, i);
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

    function fmtBrowserFileTime(ms) {
        const n = Number(ms || 0);
        if (!Number.isFinite(n) || n <= 0) return "—";
        const d = new Date(n);
        if (isNaN(d.getTime())) return "—";
        const pad = (x) => String(x).padStart(2, "0");
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }

    function fmtSpeed(bytesPerSec) {
        const v = Number(bytesPerSec || 0);
        if (!Number.isFinite(v) || v <= 0) return "—";
        return `${fmtSize(v)}/s`;
    }

    function shorten(s, n) {
        s = String(s || "");
        if (s.length <= n) return s;
        return s.slice(0, Math.max(0, n - 1)) + "…";
    }

    function apiMkdirUrl(path) {
        return `/api/v4/files/mkdir?path=${encodeURIComponent(path || "")}`;
    }

    function apiPutUrl(path, overwrite) {
        const qs = new URLSearchParams();
        qs.set("path", path || "");
        if (overwrite) qs.set("overwrite", "1");
        return `/api/v4/files/put?${qs.toString()}`;
    }

    function isSupportedGalleryUploadName(name) {
        const n = String(name || "").toLowerCase();
        return (
            n.endsWith(".jpg")  || n.endsWith(".jpeg") ||
            n.endsWith(".png")  || n.endsWith(".webp") ||
            n.endsWith(".gif")  || n.endsWith(".bmp")  ||
            n.endsWith(".svg")  || n.endsWith(".ico")  ||
            n.endsWith(".tif")  || n.endsWith(".tiff") ||
            n.endsWith(".heic") || n.endsWith(".heif") ||
            n.endsWith(".cr2")  || n.endsWith(".cr3")  ||
            n.endsWith(".nef")  || n.endsWith(".arw")  ||
            n.endsWith(".raf")  || n.endsWith(".dng")  ||
            n.endsWith(".rw2")  || n.endsWith(".orf")
        );
    }

    function showDropOverlay(show) {
        if (!dropOverlay) return;
        dropOverlay.classList.toggle("show", !!show);
        dropOverlay.setAttribute("aria-hidden", show ? "false" : "true");
    }

    function showUploadProgress(show) {
        if (!uploadProg) return;
        uploadProg.style.display = show ? "block" : "none";
        uploadProg.setAttribute("aria-hidden", show ? "false" : "true");

        if (!show) {
            if (uploadProgFill) uploadProgFill.style.width = "0%";
            if (uploadProgPct) uploadProgPct.textContent = "0%";
            if (uploadProgText) uploadProgText.textContent = "";
            if (uploadProgPill) {
                uploadProgPill.className = "upPill hidden";
                uploadProgPill.textContent = "";
            }
            setUploadCancelable(false);
        }
    }

    function setUploadCancelable(on) {
        if (!uploadCancelBtn) return;
        uploadCancelBtn.classList.toggle("hidden", !on);
        uploadCancelBtn.disabled = !on;
    }

    function setUploadProgress(pct, text, pillText = "", pillKind = "") {
        pct = Math.max(0, Math.min(100, Number(pct || 0)));

        if (uploadProgFill) uploadProgFill.style.width = `${pct.toFixed(1)}%`;
        if (uploadProgPct) uploadProgPct.textContent = `${Math.round(pct)}%`;
        if (uploadProgText && text != null) uploadProgText.textContent = String(text);

        if (uploadProgPill) {
            const t = String(pillText || "").trim();
            if (!t) {
                uploadProgPill.className = "upPill hidden";
                uploadProgPill.textContent = "";
            } else {
                uploadProgPill.className = `upPill ${pillKind || ""}`.trim();
                uploadProgPill.textContent = t;
            }
        }
    }

    function openUploadConflictModal() {
        if (!uploadConflictModal) return;
        uploadConflictModal.classList.add("show");
        uploadConflictModal.setAttribute("aria-hidden", "false");
    }

    function closeUploadConflictModal() {
        if (!uploadConflictModal) return;
        uploadConflictModal.classList.remove("show");
        uploadConflictModal.setAttribute("aria-hidden", "true");
    }

    function describeExistingConflict(existing) {
        if (!existing || typeof existing !== "object") return "Unknown";
        const parts = [];
        if (existing.size_bytes != null) parts.push(`Size: ${fmtSize(existing.size_bytes)}`);
        if (existing.mtime_epoch) parts.push(`Modified: ${existing.mtime_epoch}`);
        return parts.length ? parts.join(" • ") : "Unknown";
    }

    function describeIncomingConflict(file) {
        if (!file) return "Unknown";
        const parts = [];
        if (file.size != null) parts.push(`Size: ${fmtSize(file.size)}`);
        if (file.lastModified) parts.push(`Modified: ${fmtBrowserFileTime(file.lastModified)}`);
        return parts.length ? parts.join(" • ") : "Unknown";
    }

    function askUploadConflictDecision(rel, file, existing) {
        return new Promise((resolve) => {
            if (!uploadConflictModal) {
                resolve({ action: "cancel", applyAll: false });
                return;
            }

            if (uploadConflictPath) uploadConflictPath.textContent = "/" + String(rel || "");
            if (uploadConflictExisting) uploadConflictExisting.textContent = describeExistingConflict(existing);
            if (uploadConflictIncoming) uploadConflictIncoming.textContent = describeIncomingConflict(file);

            if (uploadConflictKeepOld) uploadConflictKeepOld.checked = true;
            if (uploadConflictReplace) uploadConflictReplace.checked = false;
            if (uploadConflictApplyAll) uploadConflictApplyAll.checked = false;

            let settled = false;

            const finish = (result) => {
                if (settled) return;
                settled = true;
                cleanup();
                closeUploadConflictModal();
                resolve(result);
            };

            const onOk = () => {
                const action = uploadConflictReplace && uploadConflictReplace.checked ? "replace" : "keep_old";
                const applyAll = !!(uploadConflictApplyAll && uploadConflictApplyAll.checked);
                finish({ action, applyAll });
            };

            const onCancel = () => finish({ action: "cancel", applyAll: false });

            const onBackdrop = (e) => {
                if (e.target === uploadConflictModal) onCancel();
            };

            const onKey = (e) => {
                if (e.key === "Escape") {
                    e.preventDefault();
                    onCancel();
                }
            };

            const cleanup = () => {
                uploadConflictOkBtn?.removeEventListener("click", onOk);
                uploadConflictCancelBtn?.removeEventListener("click", onCancel);
                uploadConflictClose?.removeEventListener("click", onCancel);
                uploadConflictModal?.removeEventListener("click", onBackdrop);
                document.removeEventListener("keydown", onKey);
            };

            uploadConflictOkBtn?.addEventListener("click", onOk);
            uploadConflictCancelBtn?.addEventListener("click", onCancel);
            uploadConflictClose?.addEventListener("click", onCancel);
            uploadConflictModal?.addEventListener("click", onBackdrop);
            document.addEventListener("keydown", onKey);

            openUploadConflictModal();
        });
    }

    async function mkdirIfNeeded(basePath, relDir, created) {
        if (!relDir) return;

        const norm = normalizeRelPath(relDir);
        if (!norm) return;

        const parts = norm.split("/").filter(Boolean);
        let acc = "";

        for (const part of parts) {
            acc = acc ? `${acc}/${part}` : part;
            const full = basePath ? `${basePath}/${acc}` : acc;
            if (created.has(full)) continue;

            try {
                await fetch(apiMkdirUrl(full), {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                });
            } catch (_) {}

            created.add(full);
        }
    }

    function readEntryAsFile(entry) {
        return new Promise((resolve) => {
            entry.file((file) => resolve(file), () => resolve(null));
        });
    }

    async function walkEntry(entry, prefix, out) {
        if (!entry) return;

        if (entry.isFile) {
            const f = await readEntryAsFile(entry);
            if (f) out.push({ rel: prefix + f.name, file: f, source: "drop" });
            return;
        }

        if (entry.isDirectory) {
            const dirReader = entry.createReader();
            const name = entry.name ? (entry.name + "/") : "";
            const nextPrefix = prefix + name;

            while (true) {
                const batch = await new Promise((resolve) => {
                    dirReader.readEntries(resolve, () => resolve([]));
                });
                if (!batch || !batch.length) break;
                for (const child of batch) {
                    await walkEntry(child, nextPrefix, out);
                }
            }
        }
    }

    async function collectDroppedFiles(dt) {
        const out = [];
        const items = dt && dt.items ? Array.from(dt.items) : [];
        const hasEntryApi = items.some(it => it && typeof it.webkitGetAsEntry === "function");

        if (hasEntryApi) {
            for (const it of items) {
                if (!it) continue;
                const entry = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
                if (!entry) continue;
                await walkEntry(entry, "", out);
            }
            return out;
        }

        const files = Array.from((dt && dt.files) || []);
        for (const f of files) out.push({ rel: f.name, file: f, source: "drop" });
        return out;
    }

    function hasFiles(dt) {
        if (!dt) return false;
        try { if (dt.files && dt.files.length > 0) return true; } catch (_) {}
        try { if (dt.items && dt.items.length > 0) return true; } catch (_) {}
        try {
            const types = Array.from(dt.types || []);
            return types.includes("Files") || types.includes("application/x-moz-file");
        } catch (_) {}
        return false;
    }

    function isFileExistsConflict(errLike) {
        if (!errLike) return false;
        if (errLike.error === "file_exists") return true;
        if (errLike.details && errLike.details.error === "file_exists") return true;
        return false;
    }

    function xhrPutFileTo(basePath, relPath, file, onProgress, opts = {}) {
        return new Promise((resolve, reject) => {
            const full = basePath ? `${basePath}/${relPath}` : relPath;
            const url = apiPutUrl(full, !!opts.overwrite);

            const xhr = new XMLHttpRequest();
            activeUploadXhr = xhr;

            const clearActive = () => {
                if (activeUploadXhr === xhr) activeUploadXhr = null;
            };

            xhr.open("PUT", url, true);
            xhr.withCredentials = true;
            xhr.setRequestHeader("Content-Type", "application/octet-stream");
            xhr.timeout = 60 * 60 * 1000;

            xhr.ontimeout = () => {
                clearActive();
                reject(Object.assign(new Error("upload failed (timeout)"), { kind: "network" }));
            };

            let lastProgressTs = 0;

            xhr.upload.onprogress = (e) => {
                if (!onProgress) return;
                const now = performance.now();
                if (now - lastProgressTs < 80) return;
                lastProgressTs = now;

                if (e.lengthComputable) onProgress(e.loaded, e.total);
                else onProgress(e.loaded, file.size || 0);
            };

            xhr.onerror = () => {
                clearActive();
                reject(Object.assign(new Error("upload failed (network)"), { kind: "network" }));
            };

            xhr.onabort = () => {
                clearActive();
                if (uploadCancelRequested) {
                    reject(Object.assign(new Error("upload cancelled"), { kind: "cancelled" }));
                } else {
                    reject(Object.assign(new Error("upload aborted"), { kind: "network" }));
                }
            };

            xhr.onload = () => {
                const status = xhr.status || 0;
                const raw = String(xhr.responseText || "").trim();
                let j = null;

                if (raw && (raw.startsWith("{") || raw.startsWith("["))) {
                    try { j = JSON.parse(raw); } catch (_) {}
                }

                if (status >= 200 && status < 300) {
                    if (!j || j.ok !== false) {
                        clearActive();
                        resolve(j || { ok: true });
                        return;
                    }
                }

                if (j && j.error === "file_exists") {
                    const err = new Error(j.message || "file already exists");
                    err.error = "file_exists";
                    err.kind = "file_exists";
                    err.details = j;
                    clearActive();
                    reject(err);
                    return;
                }

                if (j && (j.message || j.error)) {
                    const err = new Error(`${j.error || ""} ${j.message || ""}`.trim() || `HTTP ${status}`);
                    err.http = status;
                    err.details = j;
                    clearActive();
                    reject(err);
                    return;
                }

                if (status === 413) {
                    clearActive();
                    reject(Object.assign(new Error(`Upload too large: ${fmtSize(file.size)}`), { http: 413 }));
                    return;
                }

                clearActive();
                reject(Object.assign(new Error(raw ? shorten(raw, 180) : `HTTP ${status}`), { http: status }));
            };

            xhr.send(file);
        });
    }

    async function uploadRelFiles(relFiles) {
        if (!Array.isArray(relFiles) || !relFiles.length) return;

        const basePath = currentPath();

        const rawItems = relFiles.map((it) => ({
            rel: normalizeRelPath(it.rel),
            file: it.file,
            source: it.source || ""
        })).filter((it) => validateRelPath(it.rel));

        const items = rawItems.filter((it) => isSupportedGalleryUploadName(it.rel));
        const skippedUnsupported = rawItems.length - items.length;

        if (!items.length) {
            setBadge("warn", "no files");
            setStatus("No supported gallery files found in selection.");
            return;
        }

        const created = new Set();
        const totalFiles = items.length;
        const totalBytes = items.reduce((a, it) => a + (Number(it.file.size) || 0), 0) || 1;

        let doneFiles = 0;
        let skippedFiles = 0;
        let failedFiles = 0;
        let uploadedBytesCommitted = 0;
        const startedAt = performance.now();

        let conflictApplyAll = false;
        let conflictActionAll = "";

        uploadCancelRequested = false;
        activeUploadXhr = null;

        showUploadProgress(true);
        setUploadCancelable(true);
        setBadge("warn", "upload…");
        setUploadProgress(0, `Uploading 0/${totalFiles}…`);

        for (let idx = 0; idx < items.length; idx++) {
            if (uploadCancelRequested) break;

            const { rel, file } = items[idx];
            const dir = parentPath(rel);

            if (dir) await mkdirIfNeeded(basePath, dir, created);

            let lastLoaded = 0;

            const runUpload = async (overwrite = false) => {
                await xhrPutFileTo(basePath, rel, file, (loaded) => {
                    lastLoaded = Math.max(lastLoaded, loaded || 0);

                    const overall = uploadedBytesCommitted + lastLoaded;
                    const pct = (overall / totalBytes) * 100;
                    const elapsedSec = Math.max(0.001, (performance.now() - startedAt) / 1000);
                    const speedBps = overall / elapsedSec;

                    setBadge("warn", "upload…");
                    setUploadProgress(
                        pct,
                        `Uploading ${doneFiles}/${totalFiles} • ${rel} • ${fmtSize(overall)} / ${fmtSize(totalBytes)} • ${fmtSpeed(speedBps)}`
                    );
                }, { overwrite });
            };

            try {
                let finishedThisFile = false;
                let skipThisFile = false;

                while (!finishedThisFile && !skipThisFile) {
                    try {
                        const autoOverwrite = conflictApplyAll && conflictActionAll === "replace";
                        await runUpload(autoOverwrite);
                        finishedThisFile = true;
                    } catch (e) {
                        if (e && e.kind === "cancelled") throw e;

                        if (isFileExistsConflict(e)) {
                            let decision = null;

                            if (conflictApplyAll && conflictActionAll) {
                                decision = { action: conflictActionAll, applyAll: true };
                            } else {
                                setBadge("warn", "conflict");
                                setUploadProgress(
                                    (uploadedBytesCommitted / totalBytes) * 100,
                                    `Conflict: ${rel}`,
                                    `Already exists: ${rel}`,
                                    "warn"
                                );

                                decision = await askUploadConflictDecision(
                                    rel,
                                    file,
                                    e && e.details ? e.details.existing : null
                                );
                            }

                            if (!decision || decision.action === "cancel") {
                                uploadCancelRequested = true;
                                throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
                            }

                            if (decision.applyAll) {
                                conflictApplyAll = true;
                                conflictActionAll = decision.action;
                            }

                            if (decision.action === "keep_old") {
                                skipThisFile = true;
                                skippedFiles++;
                                setBadge("warn", "skipped");
                                setUploadProgress(
                                    (uploadedBytesCommitted / totalBytes) * 100,
                                    `Skipped existing file • ${rel}`,
                                    `Kept existing: ${rel}`,
                                    "warn"
                                );
                                break;
                            }

                            if (decision.action === "replace") {
                                await runUpload(true);
                                finishedThisFile = true;
                                break;
                            }
                        }

                        throw e;
                    }
                }

                if (skipThisFile) continue;

                uploadedBytesCommitted += (Number(file.size) || lastLoaded || 0);
                doneFiles++;

                const pct = (uploadedBytesCommitted / totalBytes) * 100;
                const elapsedSec = Math.max(0.001, (performance.now() - startedAt) / 1000);
                const speedBps = uploadedBytesCommitted / elapsedSec;

                setUploadProgress(
                    pct,
                    `Uploaded ${doneFiles}/${totalFiles} • ${rel} • ${fmtSpeed(speedBps)}`
                );
            } catch (e) {
                if (e && e.kind === "cancelled") {
                    setBadge("warn", "cancelled");
                    setUploadProgress(
                        (uploadedBytesCommitted / totalBytes) * 100,
                        `Upload cancelled • Uploaded ${doneFiles}/${totalFiles} • Skipped ${skippedFiles}`,
                        "",
                        "warn"
                    );
                    break;
                }

                failedFiles++;
                setBadge("err", "error");
                setUploadProgress(
                    (uploadedBytesCommitted / totalBytes) * 100,
                    `Failed: ${rel}`,
                    `Last error: ${rel}`,
                    "err"
                );
                console.warn("Photo upload failed:", rel, e);
            }
        }

        setUploadCancelable(false);
        activeUploadXhr = null;
        uploadCancelRequested = false;

        await refreshGallery(true);

        if (failedFiles > 0) {
            setBadge("warn", "partial");
            setStatus(
                `Upload finished. Uploaded ${doneFiles}/${totalFiles}, skipped ${skippedFiles}, failed ${failedFiles}` +
                (skippedUnsupported > 0 ? `, ignored unsupported ${skippedUnsupported}` : "")
            );
            return;
        }

        if (skippedFiles > 0 || skippedUnsupported > 0) {
            setBadge("warn", "ready");
            setStatus(
                `Upload finished. Uploaded ${doneFiles}/${totalFiles}, skipped existing ${skippedFiles}` +
                (skippedUnsupported > 0 ? `, ignored unsupported ${skippedUnsupported}` : "")
            );
        } else {
            setBadge("ok", "ready");
            setStatus(`Upload finished. Uploaded ${doneFiles} file${doneFiles === 1 ? "" : "s"}.`);
        }

        setTimeout(() => showUploadProgress(false), 900);
    }

    function pickFiles() {
        if (!filePick) return;
        filePick.value = "";
        filePick.click();
    }

    function pickFolder() {
        if (!folderPick) return;
        folderPick.value = "";
        folderPick.click();
    }

    function cancelCurrentUpload() {
        uploadCancelRequested = true;
        if (activeUploadXhr) {
            try { activeUploadXhr.abort(); } catch (_) {}
        }
    }

    uploadCancelBtn?.addEventListener("click", cancelCurrentUpload);

    filePick?.addEventListener("change", async () => {
        const files = Array.from(filePick.files || []);
        const relFiles = files.map((f) => ({ rel: f.name, file: f, source: "picker" }));
        await uploadRelFiles(relFiles);
        filePick.value = "";
    });

    folderPick?.addEventListener("change", async () => {
        const files = Array.from(folderPick.files || []);
        const relFiles = files.map((f) => ({
            rel: f.webkitRelativePath || f.name,
            file: f,
            source: "picker"
        }));
        await uploadRelFiles(relFiles);
        folderPick.value = "";
    });

    gridWrap?.addEventListener("dragenter", (e) => {
        e.preventDefault();
        if (hasFiles(e.dataTransfer)) showDropOverlay(true);
    });

    gridWrap?.addEventListener("dragover", (e) => {
        e.preventDefault();
        if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
        showDropOverlay(true);
    });

    gridWrap?.addEventListener("dragleave", (e) => {
        if (e.target === gridWrap) showDropOverlay(false);
    });

    gridWrap?.addEventListener("drop", async (e) => {
        e.preventDefault();
        showDropOverlay(false);

        try {
            const dt = e.dataTransfer;
            if (!dt || (!dt.files || dt.files.length === 0)) {
                setBadge("warn", "drop");
                setStatus("Drop did not contain files.");
                return;
            }

            const relFiles = await collectDroppedFiles(dt);
            if (!relFiles.length) {
                setBadge("warn", "drop");
                setStatus("Drop contained no files.");
                return;
            }

            await uploadRelFiles(relFiles);
        } catch (err) {
            setBadge("err", "error");
            setStatus(`Drop upload failed: ${String(err && err.message ? err.message : err)}`);
            console.error("Photo Gallery drop failed:", err);
        }
    });

    uploadConflictClose?.addEventListener("click", closeUploadConflictModal);
    uploadConflictModal?.addEventListener("click", (e) => {
        if (e.target === uploadConflictModal) closeUploadConflictModal();
    });

    PG.upload = {
        pickFiles,
        pickFolder,
        uploadRelFiles
    };
})();