(() => {
    "use strict";

    const api = window.PQNAS_FOLDER_PICKER = window.PQNAS_FOLDER_PICKER || {};

    let overlay = null;
    let cardEl = null;
    let dragHandleEl = null;
    let titleEl = null;
    let subEl = null;
    let sourceEl = null;
    let crumbEl = null;
    let listEl = null;
    let statusEl = null;
    let chooseBtn = null;
    let newFolderBtn = null;
    let scopeEl = null;

    let resolver = null;
    let currentPath = "";
    let activeScopeId = "";
    let busy = false;
    let loadSeq = 0;
    let opts = {};

    let dragState = null;
    let resizeBound = false;

    function normalizeRelPath(p) {
        return String(p || "")
            .replaceAll("\\", "/")
            .replace(/^\/+/, "")
            .replace(/\/+$/, "")
            .split("/")
            .filter(Boolean)
            .join("/");
    }

    function basename(p) {
        const parts = normalizeRelPath(p).split("/").filter(Boolean);
        return parts.length ? parts[parts.length - 1] : "";
    }

    function parentPath(p) {
        const parts = normalizeRelPath(p).split("/").filter(Boolean);
        parts.pop();
        return parts.join("/");
    }

    function joinPath(a, b) {
        const aa = normalizeRelPath(a);
        const bb = normalizeRelPath(b);
        if (!aa) return bb;
        if (!bb) return aa;
        return `${aa}/${bb}`;
    }

    function isSameOrUnder(path, root) {
        const p = normalizeRelPath(path);
        const r = normalizeRelPath(root);
        return !!r && (p === r || p.startsWith(r + "/"));
    }

    function blockedRoots() {
        const raw = Array.isArray(opts.blockedPaths) ? opts.blockedPaths : [];
        return raw.map(normalizeRelPath).filter(Boolean);
    }

    function destinationProblem(path) {
        const p = normalizeRelPath(path);
        for (const r of blockedRoots()) {
            if (isSameOrUnder(p, r)) {
                return "Cannot choose the source folder or one of its subfolders.";
            }
        }
        return "";
    }

    function clampCardPosition(left, top, width, height) {
        const margin = 12;
        const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);
        const vh = Math.max(document.documentElement.clientHeight || 0, window.innerHeight || 0);

        const maxLeft = Math.max(margin, vw - width - margin);
        const maxTop = Math.max(margin, vh - height - margin);

        return {
            left: Math.min(Math.max(margin, left), maxLeft),
            top: Math.min(Math.max(margin, top), maxTop)
        };
    }

    function clampExistingCardPosition() {
        if (!cardEl) return;
        if (!cardEl.style.left || !cardEl.style.top) return;

        const r = cardEl.getBoundingClientRect();
        const pos = clampCardPosition(r.left, r.top, r.width, r.height);
        cardEl.style.left = `${pos.left}px`;
        cardEl.style.top = `${pos.top}px`;
    }

    function beginDrag(ev) {
        if (!cardEl) return;
        if (ev.button !== undefined && ev.button !== 0) return;

        const target = ev.target;
        if (target && target.closest && target.closest("button, a, input, select, textarea")) {
            return;
        }

        const r = cardEl.getBoundingClientRect();
        dragState = {
            pointerId: ev.pointerId,
            dx: ev.clientX - r.left,
            dy: ev.clientY - r.top
        };

        cardEl.style.position = "fixed";
        cardEl.style.left = `${r.left}px`;
        cardEl.style.top = `${r.top}px`;
        cardEl.style.right = "auto";
        cardEl.style.bottom = "auto";
        cardEl.style.margin = "0";
        cardEl.style.transform = "none";
        cardEl.classList.add("dragging");

        try { cardEl.setPointerCapture(ev.pointerId); } catch (_) {}
        ev.preventDefault();
    }

    function dragMove(ev) {
        if (!dragState || !cardEl) return;
        if (ev.pointerId !== dragState.pointerId) return;

        const r = cardEl.getBoundingClientRect();
        const pos = clampCardPosition(
            ev.clientX - dragState.dx,
            ev.clientY - dragState.dy,
            r.width,
            r.height
        );

        cardEl.style.left = `${pos.left}px`;
        cardEl.style.top = `${pos.top}px`;
        ev.preventDefault();
    }

    function endDrag(ev) {
        if (!dragState || !cardEl) return;
        if (ev.pointerId !== dragState.pointerId) return;

        try { cardEl.releasePointerCapture(ev.pointerId); } catch (_) {}
        dragState = null;
        cardEl.classList.remove("dragging");
    }

    function defaultListUrl(path) {
        const p = normalizeRelPath(path);
        return p
            ? `/api/v4/files/list?path=${encodeURIComponent(p)}`
            : "/api/v4/files/list";
    }

    function defaultMkdirUrl(path) {
        return `/api/v4/files/mkdir?path=${encodeURIComponent(normalizeRelPath(path))}`;
    }

    function pickerScopes() {
        return Array.isArray(opts.scopes)
            ? opts.scopes.filter((s) => s && s.id)
            : [];
    }

    function activeScope() {
        const scopes = pickerScopes();
        if (!scopes.length) return null;

        let found = scopes.find((s) => String(s.id) === String(activeScopeId));
        if (!found) {
            found = scopes[0];
            activeScopeId = String(found.id || "");
        }
        return found || null;
    }

    function activeScopeRootLabel() {
        const sc = activeScope();
        return sc && sc.label ? String(sc.label) : "My Files";
    }

    function listUrl(path) {
        const sc = activeScope();
        if (sc && typeof sc.listUrl === "function") return sc.listUrl(normalizeRelPath(path));
        if (opts && typeof opts.listUrl === "function") return opts.listUrl(normalizeRelPath(path));
        return defaultListUrl(path);
    }

    function mkdirUrl(path) {
        const sc = activeScope();
        if (sc && typeof sc.mkdirUrl === "function") return sc.mkdirUrl(normalizeRelPath(path));
        if (opts && typeof opts.mkdirUrl === "function") return opts.mkdirUrl(normalizeRelPath(path));
        return defaultMkdirUrl(path);
    }

    function extractDirs(payload) {
        const out = [];
        const seen = new Set();

        function addName(name) {
            const n = String(name || "").trim();
            if (!n || n.includes("/")) return;
            if (seen.has(n)) return;
            seen.add(n);
            out.push({ name: n });
        }

        function isDirObj(x) {
            const t = String((x && (x.type || x.kind || x.entry_type)) || "").toLowerCase();
            return t === "dir" || t === "folder" || x?.is_dir === true || x?.dir === true;
        }

        function addArray(arr, forceDir = false) {
            if (!Array.isArray(arr)) return;
            for (const x of arr) {
                if (typeof x === "string") {
                    addName(basename(x));
                    continue;
                }
                if (!x || typeof x !== "object") continue;
                if (!forceDir && !isDirObj(x)) continue;
                addName(x.name || x.basename || basename(x.path || x.rel || x.rel_path || x.logical_rel_path || ""));
            }
        }

        addArray(payload?.dirs, true);
        addArray(payload?.folders, true);
        addArray(payload?.directories, true);
        addArray(payload?.items);
        addArray(payload?.entries);
        addArray(payload?.files);
        addArray(payload?.children);

        out.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }));
        return out;
    }
function ensureModal() {
        if (overlay) return;

        overlay = document.createElement("div");
        overlay.id = "pqnasFolderPicker";
        overlay.className = "fmMoveOverlay pqFolderPicker";
        overlay.setAttribute("aria-hidden", "true");

        overlay.innerHTML = `
            <div class="fmMoveCard" role="dialog" aria-modal="true" aria-labelledby="pqFolderPickerTitle">
                <div class="fmMoveHead">
                    <div>
                        <div id="pqFolderPickerTitle" class="fmMoveTitle">Choose folder</div>
                        <div class="modalSub fmMoveSub" data-pqfp-sub></div>
                    </div>
                    <button type="button" class="fmMoveClose" data-pqfp-close>Close</button>
                </div>
                <div class="fmMoveSource" data-pqfp-source></div>
                <div class="fmMoveBreadcrumb" data-pqfp-scopes></div>
                <div class="fmMoveBreadcrumb" data-pqfp-breadcrumb></div>
                <div class="fmMoveDirList" data-pqfp-list></div>
                <div class="fmMoveStatus" data-pqfp-status></div>
                <div class="fmMoveActions">
                    <div class="fmMoveActionGroup">
                        <button type="button" class="btn secondary" data-pqfp-new-folder>New folder here…</button>
                    </div>
                    <div class="fmMoveActionGroup">
                        <button type="button" class="btn secondary" data-pqfp-cancel>Cancel</button>
                        <button type="button" class="btn" data-pqfp-choose>Choose folder</button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        cardEl = overlay.querySelector(".fmMoveCard");
        dragHandleEl = overlay.querySelector(".fmMoveHead");

        titleEl = overlay.querySelector("#pqFolderPickerTitle");
        subEl = overlay.querySelector("[data-pqfp-sub]");
        sourceEl = overlay.querySelector("[data-pqfp-source]");
        scopeEl = overlay.querySelector("[data-pqfp-scopes]");
        crumbEl = overlay.querySelector("[data-pqfp-breadcrumb]");
        listEl = overlay.querySelector("[data-pqfp-list]");
        statusEl = overlay.querySelector("[data-pqfp-status]");
        chooseBtn = overlay.querySelector("[data-pqfp-choose]");
        newFolderBtn = overlay.querySelector("[data-pqfp-new-folder]");

        dragHandleEl?.addEventListener("pointerdown", beginDrag);
        cardEl?.addEventListener("pointermove", dragMove);
        cardEl?.addEventListener("pointerup", endDrag);
        cardEl?.addEventListener("pointercancel", endDrag);

        if (!resizeBound) {
            resizeBound = true;
            window.addEventListener("resize", clampExistingCardPosition);
        }

        overlay.querySelector("[data-pqfp-close]")?.addEventListener("click", () => close(null));
        overlay.querySelector("[data-pqfp-cancel]")?.addEventListener("click", () => close(null));
        chooseBtn?.addEventListener("click", () => {
            const problem = destinationProblem(currentPath);
            if (problem) {
                setStatus(problem);
                renderActionState();
                return;
            }
            close(buildCloseValue());
        });
        newFolderBtn?.addEventListener("click", createFolderHere);

        // Folder rows are rebuilt after every directory load, so handle row opening
        // from the stable list container. Capture phase makes this robust against
        // button/default handling and other app-level listeners.
        listEl?.addEventListener("click", (ev) => {
            const row = ev.target && ev.target.closest
                ? ev.target.closest("[data-pqfp-open-path]")
                : null;

            if (!row || !listEl.contains(row)) return;
            if (row.getAttribute("aria-disabled") === "true" || row.disabled) return;

            ev.preventDefault();
            ev.stopPropagation();
            if (ev.stopImmediatePropagation) ev.stopImmediatePropagation();

            const nextPath = row.getAttribute("data-pqfp-open-path") || "";
            openPath(nextPath).catch((e) => {
                setStatus(`Open folder failed: ${String(e && e.message ? e.message : e)}`);
                setBusy(false);
                renderActionState();
            });
        }, true);

        overlay.addEventListener("click", (ev) => {
            if (ev.target === overlay) close(null);
        });

        overlay.addEventListener("keydown", (ev) => {
            ev.stopPropagation();
            if (ev.key === "Escape") close(null);
        });
    }

    function setStatus(msg) {
        if (statusEl) statusEl.textContent = msg || "";
    }

    function setBusy(on) {
        busy = !!on;
        renderActionState();
    }

    function buildCloseValue() {
        const path = normalizeRelPath(currentPath);
        const scopes = pickerScopes();
        if (!scopes.length) return path;

        const sc = activeScope();
        return {
            path,
            scopeId: activeScopeId || (sc ? String(sc.id || "") : ""),
            scope: sc ? {
                id: String(sc.id || ""),
                label: String(sc.label || ""),
                kind: String(sc.kind || ""),
                workspaceId: String(sc.workspaceId || "")
            } : null
        };
    }

    function renderScopes() {
        if (!scopeEl) return;

        clear(scopeEl);

        const scopes = pickerScopes();
        if (!scopes.length) {
            scopeEl.style.display = "none";
            return;
        }

        scopeEl.style.display = "flex";
        scopeEl.style.alignItems = "center";
        scopeEl.style.gap = "10px";
        scopeEl.style.boxSizing = "border-box";
        scopeEl.style.padding = "10px 14px 12px";
        scopeEl.style.borderBottom = "1px solid rgba(0,0,0,0.10)";
        scopeEl.style.marginBottom = "8px";

        const label = document.createElement("div");
        label.textContent = "Destination location";
        label.style.fontWeight = "800";
        label.style.whiteSpace = "nowrap";

        const select = document.createElement("select");
        select.className = "fmMoveScopeSelect";
        select.disabled = busy;
        select.style.minWidth = "220px";
        select.style.maxWidth = "420px";
        select.style.padding = "8px 10px";
        select.style.borderRadius = "8px";
        select.style.border = "1px solid rgba(0,0,0,0.22)";
        select.style.background = "rgba(255,255,255,0.55)";
        select.style.fontWeight = "700";

        for (const sc of scopes) {
            const id = String(sc.id || "");
            const opt = document.createElement("option");
            opt.value = id;
            opt.textContent = String(sc.label || id || "Location");
            if (id === String(activeScopeId || "")) opt.selected = true;
            select.appendChild(opt);
        }

        select.addEventListener("change", () => {
            activeScopeId = String(select.value || "");
            const sc = activeScope();
            currentPath = normalizeRelPath(sc && sc.initialPath ? sc.initialPath : "");
            openPath(currentPath).catch((e) => {
                setStatus(`Open location failed: ${String(e && e.message ? e.message : e)}`);
                setBusy(false);
                renderActionState();
            });
        });

        scopeEl.appendChild(label);
        scopeEl.appendChild(select);
    }

    function renderActionState() {
        const problem = destinationProblem(currentPath);
        const shown = currentPath ? `/${currentPath}` : "/";

        if (chooseBtn) {
            const sc = activeScope();
            const scopeProblem = sc && sc.canChoose === false ? "Destination location is read-only." : "";
            const finalProblem = scopeProblem || problem;
            chooseBtn.disabled = busy || !!finalProblem;
            chooseBtn.textContent = opts.chooseLabel || "Choose folder";
            chooseBtn.title = finalProblem || `Choose ${activeScopeRootLabel()} ${shown}`;
        }

        if (newFolderBtn) {
            const sc = activeScope();
            newFolderBtn.disabled = busy || !!problem || opts.canCreate === false || (sc && sc.canCreate === false);
        }

        if (statusEl && !busy) {
            statusEl.textContent = problem || `Destination: ${activeScopeRootLabel()} ${shown}`;
        }
    }

    function clear(el) {
        if (!el) return;
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    function appendCrumb(label, path, active) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "fmMoveCrumb" + (active ? " active" : "");
        b.textContent = label;
        b.disabled = active || busy;
        b.addEventListener("click", () => openPath(path));
        crumbEl.appendChild(b);
    }

    function renderBreadcrumb() {
        clear(crumbEl);
        const parts = normalizeRelPath(currentPath).split("/").filter(Boolean);

        appendCrumb("/", "", parts.length === 0);

        let acc = "";
        parts.forEach((part, idx) => {
            const sep = document.createElement("span");
            sep.className = "fmMoveSep";
            sep.textContent = "/";
            crumbEl.appendChild(sep);

            acc = acc ? `${acc}/${part}` : part;
            appendCrumb(part, acc, idx === parts.length - 1);
        });
    }

    function appendRow(label, meta, onClick, rowOpts = {}) {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "fmMoveDirRow";
        row.disabled = !!rowOpts.disabled;

        if (rowOpts.disabled) {
            row.setAttribute("aria-disabled", "true");
        } else {
            row.removeAttribute("aria-disabled");
        }

        if (rowOpts.path !== undefined && rowOpts.path !== null) {
            row.setAttribute("data-pqfp-open-path", normalizeRelPath(rowOpts.path));
        }

        const name = document.createElement("div");
        name.className = "fmMoveDirName";
        name.textContent = label;

        const m = document.createElement("div");
        m.className = "fmMoveDirMeta";
        m.textContent = meta || "";

        row.appendChild(name);
        row.appendChild(m);

        if (!rowOpts.disabled && typeof onClick === "function") {
            row.addEventListener("click", (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                onClick();
            });
        }

        listEl.appendChild(row);
    }

    function renderRows(dirs) {
        clear(listEl);

        if (currentPath) {
            const upPath = parentPath(currentPath);
            appendRow("..", "Parent folder", () => openPath(upPath), { path: upPath });
        }

        if (!dirs.length) {
            const empty = document.createElement("div");
            empty.className = "fmMoveDirRow";
            empty.setAttribute("aria-disabled", "true");
            empty.textContent = "No folders here";
            listEl.appendChild(empty);
            return;
        }

        for (const d of dirs) {
            const rel = joinPath(currentPath, d.name);
            const blocked = blockedRoots().some((root) => isSameOrUnder(rel, root));
            appendRow(
                d.name,
                blocked ? "Cannot choose source" : "Folder",
                () => openPath(rel),
                { disabled: blocked, path: rel }
            );
        }
    }

    async function openPath(path) {
        currentPath = normalizeRelPath(path);
        await loadCurrentPath();
    }

    async function loadCurrentPath() {
        ensureModal();

        const mySeq = ++loadSeq;
        renderScopes();
        renderBreadcrumb();
        setBusy(true);
        setStatus(`Loading ${activeScopeRootLabel()} /${currentPath || ""}`);

        clear(listEl);
        const loading = document.createElement("div");
        loading.className = "fmMoveDirRow";
        loading.setAttribute("aria-disabled", "true");
        loading.textContent = "Loading folders…";
        listEl.appendChild(loading);

        try {
            const r = await fetch(listUrl(currentPath), {
                headers: { "Accept": "application/json" },
                credentials: "include",
                cache: "no-store"
            });
            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j || j.ok === false) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            if (mySeq !== loadSeq) return;
            renderRows(extractDirs(j));
        } catch (e) {
            if (mySeq !== loadSeq) return;
            clear(listEl);
            const err = document.createElement("div");
            err.className = "fmMoveDirRow";
            err.setAttribute("aria-disabled", "true");
            err.textContent = `Failed to load folders: ${String(e && e.message ? e.message : e)}`;
            listEl.appendChild(err);
        } finally {
            if (mySeq === loadSeq) {
                setBusy(false);
                renderActionState();
            }
        }
    }

    async function createFolderHere() {
        if (busy || opts.canCreate === false) return;

        const problem = destinationProblem(currentPath);
        if (problem) {
            setStatus(problem);
            renderActionState();
            return;
        }

        const shown = currentPath ? `/${currentPath}` : "/";
        const raw = prompt(`New folder name in ${shown}:`, "New Folder");
        if (!raw) return;

        const name = String(raw).trim();
        if (!name) return;
        if (name.includes("/") || name.includes("\\")) {
            alert("Name cannot contain '/' or '\\'.");
            return;
        }

        const rel = joinPath(currentPath, name);

        try {
            setBusy(true);
            setStatus("Creating folder…");

            const r = await fetch(mkdirUrl(rel), {
                method: "POST",
                credentials: "include",
                cache: "no-store"
            });
            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j || j.ok === false) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            currentPath = rel;
            await loadCurrentPath();
        } catch (e) {
            setStatus(`Create folder failed: ${String(e && e.message ? e.message : e)}`);
            setBusy(false);
            renderActionState();
        }
    }

    function close(value) {
        if (!overlay) return;
        overlay.classList.remove("show");
        overlay.setAttribute("aria-hidden", "true");

        const r = resolver;
        resolver = null;
        if (r) r(value);
    }

    api.open = function openFolderPicker(openOpts = {}) {
        ensureModal();

        if (resolver) {
            resolver(null);
            resolver = null;
        }

        opts = Object.assign({}, openOpts || {});

        const scopes = pickerScopes();
        activeScopeId = String(opts.initialScopeId || (scopes[0] ? scopes[0].id : "") || "");

        const sc = activeScope();
        currentPath = normalizeRelPath(
            opts.initialPath ||
            (sc && sc.initialPath) ||
            ""
        );

        if (titleEl) titleEl.textContent = opts.title || "Choose folder";
        if (subEl) subEl.textContent = opts.subtitle || "";
        if (sourceEl) sourceEl.textContent = opts.source ? String(opts.source) : "";

        overlay.classList.add("show");
        overlay.setAttribute("aria-hidden", "false");

        requestAnimationFrame(clampExistingCardPosition);

        setTimeout(() => {
            try { chooseBtn?.focus(); } catch (_) {}
        }, 0);

        loadCurrentPath().catch((e) => {
            setStatus(`Folder picker failed: ${String(e && e.message ? e.message : e)}`);
            setBusy(false);
        });

        return new Promise((resolve) => {
            resolver = resolve;
        });
    };
})();
