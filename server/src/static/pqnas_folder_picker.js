(() => {
    "use strict";

    const api = window.PQNAS_FOLDER_PICKER = window.PQNAS_FOLDER_PICKER || {};

    let overlay = null;
    let titleEl = null;
    let subEl = null;
    let sourceEl = null;
    let crumbEl = null;
    let listEl = null;
    let statusEl = null;
    let chooseBtn = null;
    let newFolderBtn = null;

    let resolver = null;
    let currentPath = "";
    let busy = false;
    let loadSeq = 0;
    let opts = {};

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

    function defaultListUrl(path) {
        const p = normalizeRelPath(path);
        return p
            ? `/api/v4/files/list?path=${encodeURIComponent(p)}`
            : "/api/v4/files/list";
    }

    function defaultMkdirUrl(path) {
        return `/api/v4/files/mkdir?path=${encodeURIComponent(normalizeRelPath(path))}`;
    }

    function listUrl(path) {
        if (opts && typeof opts.listUrl === "function") return opts.listUrl(normalizeRelPath(path));
        return defaultListUrl(path);
    }

    function mkdirUrl(path) {
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


    function ensurePickerCss() {
        if (document.getElementById("pqnasFolderPickerStyle")) return;

        const style = document.createElement("style");
        style.id = "pqnasFolderPickerStyle";
        style.textContent = `
          .fmMoveOverlay{
            position:fixed;
            inset:0;
            display:none;
            align-items:center;
            justify-content:center;
            padding:18px;
            background:var(--fm_modal_overlay, rgba(0,0,0,0.55));
            z-index:99999;
          }
          .fmMoveOverlay.show{ display:flex; }

          .fmMoveCard{
            width:min(760px, calc(100vw - 28px));
            max-height:min(760px, calc(100vh - 28px));
            display:flex;
            flex-direction:column;
            overflow:hidden;
            border-radius:18px;
            border:1px solid var(--border, rgba(var(--fg-rgb),0.18));
            background:var(--card, rgba(var(--bg-rgb),0.96));
            color:var(--fg);
            box-shadow:0 24px 70px rgba(0,0,0,0.42);
          }

          .fmMoveHead{
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:12px;
            padding:14px 16px;
            border-bottom:1px solid var(--border2, rgba(var(--fg-rgb),0.12));
            background:rgba(var(--fg-rgb),0.04);
          }
          .fmMoveTitle{ font-weight:950; font-size:17px; }
          .fmMoveSub{ opacity:.72; margin-top:2px; }

          .fmMoveClose{
            border:1px solid var(--border, rgba(var(--fg-rgb),0.18));
            border-radius:12px;
            padding:8px 10px;
            background:rgba(var(--fg-rgb),0.06);
            color:var(--fg);
            cursor:pointer;
          }

          .fmMoveSource{
            padding:10px 16px;
            border-bottom:1px solid var(--border2, rgba(var(--fg-rgb),0.10));
            opacity:.82;
            font-size:13px;
            word-break:break-word;
          }

          .fmMoveBreadcrumb{
            display:flex;
            align-items:center;
            gap:6px;
            flex-wrap:wrap;
            padding:10px 16px;
            border-bottom:1px solid var(--border2, rgba(var(--fg-rgb),0.10));
          }

          .fmMoveCrumb{
            border:1px solid var(--border, rgba(var(--fg-rgb),0.16));
            border-radius:999px;
            padding:6px 10px;
            background:rgba(var(--fg-rgb),0.055);
            color:var(--fg);
            cursor:pointer;
          }
          .fmMoveCrumb.active,
          .fmMoveCrumb:disabled{
            opacity:.72;
            cursor:default;
          }
          .fmMoveSep{ opacity:.55; }

          .fmMoveDirList{
            flex:1 1 auto;
            min-height:220px;
            overflow:auto;
            padding:10px;
          }

          .fmMoveDirRow{
            width:100%;
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:12px;
            text-align:left;
            border:1px solid transparent;
            border-radius:14px;
            padding:11px 12px;
            background:transparent;
            color:var(--fg);
            cursor:pointer;
          }
          .fmMoveDirRow:hover{
            border-color:var(--border, rgba(var(--fg-rgb),0.16));
            background:rgba(var(--fg-rgb),0.06);
          }
          .fmMoveDirRow[aria-disabled="true"],
          .fmMoveDirRow:disabled{
            opacity:.58;
            cursor:default;
          }
          .fmMoveDirName{ font-weight:850; overflow:hidden; text-overflow:ellipsis; }
          .fmMoveDirMeta{ opacity:.65; font-size:12px; white-space:nowrap; }

          .fmMoveStatus{
            padding:9px 16px;
            min-height:34px;
            border-top:1px solid var(--border2, rgba(var(--fg-rgb),0.10));
            opacity:.82;
            font-size:13px;
          }

          .fmMoveActions{
            display:flex;
            justify-content:space-between;
            gap:12px;
            padding:12px 16px 16px;
            border-top:1px solid var(--border2, rgba(var(--fg-rgb),0.10));
          }
          .fmMoveActionGroup{
            display:flex;
            align-items:center;
            gap:10px;
          }

          @media (max-width: 620px){
            .fmMoveActions{
              flex-direction:column;
              align-items:stretch;
            }
            .fmMoveActionGroup{
              justify-content:flex-end;
            }
          }
        `;
        document.head.appendChild(style);
    }

    function ensureModal() {
        ensurePickerCss();
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

        titleEl = overlay.querySelector("#pqFolderPickerTitle");
        subEl = overlay.querySelector("[data-pqfp-sub]");
        sourceEl = overlay.querySelector("[data-pqfp-source]");
        crumbEl = overlay.querySelector("[data-pqfp-breadcrumb]");
        listEl = overlay.querySelector("[data-pqfp-list]");
        statusEl = overlay.querySelector("[data-pqfp-status]");
        chooseBtn = overlay.querySelector("[data-pqfp-choose]");
        newFolderBtn = overlay.querySelector("[data-pqfp-new-folder]");

        overlay.querySelector("[data-pqfp-close]")?.addEventListener("click", () => close(null));
        overlay.querySelector("[data-pqfp-cancel]")?.addEventListener("click", () => close(null));
        chooseBtn?.addEventListener("click", () => {
            const problem = destinationProblem(currentPath);
            if (problem) {
                setStatus(problem);
                renderActionState();
                return;
            }
            close(normalizeRelPath(currentPath));
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

    function renderActionState() {
        const problem = destinationProblem(currentPath);
        const shown = currentPath ? `/${currentPath}` : "/";

        if (chooseBtn) {
            chooseBtn.disabled = busy || !!problem;
            chooseBtn.textContent = opts.chooseLabel || "Choose folder";
            chooseBtn.title = problem || `Choose ${shown}`;
        }

        if (newFolderBtn) {
            newFolderBtn.disabled = busy || !!problem || opts.canCreate === false;
        }

        if (statusEl && !busy) {
            statusEl.textContent = problem || `Destination: ${shown}`;
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

        appendCrumb("My Files", "", parts.length === 0);

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
        renderBreadcrumb();
        setBusy(true);
        setStatus(`Loading /${currentPath || ""}`);

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
        currentPath = normalizeRelPath(opts.initialPath || "");

        if (titleEl) titleEl.textContent = opts.title || "Choose folder";
        if (subEl) subEl.textContent = opts.subtitle || "";
        if (sourceEl) sourceEl.textContent = opts.source ? String(opts.source) : "";

        overlay.classList.add("show");
        overlay.setAttribute("aria-hidden", "false");

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
