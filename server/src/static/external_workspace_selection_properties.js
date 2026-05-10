(() => {
    "use strict";

    if (window.__externalWorkspaceSelectionProperties) return;
    window.__externalWorkspaceSelectionProperties = true;

    const params = new URLSearchParams(location.search);
    const workspaceId = String(params.get("workspace_id") || "").trim();

    const MAX_ITEMS = 200;

    function normalizeRelPath(p) {
        let v = String(p || "").trim().replaceAll("\\", "/");
        while (v.startsWith("/")) v = v.slice(1);
        while (v.endsWith("/") && v.length > 1) v = v.slice(0, -1);
        if (v === "." || v === "/") return "";
        return v;
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

    async function apiJson(path) {
        const r = await fetch(path, {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || j.ok !== true) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg);
        }
        return j;
    }

    function statUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath) || ".");
        return `/api/v4/workspaces/files/stat?${qs.toString()}`;
    }

    function selectedRows() {
        return Array.from(document.querySelectorAll("#files .fileRow.selected, #files .fileRow[aria-selected='true']"))
            .filter((row) => row && (row.dataset.file || row.dataset.dir));
    }

    function rowToItem(row) {
        const isDir = !!row.dataset.dir;
        const rel = normalizeRelPath(isDir ? row.dataset.dir : row.dataset.file);
        const name = row.dataset.name || rel.split("/").pop() || "item";

        return {
            rel,
            name,
            isDir,
            size: Number(row.dataset.size || 0),
            mtime: Number(row.dataset.mtime || 0),
            favorite: row.classList.contains("favorite") ||
                row.dataset.favorite === "1" ||
                row.dataset.favorite === "true"
        };
    }

    function selectedItems() {
        return selectedRows().map(rowToItem).filter((it) => it.rel);
    }

    function propsEls() {
        return {
            modal: document.getElementById("propsModal"),
            title: document.getElementById("propsTitle"),
            path: document.getElementById("propsPath"),
            body: document.getElementById("propsBody")
        };
    }

    function addPropsRow(body, k, v) {
        const kEl = document.createElement("div");
        kEl.className = "k";
        kEl.textContent = k;

        const vEl = document.createElement("div");
        vEl.className = "v mono";
        vEl.textContent = v == null ? "" : String(v);

        body.appendChild(kEl);
        body.appendChild(vEl);
    }

    function addRawJson(body, raw) {
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
        pre.textContent = JSON.stringify(raw, null, 2);

        details.appendChild(summary);
        details.appendChild(pre);
        vEl.appendChild(details);

        body.appendChild(kEl);
        body.appendChild(vEl);
    }

    function openPropsModal() {
        const { modal } = propsEls();
        if (!modal) return;
        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");
    }

    function ensureMenuItem() {
        const menu = document.getElementById("selectionContextMenu");
        if (!menu) return;
        if (menu.querySelector('[data-action="multi-properties"]')) return;

        const btn = document.createElement("button");
        btn.type = "button";
        btn.dataset.action = "multi-properties";
        btn.textContent = "Properties...";

        const clearBtn = menu.querySelector('[data-action="multi-clear"]');
        if (clearBtn) {
            const sep = clearBtn.previousElementSibling &&
                clearBtn.previousElementSibling.classList.contains("contextSep")
                    ? clearBtn.previousElementSibling
                    : clearBtn;
            menu.insertBefore(btn, sep);
        } else {
            menu.appendChild(btn);
        }
    }

    async function showSelectionProperties() {
        const items = selectedItems();
        const { modal, title, path, body } = propsEls();

        if (!modal || !body) return;

        if (title) title.textContent = "Selection properties";
        if (path) path.textContent = `${items.length} item(s)`;
        body.innerHTML = "";

        openPropsModal();

        if (!items.length) {
            addPropsRow(body, "Items", "0");
            addPropsRow(body, "Complete", "No");
            return;
        }

        addPropsRow(body, "Items", `${items.length}`);
        addPropsRow(body, "Status", "Scanning selection...");

        let files = 0;
        let folders = 0;
        let favorites = 0;
        let totalBytes = 0;
        let complete = true;
        let errors = 0;
        let dirScanTimeCap = "";
        let dirScanEntryCap = "";

        const raw = {
            workspace_id: workspaceId,
            selected_count: items.length,
            max_items: MAX_ITEMS,
            scanned: []
        };

        const scanItems = items.slice(0, MAX_ITEMS);
        if (items.length > MAX_ITEMS) complete = false;

        for (const item of scanItems) {
            if (item.favorite) favorites++;

            try {
                const st = await apiJson(statUrl(item.rel));
                raw.scanned.push(st);

                const type = String(st.type || (item.isDir ? "dir" : "file")).toLowerCase();
                const isDir = type === "dir" || type === "folder" || item.isDir;

                if (isDir) {
                    folders++;
                    const recursiveBytes = Number(st.bytes_recursive ?? st.recursive_bytes ?? 0);
                    totalBytes += Number.isFinite(recursiveBytes) ? recursiveBytes : 0;

                    if (st.recursive_complete === false) complete = false;

                    if (!dirScanTimeCap && st.time_cap_ms != null) {
                        dirScanTimeCap = `${st.time_cap_ms} ms`;
                    }
                    if (!dirScanEntryCap && st.scan_cap != null) {
                        dirScanEntryCap = String(st.scan_cap);
                    }
                } else {
                    files++;
                    const bytes = Number(st.bytes ?? st.size_bytes ?? item.size ?? 0);
                    totalBytes += Number.isFinite(bytes) ? bytes : 0;
                }
            } catch (e) {
                errors++;
                complete = false;
                raw.scanned.push({
                    path: item.rel,
                    error: String(e && e.message ? e.message : e)
                });

                if (item.isDir) folders++;
                else {
                    files++;
                    totalBytes += Number(item.size || 0);
                }
            }
        }

        body.innerHTML = "";

        addPropsRow(body, "Items", `${items.length}`);
        addPropsRow(body, "Favorites", `${favorites}`);
        addPropsRow(body, "Files", `${files}`);
        addPropsRow(body, "Folders", `${folders}`);
        addPropsRow(body, "Total size", fmtSize(totalBytes));
        addPropsRow(body, "Complete", complete ? "Yes" : "No");
        addPropsRow(body, "Max Items", `${MAX_ITEMS}`);
        addPropsRow(body, "Dir scan time cap", dirScanTimeCap || "—");
        addPropsRow(body, "Dir scan entry cap", dirScanEntryCap || "—");

        if (errors) addPropsRow(body, "Errors", `${errors}`);

        raw.summary = {
            items: items.length,
            favorites,
            files,
            folders,
            total_size_bytes: totalBytes,
            complete,
            errors,
            max_items: MAX_ITEMS,
            dir_scan_time_cap: dirScanTimeCap || null,
            dir_scan_entry_cap: dirScanEntryCap || null
        };

        addRawJson(body, raw);
    }

    ensureMenuItem();

    document.addEventListener("click", (ev) => {
        const btn = ev.target && ev.target.closest
            ? ev.target.closest("#selectionContextMenu [data-action='multi-properties']")
            : null;

        if (!btn || btn.disabled) return;

        ev.preventDefault();
        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();

        const menu = document.getElementById("selectionContextMenu");
        if (menu) menu.classList.add("hidden");

        showSelectionProperties().catch((e) => {
            const { body } = propsEls();
            if (body) {
                body.innerHTML = "";
                addPropsRow(body, "Error", String(e && e.message ? e.message : e));
            }
        });
    }, true);

    const mo = new MutationObserver(ensureMenuItem);
    mo.observe(document.documentElement, { childList: true, subtree: true });
})();
