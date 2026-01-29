(() => {
  "use strict";

  // ===========================================================================
  // PQ-NAS File Manager (example bundled app)
  //
  // Goals for this app:
  // - Stay small and readable (no frameworks).
  // - Use PQ-NAS Files API endpoints directly:
  //     GET    /api/v4/files/list?path=<rel>
  //     GET    /api/v4/files/get?path=<rel>
  //     POST   /api/v4/files/mkdir?path=<rel>
  //     POST   /api/v4/files/move?from=<rel>&to=<rel>   (rename/move)
  //     DELETE /api/v4/files/delete?path=<rel>          (file or dir recursive)
  // - Provide a good UX baseline: select, double-click open/download, right-click
  //   context menu, long-press menu on touch devices.
  //
  // Notes:
  // - Server does strict path resolution, so this app sends relative paths only.
  // - Client still does basic guardrails (no slashes in names) to prevent mistakes.
  // ===========================================================================

  // If we're inside an iframe, remove extra "window chrome" so we don't get
  // borders-within-borders (PQ-NAS can embed apps inside a desktop shell).
  try {
    if (window.self !== window.top) document.body.classList.add("embedded");
  } catch (_) {
    // Cross-origin iframes can throw here. In PQ-NAS it should be same-origin,
    // but we fail safe and still go "embedded".
    document.body.classList.add("embedded");
  }

  // ----- DOM handles (required) -----
  const gridEl = document.getElementById("grid");
  const pathLine = document.getElementById("pathLine");
  const badge = document.getElementById("badge");
  const status = document.getElementById("status");
  const refreshBtn = document.getElementById("refreshBtn");
  const upBtn = document.getElementById("upBtn");
  const titleLine = document.getElementById("titleLine");

  // Context menu root (optional but expected if you want menus).
  // Your HTML must include:
  //   <div id="ctxMenu" class="ctxMenu" aria-hidden="true"></div>
  const ctxEl = document.getElementById("ctxMenu");

  // ----- State -----
  // curPath is the current directory relative to user storage root.
  // "" means root.
  let curPath = "";

  // selectedKey is stable across reloads:
  //   "dir:<name>" or "file:<name>" for the currently selected item in this folder
  let selectedKey = "";

  // Tracks which item the context menu is open for.
  let ctxOpenForKey = "";

  // Used for long-press menu on touch devices.
  let longPressTimer = null;

  // ----- Small helpers -----
  function detectVersionFromUrl() {
    // Expected app URL pattern:
    //   /apps/<id>/<ver>/www/...
    // We display <ver> in the title to make it obvious which version is running.
    const p = String(location.pathname || "");
    const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
    return m ? m[1] : "";
  }

  const appVer = detectVersionFromUrl();
  if (titleLine && appVer) titleLine.textContent = `File Manager • ${appVer}`;

  function setBadge(kind, text) {
    // kind should match your CSS variants: "ok" | "warn" | "err" (etc)
    badge.className = `badge ${kind}`;
    badge.textContent = text;
  }

  function joinPath(base, name) {
    // Join relative paths without introducing "//".
    if (!base) return name;
    return `${base}/${name}`;
  }

  function parentPath(p) {
    // Return parent directory of a relative path.
    // "" stays "" (already at root).
    if (!p) return "";
    const i = p.lastIndexOf("/");
    if (i < 0) return "";
    return p.slice(0, i);
  }

  function fmtSize(n) {
    // Human-readable sizes for status messages.
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = Number(n || 0);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
  }

  function fmtTime(unix) {
    // Server returns mtime_unix in seconds; show ISO-ish string.
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toISOString().replace("T", " ").replace("Z", "");
  }

  function iconFor(item) {
    // Very simple file extension -> icon mapping.
    // (Icons live inside the app bundle: ./icons/...)
    if (item.type === "dir") return "./icons/folder.png";

    const n = String(item.name || "");
    const dot = n.lastIndexOf(".");
    const ext = (dot >= 0 ? n.slice(dot + 1) : "").toLowerCase();

    if (["txt", "md", "log", "json", "yaml", "yml", "ini", "cfg", "conf"].includes(ext))
      return "./icons/text.png";
    if (["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"].includes(ext))
      return "./icons/cpp.png";
    if (["html", "htm", "css", "js", "mjs", "cjs", "ts", "tsx", "jsx"].includes(ext))
      return "./icons/html.png";
    if (["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico", "tiff"].includes(ext))
      return "./icons/image.png";
    if (["exe", "bin", "run", "appimage", "sh"].includes(ext))
      return "./icons/exe.png";

    return "./icons/file.png";
  }

  function clear() {
    gridEl.innerHTML = "";
  }

  function setSelected(key) {
    // Updates both state and DOM selection styling.
    selectedKey = key;
    for (const el of gridEl.querySelectorAll(".tile")) {
      el.classList.toggle("sel", el.dataset.key === key);
    }
  }

  // ===========================================================================
  // Context menu (right-click and long-press)
  // ===========================================================================

  function closeMenu() {
    if (!ctxEl) return;
    ctxEl.classList.remove("show");
    ctxEl.setAttribute("aria-hidden", "true");
    ctxEl.innerHTML = "";
    ctxOpenForKey = "";
  }

  function clamp(n, lo, hi) {
    return Math.max(lo, Math.min(hi, n));
  }

  function placeMenu(x, y) {
    // Must be visible to measure size.
    ctxEl.style.left = "0px";
    ctxEl.style.top = "0px";
    ctxEl.classList.add("show");

    const rect = ctxEl.getBoundingClientRect();
    const pad = 8;

    // Prevent the menu from going outside the viewport.
    const nx = clamp(x, pad, window.innerWidth - rect.width - pad);
    const ny = clamp(y, pad, window.innerHeight - rect.height - pad);

    ctxEl.style.left = `${nx}px`;
    ctxEl.style.top = `${ny}px`;
  }

  function menuItem(label, rightHint, onClick, opts = {}) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = `ctxItem${opts.danger ? " danger" : ""}`;

    // NOTE: this assumes your ctxItem uses flex with justify-content: space-between.
    b.textContent = label;

    if (rightHint) {
      const r = document.createElement("span");
      r.style.opacity = "0.7";
      r.style.fontWeight = "800";
      r.textContent = rightHint;
      b.appendChild(r);
    }

    b.addEventListener("click", () => {
      closeMenu();
      onClick();
    });

    return b;
  }

  function menuSep() {
    const d = document.createElement("div");
    d.className = "ctxSep";
    return d;
  }

  function currentRelPathFor(item) {
    // Relative path to this item from user root (server expects relative).
    return joinPath(curPath, item.name);
  }

  // ===========================================================================
  // Files API operations
  // ===========================================================================

  function doDownload(item) {
    // Keep current behavior: download by navigating.
    // (Later we can change this to fetch + blob for nicer UX.)
    const p = currentRelPathFor(item);
    window.location.href = `/api/v4/files/get?path=${encodeURIComponent(p)}`;
  }

  async function doRename(item) {
    // Rename implemented using /files/move within the same parent folder.
    const oldRel = currentRelPathFor(item);
    const oldName = String(item.name || "");
    const newName = prompt("Rename to:", oldName);
    if (!newName) return;

    // Client-side safety:
    // - Disallow slash/backslash so this doesn't become a move to another folder.
    // Server is strict anyway, but UX is better if we prevent typos early.
    if (newName.includes("/") || newName.includes("\\")) {
      alert("Name cannot contain '/' or '\\\\'.");
      return;
    }

    const base = parentPath(oldRel);
    const newRel = base ? `${base}/${newName}` : newName;
    if (newRel === oldRel) return;

    setBadge("warn", "working…");
    status.textContent = "Renaming…";

    const url = `/api/v4/files/move?from=${encodeURIComponent(oldRel)}&to=${encodeURIComponent(newRel)}`;
    const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      setBadge("err", "error");
      const msg =
          j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `Rename failed: ${msg}`;
      return;
    }

    status.textContent = "Renamed.";
    setBadge("ok", "ready");
    selectedKey = "";
    await load();
  }

  async function doDelete(item) {
    // Delete uses DELETE /api/v4/files/delete?path=...
    const rel = currentRelPathFor(item);
    const isDir = item.type === "dir";

    const ok = confirm(isDir ? `Delete folder (recursive)?\n\n${rel}` : `Delete file?\n\n${rel}`);
    if (!ok) return;

    setBadge("warn", "working…");
    status.textContent = "Deleting…";

    const url = `/api/v4/files/delete?path=${encodeURIComponent(rel)}`;
    const r = await fetch(url, { method: "DELETE", credentials: "include", cache: "no-store" });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      setBadge("err", "error");
      const msg =
          j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `Delete failed: ${msg}`;
      return;
    }

    // Some endpoints return freed_bytes as a number; show it if available.
    const freed = j && typeof j.freed_bytes === "number" ? ` Freed: ${fmtSize(j.freed_bytes)}` : "";
    status.textContent = `Deleted.${freed}`;
    setBadge("ok", "ready");
    selectedKey = "";
    await load();
  }

  async function doMkdirAt(relDir) {
    // Create folder using:
    //   POST /api/v4/files/mkdir?path=<relative>
    //
    // relDir:
    // - "" means "current folder"
    // - "a/b" means "inside a/b"
    //
    // IMPORTANT: this creates the folder immediately. We keep it simple:
    // - prompt for name
    // - reject slashes
    // - call endpoint
    // - reload listing

    const baseShown = relDir ? `/${relDir}` : curPath ? `/${curPath}` : "/";

    const name = prompt(`New folder name in ${baseShown}:`, "New Folder");
    if (!name) return;

    // Client-side guard: name should be a single path segment.
    if (name.includes("/") || name.includes("\\")) {
      alert("Folder name cannot contain '/' or '\\\\'.");
      return;
    }

    const base = relDir != null ? relDir : curPath;
    const newRel = base ? `${base}/${name}` : name;

    setBadge("warn", "working…");
    status.textContent = "Creating folder…";

    const url = `/api/v4/files/mkdir?path=${encodeURIComponent(newRel)}`;
    const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      setBadge("err", "error");
      const msg =
          j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `mkdir failed: ${msg}`;
      return;
    }

    setBadge("ok", "ready");
    status.textContent = "Folder created.";
    selectedKey = "";
    await load();
  }

  // ===========================================================================
  // Context menu builders
  // ===========================================================================

  function openMenuAt(x, y, item) {
    if (!ctxEl) return;

    // Toggle behavior: if menu already open for the same item, close it.
    const key = `${item.type}:${item.name}`;
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    if (item.type === "dir") {
      ctxEl.appendChild(
          menuItem("Open", "↩", () => {
            curPath = joinPath(curPath, item.name);
            selectedKey = "";
            load();
          })
      );

      // Create folder inside this folder.
      ctxEl.appendChild(
          menuItem("New folder here…", "", () => {
            const relDir = joinPath(curPath, item.name);
            doMkdirAt(relDir);
          })
      );

      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));
    } else {
      ctxEl.appendChild(menuItem("Download", "⤓", () => doDownload(item)));
      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));
    }

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  function openBackgroundMenuAt(x, y) {
    // Right-clicking empty space should provide folder-level actions.
    if (!ctxEl) return;

    // Toggle: if background menu already open, close it.
    const key = "__bg__";
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    ctxEl.appendChild(menuItem("New folder…", "", () => doMkdirAt(curPath)));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Refresh", "", () => load()));

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  // Close menu on outside click / escape / scroll / resize
  document.addEventListener("click", (e) => {
    if (!ctxEl || !ctxEl.classList.contains("show")) return;
    if (e.target === ctxEl || ctxEl.contains(e.target)) return;
    closeMenu();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMenu();
  });

  window.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu);

  function installLongPress(el, item) {
    // Long press for touch/pen:
    // - On pointerdown, start timer
    // - If finger moves (scroll/drag), cancel
    // - If timer fires, open context menu
    el.addEventListener("pointerdown", (e) => {
      if (e.pointerType === "mouse") return; // right-click covers mouse
      clearTimeout(longPressTimer);

      const x = e.clientX;
      const y = e.clientY;

      longPressTimer = setTimeout(() => {
        setSelected(`${item.type}:${item.name}`);
        openMenuAt(x, y, item);
      }, 520);
    });

    const cancel = () => {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    };

    el.addEventListener("pointerup", cancel);
    el.addEventListener("pointercancel", cancel);
    el.addEventListener("pointerleave", cancel);
    el.addEventListener("pointermove", (e) => {
      // If user starts scrolling/dragging, cancel long press.
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 8) cancel();
    });
  }

  // Background menu: only show if user right-clicks empty area.
  gridEl?.addEventListener("contextmenu", (e) => {
    if (e.target && e.target.closest && e.target.closest(".tile")) return;
    e.preventDefault();
    openBackgroundMenuAt(e.clientX, e.clientY);
  });

  // ===========================================================================
  // Tile rendering
  // ===========================================================================

  function tile(item) {
    const key = `${item.type}:${item.name}`;

    const t = document.createElement("div");
    t.className = "tile";
    t.dataset.key = key;

    const img = document.createElement("img");
    img.className = "ico";
    img.alt = "";
    img.src = iconFor(item);

    const nm = document.createElement("div");
    nm.className = "name";
    nm.textContent = item.name || "(unnamed)";

    const meta = document.createElement("div");
    meta.className = "meta";

    const left = document.createElement("span");
    left.textContent = item.type === "dir" ? "dir" : fmtSize(item.size_bytes || 0);

    const right = document.createElement("span");
    right.textContent = fmtTime(item.mtime_unix);

    meta.appendChild(left);
    meta.appendChild(right);

    t.appendChild(img);
    t.appendChild(nm);
    t.appendChild(meta);

    // Single click = select (only visual selection).
    t.addEventListener("click", () => setSelected(key));

    // Right click = context menu.
    t.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      setSelected(key);
      openMenuAt(e.clientX, e.clientY, item);
    });

    // Long press (touch) = context menu.
    installLongPress(t, item);

    // Double click = open:
    // - Directories: enter folder
    // - Files: download
    t.addEventListener("dblclick", () => {
      if (item.type === "dir") {
        curPath = joinPath(curPath, item.name);
        selectedKey = "";
        load();
      } else if (item.type === "file") {
        doDownload(item);
      }
    });

    return t;
  }

  // ===========================================================================
  // Listing loader (GET /api/v4/files/list)
  // ===========================================================================

  async function load() {
    // Always close context menus when reloading.
    closeMenu();

    setBadge("warn", "loading…");
    status.textContent = "Loading…";
    clear();

    try {
      // If curPath is "", server will list the root.
      const url = curPath
          ? `/api/v4/files/list?path=${encodeURIComponent(curPath)}`
          : `/api/v4/files/list`;

      const r = await fetch(url, { credentials: "include", cache: "no-store" });
      const j = await r.json().catch(() => null);

      // The PQ-NAS API style is { ok: true, ... } on success.
      if (!r.ok || !j || !j.ok) {
        setBadge("err", "error");
        status.textContent = `List failed: HTTP ${r.status}`;

        const msg =
            j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : "bad response";

        const err = document.createElement("div");
        err.className = "tile mono";
        err.style.cursor = "default";
        err.textContent = msg;
        gridEl.appendChild(err);
        return;
      }

      // Server can echo the normalized path.
      curPath = typeof j.path === "string" ? j.path : curPath;
      pathLine.textContent = `path: ${curPath ? "/" + curPath : "/"}`;

      setBadge("ok", "ready");

      // Sort: directories first, then files, then by name.
      const items = Array.isArray(j.items) ? j.items.slice() : [];
      items.sort((a, b) => {
        if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
        return String(a.name || "").localeCompare(String(b.name || ""));
      });

      status.textContent = `Items: ${items.length}`;

      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "tile mono";
        empty.style.cursor = "default";
        empty.textContent = "(empty)";
        gridEl.appendChild(empty);
        return;
      }

      for (const it of items) gridEl.appendChild(tile(it));

      // Restore selection highlight if possible.
      if (selectedKey) setSelected(selectedKey);
    } catch (e) {
      setBadge("err", "network");
      status.textContent = "Network error";

      const err = document.createElement("div");
      err.className = "tile mono";
      err.style.cursor = "default";
      err.textContent = String(e && e.stack ? e.stack : e);
      gridEl.appendChild(err);
    }
  }

  // ===========================================================================
  // Navigation buttons
  // ===========================================================================

  refreshBtn?.addEventListener("click", load);

  upBtn?.addEventListener("click", () => {
    curPath = parentPath(curPath);
    selectedKey = "";
    load();
  });

  // Initial load.
  load();
})();
