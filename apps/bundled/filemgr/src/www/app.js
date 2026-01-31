(() => {
  "use strict";

  // ===========================================================================
  // PQ-NAS File Manager (example bundled app)
  //
  // Purpose
  // - Demonstrates how a bundled "static web app" can talk to PQ-NAS via the
  //   Files API using cookie-based sessions (credentials: "include").
  //
  // Files API used:
  //     GET    /api/v4/files/list?path=<rel>             (list directory)
  //     GET    /api/v4/files/get?path=<rel>              (download file)
  //     POST   /api/v4/files/mkdir?path=<rel>            (create directory)
  //     POST   /api/v4/files/move?from=<rel>&to=<rel>    (rename/move)
  //     DELETE /api/v4/files/delete?path=<rel>           (delete file/dir)
  //     PUT    /api/v4/files/put?path=<rel>              (upload/replace)
  //
  // Folder upload:
  // - Picker: <input webkitdirectory> provides File.webkitRelativePath
  // - Drag&Drop (Chromium): DataTransferItem.webkitGetAsEntry() recursion
  //
  // Selection UX:
  // - Single click selects 1 tile
  // - Ctrl/Cmd click toggles tiles
  // - Drag on empty space draws a rectangle (marquee) selecting tiles inside
  // - Ctrl/Cmd + drag adds to existing selection
  //
  // Note
  // - Client-side path checks are ONLY for UX. Server must enforce security.
  // ===========================================================================
  try {
    // If this app is loaded inside an <iframe>, switch to "embedded" layout.
    // (PQ-NAS admin/app host may embed apps in a viewport.)
    if (window.self !== window.top) document.body.classList.add("embedded");
  } catch (_) {
    // If cross-origin framing blocks access to window.top, assume embedded.
    document.body.classList.add("embedded");
  }

  // ---- DOM handles ----------------------------------------------------------
  // Core grid
  const gridEl = document.getElementById("grid");
  const gridWrap = document.getElementById("gridWrap");
  const dropOverlay = document.getElementById("dropOverlay");

  // Top bar / status UI
  const pathLine = document.getElementById("pathLine");
  const badge = document.getElementById("badge");
  const status = document.getElementById("status");
  const refreshBtn = document.getElementById("refreshBtn");
  const upBtn = document.getElementById("upBtn");
  const titleLine = document.getElementById("titleLine");
  const upIcon = document.getElementById("upIcon");

  // (Optional legacy buttons - some versions hide these and use context menu)
  const uploadBtn = document.getElementById("uploadBtn");
  const uploadFolderBtn = document.getElementById("uploadFolderBtn");
  const downloadFolderBtn = document.getElementById("downloadFolderBtn");

  // Hidden file pickers used by "Upload…" actions
  const filePick = document.getElementById("filePick");
  const folderPick = document.getElementById("folderPick");

  // Context menu root element (built dynamically per click)
  const ctxEl = document.getElementById("ctxMenu");

  // Upload progress UI (footer)
  const uploadProg = document.getElementById("uploadProg");
  const uploadProgText = document.getElementById("uploadProgText");
  const uploadProgPct = document.getElementById("uploadProgPct");
  const uploadProgFill = document.getElementById("uploadProgFill");

  // Properties modal UI
  const propsModal = document.getElementById("propsModal");
  const propsClose = document.getElementById("propsClose");
  const propsTitle = document.getElementById("propsTitle");
  const propsPath = document.getElementById("propsPath");
  const propsBody = document.getElementById("propsBody");

  // Share modal UI
  const shareModal = document.getElementById("shareModal");
  const shareClose = document.getElementById("shareClose");
  const shareTitle = document.getElementById("shareTitle");
  const sharePath = document.getElementById("sharePath");
  const shareExpiry = document.getElementById("shareExpiry");
  const shareCreateBtn = document.getElementById("shareCreateBtn");
  const shareOutWrap = document.getElementById("shareOutWrap");
  const shareOut = document.getElementById("shareOut");
  const shareCopyBtn = document.getElementById("shareCopyBtn");
  const shareStatus = document.getElementById("shareStatus");


  // ---- State ----------------------------------------------------------------
  // Current folder path (server-relative, no leading "/"; "" means root).
  let curPath = "";

  // Multi-select: keys are stable within the *current folder listing*:
  // "dir:<name>" or "file:<name>" (name is a single path segment).
  // We intentionally do NOT store full paths here to keep selection stable
  // after reloads in the same directory.
  let selectedKeys = new Set();



  // Share overlay state: path -> count of active shares for that path
  // Paths are server-relative (same as files API), no leading "/".
  let shareCountByPath = new Map();
  let shareTokensByPath = new Map(); // path -> most recent token (best-effort)
  let sharesLoadedAt = 0;
  // Context menu state: used to toggle open/close when right-clicking same item.
  let ctxOpenForKey = "";

  let propsShareTimer = null;

  // Mobile/tablet long-press timer for opening context menu without right-click.
  let longPressTimer = null;

  // ---- Version label (nice for demo bundles) --------------------------------
  // The app can be installed with versioned paths like:
  //   /apps/<appId>/<version>/www/index.html
  // We show the version in the UI title if detected.
  function detectVersionFromUrl() {
    const p = String(location.pathname || "");
    const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
    return m ? m[1] : "";
  }
  const appVer = detectVersionFromUrl();
  if (titleLine && appVer) titleLine.textContent = `File Manager • ${appVer}`;

  // ---- Badge + transient warnings -------------------------------------------
  // Badge: short status pill. kind is one of: ok / warn / err (CSS classes).
  function setBadge(kind, text) {
    badge.className = `badge ${kind}`;
    badge.textContent = text;
  }

  // showTransientWarning() is used for browser quirks / UX hints that should
  // disappear automatically (ex: browser didn't provide files in drag&drop).
  //
  // Behavior:
  // - Does NOT override the "upload…" badge if upload progress UI is visible.
  // - After a timeout, resets back to "ready" (unless uploading is still active).
  let warnTimer = null;

  function showTransientWarning(text, ms = 6000) {
    if (warnTimer) { clearTimeout(warnTimer); warnTimer = null; }

    // Don't stomp upload UI if it's currently visible
    const uploadingNow = uploadProg && uploadProg.style.display !== "none";

    if (!uploadingNow) setBadge("warn", "browser");
    status.textContent = text;

    warnTimer = setTimeout(() => {
      warnTimer = null;

      // Only reset if we're still not uploading
      const stillUploading = uploadProg && uploadProg.style.display !== "none";
      if (!stillUploading) {
        setBadge("ok", "ready");
        status.textContent = "Ready.";
      }
    }, ms);
  }
  // ===========================================================================
  // Shares cache (so we can show "already shared" + badges/menu)
  // Server endpoints:
  //   GET  /api/v4/shares/list   -> { ok:true, shares:[{token,url,path,type,expires_at,downloads,...}] }
  //   POST /api/v4/shares/create -> { ok:true, url:"/s/<token>", token:"...", ... }
  //   POST /api/v4/shares/revoke -> { ok:true }
  // ===========================================================================

  // Map key = "<type>:<path>" -> share obj
  // type is "file" or "dir", path is rel path (no leading "/")
  let sharesByKey = new Map();
  let sharesLoadedOnce = false;

  // ===========================================================================
  // Shares cache (so we can show "already shared" + badges/menu)
  // ===========================================================================

  function shareKey(type, relPath) {
    const t = (type === "dir") ? "dir" : "file";
    const p = String(relPath || "").replace(/^\/+/, "").replace(/\\/g, "/");
    return `${t}:${p}`;
  }

  function existingShareFor(relPath, type) {
    return sharesByKey.get(shareKey(type, relPath)) || null;
  }
  async function refreshSharesCache() {
    try {
      const r = await fetch("/api/v4/shares/list", {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.ok || !Array.isArray(j.shares)) {
        sharesByKey = new Map();
        sharesLoadedOnce = true;
        return;
      }

      const m = new Map();
      for (const s of j.shares) {
        if (!s || typeof s !== "object") continue;
        const k = shareKey(s.type, s.path);
        m.set(k, s);
      }
      sharesByKey = m;
      sharesLoadedOnce = true;
      sharesLoadedAt = Date.now();
    } catch (_) {
      sharesByKey = new Map();
      sharesLoadedOnce = true;
    }
  }

  function shareUrlForToken(token) {
    // If you later add PQNAS_ORIGIN on client, you can make absolute.
    return `${location.origin}/s/${token}`;
  }

  async function createShareForPath(relPath, expiresSec = 0) {
    const r = await fetch("/api/v4/shares/create", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ path: relPath, expires_sec: expiresSec })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      throw new Error(msg || "share create failed");
    }
    return j; // {token,url,...}
  }

  async function revokeShareToken(token) {
    const r = await fetch("/api/v4/shares/revoke", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ token })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error)
          ? `${j.error || ""} ${j.message || ""}`.trim()
          : `HTTP ${r.status}`;
      throw new Error(msg || "share revoke failed");
    }
  }
  function isShareExpired(share) {
    if (!share || !share.expires_at) return false; // no expiry => not expired
    const ms = Date.parse(share.expires_at);
    if (!Number.isFinite(ms)) return false; // fail-open
    return Date.now() >= ms;
  }

  async function copyTextToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      // fallback
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (_) {}
      ta.remove();
      return true;
    }
  }

  // ---- Properties modal helpers ---------------------------------------------
  // Modal shows either single-item properties, or selection summary.
  function openPropsModal() {
    if (!propsModal) return;
    propsModal.classList.add("show");
    propsModal.setAttribute("aria-hidden", "false");
  }

  function closePropsModal() {
    if (propsShareTimer) {
      clearInterval(propsShareTimer);
      propsShareTimer = null;
    }

    if (!propsModal) return;
    propsModal.classList.remove("show");
    propsModal.setAttribute("aria-hidden", "true");
  }

  function openShareModal() {
    if (!shareModal) return;
    shareModal.classList.add("show");
    shareModal.setAttribute("aria-hidden", "false");
  }

  function closeShareModal() {
    if (!shareModal) return;
    shareModal.classList.remove("show");
    shareModal.setAttribute("aria-hidden", "true");
  }

  shareClose?.addEventListener("click", closeShareModal);
  shareModal?.addEventListener("click", (e) => {
    if (e.target === shareModal) closeShareModal();
  });

  // Close button + click-outside-to-close
  propsClose?.addEventListener("click", closePropsModal);
  propsModal?.addEventListener("click", (e) => {
    // click outside card closes
    if (e.target === propsModal) closePropsModal();
  });

  // ---- Theme + icons --------------------------------------------------------
  // PQ-NAS provides global theme tokens; this demo app also swaps icons by theme.
  // - theme.css/theme.js set documentElement[data-theme]
  // - we also mirror theme name in localStorage ("pqnas_theme")
  function getActiveThemeName() {
    const dt = document.documentElement.getAttribute("data-theme") || "";
    if (dt) return dt;
    try { return localStorage.getItem("pqnas_theme") || ""; } catch (_) { return ""; }
  }

  // Icons are packaged in ./icons/ and ./icons/orange/ for CPUNK orange theme.
  function iconBase() {
    const t = String(getActiveThemeName() || "").toLowerCase();
    return (t === "cpunk_orange") ? "./icons/orange/" : "./icons/";
  }

  // Apply theme-specific icons that are not part of each tile.
  function applyIconsNow() {
    if (upIcon) upIcon.src = iconBase() + "updir_small.png";
  }

  applyIconsNow();

  // When PQ-NAS theme changes in another tab, update icons and reload listing.
  window.addEventListener("storage", (e) => {
    if (!e || e.key !== "pqnas_theme") return;
    applyIconsNow();
    load();
  });

  // When returning to the tab, refresh icons (theme might have changed).
  window.addEventListener("focus", () => applyIconsNow());

  // ---- Path helpers ---------------------------------------------------------
  // setPathAndLoad() is the single entry point for changing directories:
  // - updates curPath
  // - clears selection
  // - reloads listing
  function setPathAndLoad(p) {
    curPath = p || "";
    clearSelection();
    load();
  }

  // Render breadcrumb navigation:
  // - root "/" is always present
  // - intermediate crumbs are clickable (to jump back up)
  // - last crumb is "active" and not clickable
  function renderBreadcrumb() {
    if (!pathLine) return;

    pathLine.className = "crumbbar mono";
    pathLine.replaceChildren();

    // Root "/"
    const root = document.createElement("span");
    root.className = "crumb";
    root.textContent = "/";
    root.title = "Go to root";
    root.addEventListener("click", () => setPathAndLoad(""));
    pathLine.appendChild(root);

    if (!curPath) {
      root.classList.add("active");
      return;
    }

    const parts = String(curPath).split("/").filter(Boolean);
    let acc = "";

    for (let i = 0; i < parts.length; i++) {
      const sep = document.createElement("span");
      sep.className = "crumbSep";
      sep.textContent = "›";
      pathLine.appendChild(sep);

      const name = parts[i];
      acc = acc ? `${acc}/${name}` : name;

      const el = document.createElement("span");
      el.className = "crumb";
      if (i === parts.length - 1) el.classList.add("active");

      const txt = document.createElement("span");
      txt.className = "crumbText";
      txt.textContent = name;
      el.appendChild(txt);

      const target = acc;
      el.title = "/" + target;

      if (i !== parts.length - 1) {
        el.addEventListener("click", () => setPathAndLoad(target));
      }

      pathLine.appendChild(el);
    }
  }

  // Join a directory path and a single segment (no leading "/").
  function joinPath(base, name) {
    if (!base) return name;
    return `${base}/${name}`;
  }

  // Parent directory ("" => root). Used for "Up" button.
  function parentPath(p) {
    if (!p) return "";
    const i = p.lastIndexOf("/");
    if (i < 0) return "";
    return p.slice(0, i);
  }

  // Human-friendly file sizes (KiB/MiB/GiB).
  function fmtSize(n) {
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = Number(n || 0);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
  }

  // File list times come from server as epoch seconds (UTC). We show ISO-like.
  function fmtTime(unix) {
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toISOString().replace("T", " ").replace("Z", "");
  }

  // Choose an icon based on item type and file extension.
  // This is intentionally "simple + predictable" for the demo app.
  function iconFor(item) {
    const base = iconBase();
    if (item.type === "dir") return base + "folder.png";

    const n = String(item.name || "");
    const dot = n.lastIndexOf(".");
    const ext = (dot >= 0 ? n.slice(dot + 1) : "").toLowerCase();

    if (["txt","log","json","yaml","yml","ini","cfg","conf","toml","xml"].includes(ext)) return base + "text.png";
    if (["md","markdown"].includes(ext)) return base + "md.png";
    if (["c","cc","cpp","cxx","h","hh","hpp","hxx"].includes(ext)) return base + "cpp.png";
    if (["html","htm","css","js","mjs","cjs","ts","tsx","jsx"].includes(ext)) return base + "html.png";
    if (["png","jpg","jpeg","gif","webp","bmp","svg","ico","tiff"].includes(ext)) return base + "image.png";
    if (["pdf"].includes(ext)) return base + "pdf.png";
    if (["doc","docx"].includes(ext)) return base + "doc.png";
    if (["ppt","pptx"].includes(ext)) return base + "ppt.png";
    if (["xls","xlsx"].includes(ext)) return base + "xls.png";
    if (["rtf"].includes(ext)) return base + "rtf.png";
    if (["mp3","wav","flac","ogg","m4a"].includes(ext)) return base + "mp3.png";
    if (["mp4","mkv","webm"].includes(ext)) return base + "mp4.png";
    if (["mov"].includes(ext)) return base + "mov.png";
    if (["avi"].includes(ext)) return base + "avi.png";
    if (["mpg","mpeg"].includes(ext)) return base + "mpg.png";
    if (["zip","7z","tar","gz","tgz","bz2","xz"].includes(ext)) return base + "zip.png";
    if (["rar"].includes(ext)) return base + "rar.png";
    if (["exe","bin","run","appimage","sh"].includes(ext)) return base + "exe.png";
    return base + "file.png";
  }

  // Clear the tile grid (used before rendering a new listing).
  function clear() { gridEl.innerHTML = ""; }

  // ===========================================================================
  // Selection helpers (multi-select + marquee)
  // ===========================================================================
  // Removes selection styling from all tiles.
  function clearSelectionDom() {
    for (const el of gridEl.querySelectorAll(".tile")) el.classList.remove("sel");
  }

  // Applies current selectedKeys to the tile DOM.
  function applySelectionToDom() {
    for (const el of gridEl.querySelectorAll(".tile")) {
      el.classList.toggle("sel", selectedKeys.has(el.dataset.key));
    }
  }

  // Clears selection state + DOM.
  function clearSelection() {
    selectedKeys.clear();
    clearSelectionDom();
  }

  // Makes selection exactly one item.
  function setSingleSelection(key) {
    selectedKeys = new Set([key]);
    applySelectionToDom();
  }

  // Toggle selection of one item (Ctrl/Cmd click behavior).
  function toggleSelection(key) {
    if (selectedKeys.has(key)) selectedKeys.delete(key);
    else selectedKeys.add(key);
    applySelectionToDom();
  }

  // Ensure an item is selected (used before opening item context menu).
  function ensureSelected(key) {
    if (!selectedKeys.has(key)) setSingleSelection(key);
  }

  // --- Marquee selection -----------------------------------------------------
  // We draw the marquee on <body> (absolute coords) so it overlays the scroll
  // container. Intersection checks use getBoundingClientRect() (viewport coords).
  const marquee = document.createElement("div");
  marquee.style.position = "absolute";
  marquee.style.border = "1px solid rgba(var(--fg-rgb),0.45)";
  marquee.style.background = "rgba(var(--fg-rgb),0.12)";
  marquee.style.borderRadius = "10px";
  marquee.style.pointerEvents = "none";
  marquee.style.display = "none";
  marquee.style.zIndex = "9999";
  document.body.appendChild(marquee);

  let marqueeOn = false;
  let marqueeStartX = 0;
  let marqueeStartY = 0;
  let marqueeBaseSelection = null; // Set() when ctrl/meta used

  // Snapshot current tile rects (key + bounding box).
  function tileRects() {
    const out = [];
    for (const el of gridEl.querySelectorAll(".tile")) {
      out.push({ key: el.dataset.key, rect: el.getBoundingClientRect() });
    }
    return out;
  }

  // Basic rectangle intersection test.
  function rectIntersects(a, b) {
    return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);
  }

  // End marquee mode (hide overlay + clear base selection).
  function endMarquee() {
    if (!marqueeOn) return;
    marqueeOn = false;
    marquee.style.display = "none";
    marqueeBaseSelection = null;
  }

  // Start marquee only when dragging on empty space inside gridWrap.
  // This avoids fighting with tile clicks and context menus.
  gridWrap?.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return; // left only
    if (e.target && e.target.closest && e.target.closest(".tile")) return; // tiles handle clicks
    if (ctxEl && ctxEl.classList.contains("show")) return; // don't start under context menu

    marqueeOn = true;
    marqueeStartX = e.clientX;
    marqueeStartY = e.clientY;

    // Ctrl/Cmd + drag adds to selection; otherwise start fresh.
    marqueeBaseSelection = (e.ctrlKey || e.metaKey) ? new Set(selectedKeys) : null;
    if (!marqueeBaseSelection) clearSelection();

    marquee.style.left = `${marqueeStartX}px`;
    marquee.style.top = `${marqueeStartY}px`;
    marquee.style.width = "0px";
    marquee.style.height = "0px";
    marquee.style.display = "block";

    try { gridWrap.setPointerCapture(e.pointerId); } catch (_) {}
    e.preventDefault();
  });

  // Update marquee rect and selection set as pointer moves.
  gridWrap?.addEventListener("pointermove", (e) => {
    if (!marqueeOn) return;

    const x = e.clientX;
    const y = e.clientY;

    const left = Math.min(marqueeStartX, x);
    const top = Math.min(marqueeStartY, y);
    const right = Math.max(marqueeStartX, x);
    const bottom = Math.max(marqueeStartY, y);

    marquee.style.left = `${left}px`;
    marquee.style.top = `${top}px`;
    marquee.style.width = `${right - left}px`;
    marquee.style.height = `${bottom - top}px`;

    const selRect = { left, top, right, bottom };

    const rects = tileRects();
    const next = marqueeBaseSelection ? new Set(marqueeBaseSelection) : new Set();

    for (const t of rects) {
      if (rectIntersects(selRect, t.rect)) next.add(t.key);
    }

    selectedKeys = next;
    applySelectionToDom();
  });

  gridWrap?.addEventListener("pointerup", endMarquee);
  gridWrap?.addEventListener("pointercancel", endMarquee);

  // If we lose focus mid-drag (alt-tab etc), stop marquee.
  window.addEventListener("blur", endMarquee);

  // ===========================================================================
  // Upload helpers (files + folders)
  // ===========================================================================
  // Overlay makes it obvious where to drop files/folders.
  function showDropOverlay(show) {
    if (!dropOverlay) return;
    dropOverlay.classList.toggle("show", !!show);
    dropOverlay.setAttribute("aria-hidden", show ? "false" : "true");
  }

  // Normalize relative path for uploads:
  // - converts "\" to "/"
  // - strips leading "/"
  // - collapses empty segments
  function normalizeRelPath(rel) {
    rel = String(rel || "").replace(/\\/g, "/");
    rel = rel.replace(/^\/+/, "");
    rel = rel.split("/").filter(Boolean).join("/");
    return rel;
  }

  // Client-side guardrails only (UX).
  // Server still enforces strict path rules (no traversal, no escapes).
  function validateRelPath(rel) {
    const parts = String(rel || "").split("/").filter(Boolean);
    if (!parts.length) return false;
    for (const p of parts) {
      if (p === "." || p === "..") return false;
      if (p.includes("/") || p.includes("\\")) return false;
    }
    return true;
  }

  // Show/hide upload progress block in footer.
  function showUploadProgress(show) {
    if (!uploadProg) return;
    uploadProg.style.display = show ? "block" : "none";
    uploadProg.setAttribute("aria-hidden", show ? "false" : "true");
    if (!show) {
      if (uploadProgFill) uploadProgFill.style.width = "0%";
      if (uploadProgPct) uploadProgPct.textContent = "0%";
      if (uploadProgText) uploadProgText.textContent = "";
    }
  }

  // Delete the current selection (multi-delete):
  // - sequential deletes for predictable UX + simpler server load
  // - shows summary, logs failures to console
  async function deleteSelection() {
    const paths = selectedRelPaths(); // absolute-rel paths (includes curPath prefix)
    if (!paths.length) {
      status.textContent = "Nothing selected.";
      return;
    }

    const ok = confirm(`Delete ${paths.length} item(s)?\n\nThis cannot be undone.`);
    if (!ok) return;

    setBadge("warn", "deleting…");
    status.textContent = `Deleting 0/${paths.length}…`;

    let done = 0;
    let failed = 0;
    const failures = [];

    for (const rel of paths) {
      try {
        const url = `/api/v4/files/delete?path=${encodeURIComponent(rel)}`;
        const r = await fetch(url, { method: "DELETE", credentials: "include", cache: "no-store" });
        const j = await r.json().catch(() => null);

        if (!r.ok || !j || !j.ok) {
          failed++;
          const msg = j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : `HTTP ${r.status}`;
          failures.push(`${rel} — ${msg}`);
        }
      } catch (e) {
        failed++;
        failures.push(`${rel} — ${String(e && e.message ? e.message : e)}`);
      }

      done++;
      status.textContent = `Deleting ${done}/${paths.length}…`;
    }

    clearSelection();

    if (failed > 0) {
      setBadge("err", "partial");
      status.textContent = `Deleted ${paths.length - failed}/${paths.length}. Failed: ${failed}. See console.`;
      console.warn("Multi-delete failures:", failures);
    } else {
      setBadge("ok", "ready");
      status.textContent = `Deleted ${paths.length} item(s).`;
    }

    await load();
  }

  // Update upload progress bar (percent + line of text).
  function setUploadProgress(pct, text) {
    pct = Math.max(0, Math.min(100, Number(pct || 0)));
    if (uploadProgFill) uploadProgFill.style.width = `${pct.toFixed(1)}%`;
    if (uploadProgPct) uploadProgPct.textContent = `${Math.round(pct)}%`;
    if (uploadProgText && text) uploadProgText.textContent = text;
  }

  // Ensure directory path exists before uploading nested files.
  // We create progressively: a/b/c -> mkdir a, mkdir a/b, mkdir a/b/c
  // created is a Set of already attempted dirs (avoid spamming server).
  async function mkdirIfNeeded(relDir, created) {
    if (!relDir) return;
    const norm = normalizeRelPath(relDir);
    if (!norm) return;

    const parts = norm.split("/").filter(Boolean);
    let acc = "";
    for (const part of parts) {
      acc = acc ? `${acc}/${part}` : part;
      const full = curPath ? `${curPath}/${acc}` : acc;
      if (created.has(full)) continue;

      const url = `/api/v4/files/mkdir?path=${encodeURIComponent(full)}`;
      const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
      const j = await r.json().catch(() => null);

      // mkdir may return ok:false if already exists; we still mark as created
      // so we don't retry for every file.
      if (r.ok && j && j.ok) created.add(full);
      else created.add(full);
    }
  }

  // Upload a file with progress reporting.
  // XMLHttpRequest is used because fetch() upload progress isn't widely supported.
  // Server returns JSON {ok:true} on success, and may return quota details.
  function xhrPutFileTo(relPath, file, onProgress) {
    return new Promise((resolve, reject) => {
      const full = curPath ? `${curPath}/${relPath}` : relPath;
      const url = `/api/v4/files/put?path=${encodeURIComponent(full)}`;

      const xhr = new XMLHttpRequest();
      xhr.open("PUT", url, true);
      xhr.withCredentials = true;

      xhr.upload.onprogress = (e) => {
        if (!onProgress) return;
        if (e.lengthComputable) onProgress(e.loaded, e.total);
        else onProgress(e.loaded, file.size || 0);
      };

      xhr.onerror = () => reject(new Error("upload failed (network)"));
      xhr.onabort = () => reject(new Error("upload aborted"));

      xhr.onload = () => {
        let j = null;
        try { j = JSON.parse(xhr.responseText || ""); } catch (_) {}

        if (xhr.status >= 200 && xhr.status < 300 && j && j.ok) {
          resolve(j);
          return;
        }

        // Prefer rich quota message if present
        if (j && j.error === "quota_exceeded") {
          const used = (j.used_bytes != null) ? fmtSize(j.used_bytes) : "?";
          const quota = (j.quota_bytes != null) ? fmtSize(j.quota_bytes) : "?";
          const incoming = (j.incoming_bytes != null) ? fmtSize(j.incoming_bytes) : "?";
          const existing = (j.existing_bytes != null) ? fmtSize(j.existing_bytes) : "?";
          reject(new Error(`Quota exceeded: used ${used} / ${quota}. Upload ${incoming} (replacing ${existing}).`));
          return;
        }

        const msg = (j && (j.message || j.error))
            ? `${j.error || ""} ${j.message || ""}`.trim()
            : `HTTP ${xhr.status}`;

        reject(new Error(msg || "upload failed"));
      };

      xhr.send(file);
    });
  }

  // Upload many files (from picker or drag&drop).
  // - Normalizes & validates each relative path
  // - mkdir() for parent dirs as needed
  // - uploads sequentially to keep server load predictable
  // - progress is computed by total bytes across all files
  async function uploadRelFiles(relFiles) {
    // relFiles: Array<{ rel: string, file: File }>
    if (!relFiles.length) return;

    const created = new Set();

    // Normalize/filter first so totals and progress are correct
    const items = [];
    for (const it of relFiles) {
      const rel = normalizeRelPath(it.rel);
      if (!validateRelPath(rel)) continue; // skip unsafe paths (UX)
      items.push({ rel, file: it.file });
    }

    if (!items.length) {
      setBadge("err", "error");
      status.textContent = "Upload skipped (no valid paths).";
      return;
    }

    const totalFiles = items.length;
    const totalBytes = items.reduce((a, it) => a + (Number(it.file.size) || 0), 0) || 1;

    let doneFiles = 0;
    let uploadedBytesCommitted = 0; // bytes from fully finished files
    let failedFiles = 0;
    const failures = [];
    let lastErrMsg = "";

    showUploadProgress(true);
    setBadge("warn", "upload…");
    setUploadProgress(0, `Uploading 0/${totalFiles}…`);

    for (let idx = 0; idx < items.length; idx++) {
      const { rel, file } = items[idx];

      // Ensure folder exists (for nested uploads)
      const dir = parentPath(rel);
      if (dir) await mkdirIfNeeded(dir, created);

      let lastLoaded = 0;

      try {
        status.textContent = `Uploading: ${rel} (${fmtSize(file.size)})`;

        await xhrPutFileTo(rel, file, (loaded) => {
          // overall = committed bytes + current file loaded bytes
          lastLoaded = Math.max(lastLoaded, loaded || 0);
          const overall = uploadedBytesCommitted + lastLoaded;
          const pct = (overall / totalBytes) * 100;

          setBadge("warn", "upload…");
          setUploadProgress(
              pct,
              `Uploading ${doneFiles}/${totalFiles} • ${rel} • ${fmtSize(overall)} / ${fmtSize(totalBytes)}`
          );
        });

        // File finished => commit full size
        uploadedBytesCommitted += (Number(file.size) || lastLoaded || 0);
        doneFiles++;

        const pct = (uploadedBytesCommitted / totalBytes) * 100;
        setUploadProgress(pct, `Uploaded ${doneFiles}/${totalFiles} • ${rel}`);

      } catch (e) {
        failedFiles++;
        lastErrMsg = String(e && e.message ? e.message : e);
        failures.push({ rel, message: lastErrMsg });

        setBadge("err", "error");
        status.textContent = `Upload failed: ${rel} — ${lastErrMsg}`;

        // Keep progress based only on committed bytes (failed file doesn't count)
        const pct = (uploadedBytesCommitted / totalBytes) * 100;
        setUploadProgress(pct, `Failed ${failedFiles} • Uploaded ${doneFiles}/${totalFiles} • ${rel}`);
      }
    }

    // End state: keep progress visible on errors; auto-hide on clean success.
    if (failedFiles > 0) {
      setBadge("err", "partial");
      const pct = (uploadedBytesCommitted / totalBytes) * 100;
      setUploadProgress(pct, `Upload finished • OK ${doneFiles}/${totalFiles} • Failed ${failedFiles}`);
      status.textContent =
          `Upload finished with errors. OK ${doneFiles}/${totalFiles}, failed ${failedFiles}. ` +
          `Last error: ${lastErrMsg}`;
      console.warn("Upload failures:", failures);
    } else {
      setBadge("ok", "ready");
      setUploadProgress(100, `Upload finished • ${doneFiles}/${totalFiles} files`);
      status.textContent = `Upload finished. Files: ${doneFiles}/${totalFiles}`;
      setTimeout(() => showUploadProgress(false), 900);
    }

    await load();
  }

  // Trigger hidden file picker.
  function pickFiles() {
    if (!filePick) return;
    filePick.value = ""; // allow selecting same file twice
    filePick.click();
  }

  // Trigger hidden folder picker (Chromium + some others).
  function pickFolder() {
    if (!folderPick) return;
    folderPick.value = "";
    folderPick.click();
  }

  // File picker -> upload to current folder
  filePick?.addEventListener("change", async () => {
    const files = Array.from(filePick.files || []);
    const relFiles = files.map(f => ({ rel: f.name, file: f }));
    await uploadRelFiles(relFiles);
    filePick.value = "";
  });

  // Folder picker -> upload preserving folder structure via webkitRelativePath
  folderPick?.addEventListener("change", async () => {
    const files = Array.from(folderPick.files || []);
    const relFiles = files.map(f => ({
      rel: f.webkitRelativePath || f.name,
      file: f
    }));
    await uploadRelFiles(relFiles);
    folderPick.value = "";
  });

  // ===========================================================================
  // Drag & Drop folder recursion (Chromium)
  // ===========================================================================
  // Best-effort check if a DataTransfer likely contains files.
  // (Some browsers are inconsistent during dragenter/dragover.)
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

  // Convert FileSystemEntry (webkitGetAsEntry) to File.
  function readEntryAsFile(entry) {
    return new Promise((resolve) => {
      entry.file((file) => resolve(file), () => resolve(null));
    });
  }

  // Recursively walk a dropped directory (Chromium).
  // prefix tracks current relative directory path within the drop.
  async function walkEntry(entry, prefix, out) {
    if (!entry) return;

    if (entry.isFile) {
      const f = await readEntryAsFile(entry);
      if (f) out.push({ rel: prefix + f.name, file: f });
      return;
    }

    if (entry.isDirectory) {
      const dirReader = entry.createReader();
      const name = entry.name ? (entry.name + "/") : "";
      const nextPrefix = prefix + name;

      // readEntries() returns chunks; loop until empty.
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

  // Normalize a browser drop into our {rel,file} format.
  // - Chromium: use entry API when available (keeps folder structure)
  // - Fallback: plain dt.files (usually no folder structure)
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

    // Fallback: plain files
    const files = Array.from(dt.files || []);
    for (const f of files) out.push({ rel: f.name, file: f });
    return out;
  }

  // dragenter: allow drop + show overlay if possible
  gridWrap?.addEventListener("dragenter", (e) => {
    e.preventDefault(); // ALWAYS allow drop
    if (hasFiles(e.dataTransfer)) showDropOverlay(true);
  });

  // dragover: MUST preventDefault or the browser won't populate drop data
  gridWrap?.addEventListener("dragover", (e) => {
    e.preventDefault(); // CRITICAL
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
    showDropOverlay(true);
  });

  // dragleave: hide overlay when leaving the container
  gridWrap?.addEventListener("dragleave", (e) => {
    if (e.target === gridWrap) showDropOverlay(false);
  });

  // Browser hint (currently unused; keep if you later branch behavior)
  const isFirefox = navigator.userAgent.includes("Firefox");

  // drop:
  // - Prevent browser navigation to dropped file (VERY IMPORTANT)
  // - Convert drop content to upload list
  // - If browser provides no files (quirk/permissions), show a transient warning
  gridWrap?.addEventListener("drop", async (e) => {
    e.preventDefault();
    showDropOverlay(false);

    try {
      const dt = e.dataTransfer;

      // Some browser/platform combinations can produce an empty DataTransfer.
      if (!dt || (!dt.files || dt.files.length === 0)) {
        showTransientWarning(
            "Drag & drop did not provide files. Firefox on Linux may block file drops here — use Upload instead."
        );
        return;
      }

      const relFiles = await collectDroppedFiles(dt);

      if (!relFiles || relFiles.length === 0) {
        setBadge("err", "error");
        status.textContent = "Drop contained no files.";
        return;
      }

      await uploadRelFiles(relFiles);

    } catch (err) {
      setBadge("err", "error");
      status.textContent =
          `Drop upload failed: ${String(err && err.message ? err.message : err)}`;
      console.error("Drop failed:", err);
    }
  });


  // ===========================================================================
  // Context menu / UI
  //
  // Goals:
  // - Right-click (or long-press on touch) opens an item menu.
  // - Right-click on empty background opens a "background" menu:
  //     * If selection exists -> selection actions
  //     * If no selection -> upload / mkdir / download current folder / refresh
  // - Esc closes the properties modal first, then the context menu.
  // - Delete key deletes current selection (like desktop file managers).
  // - Ctrl/Cmd+A selects all visible tiles.
  //
  // Notes:
  // - We keep the menu DOM lightweight: rebuild on open, delete on close.
  // - Menu is positioned/clamped to viewport so it never renders off-screen.
  // ===========================================================================
  function closeMenu() {
    if (!ctxEl) return;
    ctxEl.classList.remove("show");
    ctxEl.setAttribute("aria-hidden", "true");
    ctxEl.innerHTML = "";
    ctxOpenForKey = "";
  }

  // Clamp an integer/float to [lo, hi]
  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

  // Place menu at screen coords (x,y), then clamp so it stays within viewport.
  function placeMenu(x, y) {
    ctxEl.style.left = "0px";
    ctxEl.style.top = "0px";
    ctxEl.classList.add("show");

    const rect = ctxEl.getBoundingClientRect();
    const pad = 8;
    const nx = clamp(x, pad, window.innerWidth - rect.width - pad);
    const ny = clamp(y, pad, window.innerHeight - rect.height - pad);

    ctxEl.style.left = `${nx}px`;
    ctxEl.style.top = `${ny}px`;
  }

  // Create a clickable menu button.
  // - label: left text
  // - rightHint: e.g. shortcut hint (optional)
  // - onClick: callback executed after menu closes
  // - opts.danger: red styling for destructive actions
  function menuItem(label, rightHint, onClick, opts = {}) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = `ctxItem${opts.danger ? " danger" : ""}`;
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

  // Visual separator line inside menu
  function menuSep() {
    const d = document.createElement("div");
    d.className = "ctxSep";
    return d;
  }

  // Build menu with selection-only actions.
  // Used when multiple items are selected (or background click with selection).
  function buildSelectionMenuOnly() {
    if (!ctxEl) return;

    ctxEl.innerHTML = "";
    ctxEl.appendChild(menuItem(`Properties (selection)…`, "", () => showSelectionProperties()));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip()));
    ctxEl.appendChild(menuItem(`Delete selection (${selectedKeys.size})…`, "", () => deleteSelection(), { danger: true }));
  }

  // Convert an item from list view into a rel-path to send to server.
  function currentRelPathFor(item) {
    return joinPath(curPath, item.name);
  }

  // Simple file download via browser navigation to GET endpoint.
  function doDownload(item) {
    const p = currentRelPathFor(item);
    window.location.href = `/api/v4/files/get?path=${encodeURIComponent(p)}`;
  }

  // Download a directory as a server-generated zip (GET endpoint).
  function downloadFolderZip(relDir) {
    // relDir: "" means root/current
    const p = relDir || "";
    // Server endpoint:
    //   GET /api/v4/files/zip?path=<relDir>
    window.location.href = `/api/v4/files/zip?path=${encodeURIComponent(p)}`;
  }

  // Convert selection key ("dir:name" or "file:name") into absolute-rel path.
  // Keys are only valid within the current folder listing.
  function keyToItemRelPath(key) {
    const s = String(key || "");
    const i = s.indexOf(":");
    if (i < 0) return null;
    const name = s.slice(i + 1);
    if (!name) return null;
    return curPath ? `${curPath}/${name}` : name;
  }

  // Show aggregated stats for the current selection using server endpoint:
  //   POST /api/v4/files/stat_sel  { paths: ["rel/a", "rel/b", ...] }
  // This is useful for multi-select where client doesn't know recursive sizes.
  async function showSelectionProperties() {
    const paths = selectedRelPaths();
    if (!paths.length) return;

    if (propsTitle) propsTitle.textContent = `Selection properties`;
    if (propsPath) propsPath.textContent = `${paths.length} item(s)`;
    if (propsBody) propsBody.innerHTML = "";

    // Initial placeholder rows so modal doesn't feel "blank" while loading.
    const rows = [];
    rows.push(["Items", String(paths.length)]);
    rows.push(["Details", "Loading…"]);

    if (propsBody) {
      for (const [k, v] of rows) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    // Fetch aggregated stats from server (counts, bytes, partial scan, errors).
    let st = null;
    try {
      const r = await fetch("/api/v4/files/stat_sel", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ paths })
      });
      st = await r.json().catch(() => null);
    } catch (e) {
      st = { ok: false, error: "client_error", message: String(e && e.message ? e.message : e) };
    }

    if (!propsBody) { openPropsModal(); return; }
    propsBody.innerHTML = "";

    if (!st || !st.ok) {
      const msg = (st && (st.message || st.error))
          ? `${st.error || "error"}: ${st.message || ""}`.trim()
          : "Failed to load selection properties";

      for (const [k, v] of [["Items", String(paths.length)], ["Error", msg]]) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
      openPropsModal();
      return;
    }

    // Helper: append rows only if value exists.
    const pushRow = (arr, k, v) => {
      if (v === undefined || v === null || v === "") return;
      arr.push([k, v]);
    };

    // Render readable summary first.
    const rows2 = [];
    pushRow(rows2, "Items", String(st.count != null ? st.count : paths.length));
    pushRow(rows2, "Files", st.files != null ? String(st.files) : "");
    pushRow(rows2, "Folders", st.dirs != null ? String(st.dirs) : "");
    if (st.other != null && st.other !== 0) pushRow(rows2, "Other", String(st.other));
    if (st.bytes_total != null) pushRow(rows2, "Total size", fmtSize(st.bytes_total));

    if (typeof st.partial === "boolean") {
      pushRow(rows2, "Complete", st.partial ? "No (partial)" : "Yes");
    }

    // Expose server limits if present (helps explain why scan was partial).
    if (st.limits) {
      if (st.limits.max_items != null) pushRow(rows2, "Max items", String(st.limits.max_items));
      if (st.limits.time_cap_ms != null) pushRow(rows2, "Dir scan time cap", `${st.limits.time_cap_ms} ms`);
      if (st.limits.scan_cap != null) pushRow(rows2, "Dir scan entry cap", String(st.limits.scan_cap));
    }

    // Errors summary (full list in Raw JSON below).
    const errCount = Array.isArray(st.errors) ? st.errors.length : 0;
    if (errCount) pushRow(rows2, "Errors", String(errCount));

    // Collapsible Raw JSON for developers (keeps UI clean for normal users).
    const rawDetails = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Raw JSON";
    rawDetails.appendChild(summary);

    const pre = document.createElement("pre");
    pre.className = "pre mono";
    pre.textContent = JSON.stringify(st, null, 2);
    rawDetails.appendChild(pre);

    // Render summary rows
    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    // Add details block spanning full width: append empty key cell + value cell.
    {
      const kEl = document.createElement("div");
      kEl.className = "k";
      kEl.textContent = "";
      const vEl = document.createElement("div");
      vEl.className = "v mono";
      vEl.appendChild(rawDetails);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    openPropsModal();
  }



  function isoUtcToMs(iso) {
    if (!iso) return 0;
    const t = Date.parse(iso); // "2026-01-31T12:34:56Z" -> ms
    return Number.isFinite(t) ? t : 0;
  }

  function fmtCountdown(msLeft) {
    if (msLeft <= 0) return "expired";
    const sec = Math.floor(msLeft / 1000);
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;

    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function fullShareUrl(urlPath) {
    // server returns "/s/<token>"
    if (!urlPath) return "";
    if (urlPath.startsWith("http://") || urlPath.startsWith("https://")) return urlPath;
    return `${window.location.origin}${urlPath}`;
  }


  // Convert selectedKeys to server-usable rel paths (includes curPath prefix).
  // Sorted to keep output stable and user-friendly.
  function selectedRelPaths() {
    const out = [];
    for (const k of selectedKeys) {
      const p = keyToItemRelPath(k);
      if (p) out.push(p);
    }
    out.sort((a, b) => String(a).localeCompare(String(b)));
    return out;
  }

  // Download a zip of the current selection.
  // Uses fetch+Blob because we need to send a JSON body (list of paths).
  // Server endpoint:
  //   POST /api/v4/files/zip_sel
  //   Body: { paths: [...], base: curPath }
  async function downloadSelectionZip() {
    const paths = selectedRelPaths();
    if (!paths.length) {
      status.textContent = "Nothing selected.";
      return;
    }

    setBadge("warn", "zip…");
    status.textContent = `Preparing zip (${paths.length} items)…`;

    const r = await fetch("/api/v4/files/zip_sel", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths, base: curPath })
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      setBadge("err", "error");
      status.textContent = `Zip failed: HTTP ${r.status}${t ? " — " + t : ""}`;
      return;
    }

    const blob = await r.blob();

    // Use server-provided filename if present, otherwise fallback.
    const cd = r.headers.get("Content-Disposition") || "";
    let filename = "pqnas_selection.zip";
    const m = cd.match(/filename="([^"]+)"/i);
    if (m && m[1]) filename = m[1];

    // Trigger download
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    setBadge("ok", "ready");
    status.textContent = `Downloaded: ${filename}`;
  }

  // Rename (move within same directory) using server move endpoint.
  async function doRename(item) {
    const oldRel = currentRelPathFor(item);
    const oldName = String(item.name || "");
    const newName = prompt("Rename to:", oldName);
    if (!newName) return;

    // UX guardrails: disallow path separators in the *name* prompt.
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
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `Rename failed: ${msg}`;
      return;
    }

    status.textContent = "Renamed.";
    setBadge("ok", "ready");
    clearSelection();
    await load();
  }

  // Delete a single file/folder using server delete endpoint.
  async function doDelete(item) {
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
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `Delete failed: ${msg}`;
      return;
    }

    status.textContent = "Deleted.";
    setBadge("ok", "ready");
    clearSelection();
    await load();
  }

  // Create a folder (mkdir) at relDir (or current path).
  async function doMkdirAt(relDir) {
    const baseShown = relDir ? `/${relDir}` : curPath ? `/${curPath}` : "/";
    const name = prompt(`New folder name in ${baseShown}:`, "New Folder");
    if (!name) return;

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
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = `mkdir failed: ${msg}`;
      return;
    }

    setBadge("ok", "ready");
    status.textContent = "Folder created.";
    clearSelection();
    await load();
  }
  function expiresSecFromPreset(v) {
    if (v === "1h") return 3600;
    if (v === "24h") return 86400;
    if (v === "7d") return 7 * 86400;
    return 0; // never
  }
  async function revokeShareToken(token) {
    const r = await fetch("/api/v4/shares/revoke", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ token })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error)
          ? `${j.error || ""} ${j.message || ""}`.trim()
          : `HTTP ${r.status}`;
      throw new Error(msg || "share revoke failed");
    }
  }

  async function createShareLinkFor(relPath, expiresSec) {
    const r = await fetch("/api/v4/shares/create", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ path: relPath, expires_sec: expiresSec })
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error)
          ? `${j.error || ""} ${j.message || ""}`.trim()
          : `HTTP ${r.status}`;
      throw new Error(msg || "share create failed");
    }

    const url = j.url || "";
    if (!url) throw new Error("server did not return url");
    return `${window.location.origin}${url}`;
  }


  async function copyText(s) {
    try {
      await navigator.clipboard.writeText(s);
      return true;
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = s;
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    }
  }

  function openShareDialogFor(item) {
    const rel = currentRelPathFor(item);
    const type = (item.type === "dir") ? "dir" : "file";

    const existing = existingShareFor(rel, type);

    if (shareTitle) shareTitle.textContent = "Share link";
    if (sharePath) sharePath.textContent = "/" + (rel || "");
    if (shareStatus) shareStatus.textContent = "";
    if (shareOutWrap) shareOutWrap.classList.add("hidden");
    if (shareOut) shareOut.value = "";

    // Default expiry = 24h for new shares
    if (shareExpiry) shareExpiry.value = "24h";

    // If already shared -> show link immediately, change primary button to "Re-create"
    if (existing) {
      const full = `${window.location.origin}${existing.url || ("/s/" + (existing.token || ""))}`;
      if (shareOut) shareOut.value = full;
      if (shareOutWrap) shareOutWrap.classList.remove("hidden");

      const exp = existing.expires_at ? ` • expires ${existing.expires_at}` : " • no expiry";
      if (shareStatus) shareStatus.textContent = `Already shared${exp}.`;

      if (shareCreateBtn) shareCreateBtn.textContent = "Create new link (rotate)…";
    } else {
      if (shareCreateBtn) shareCreateBtn.textContent = "Create link";
    }

    if (shareCreateBtn) {
      shareCreateBtn.onclick = async () => {
        try {
          if (shareStatus) shareStatus.textContent = "Creating…";
          const expiresSec = expiresSecFromPreset(shareExpiry ? shareExpiry.value : "24h");

          // If already shared, you might want to rotate by revoking old token first.
          // This is optional; leaving it in gives deterministic UX.
          if (existing && existing.token) {
            try { await revokeShareToken(existing.token); } catch (_) {}
          }

          const link = await createShareLinkFor(rel, expiresSec);

          if (shareOut) shareOut.value = link;
          if (shareOutWrap) shareOutWrap.classList.remove("hidden");
          if (shareStatus) shareStatus.textContent = existing ? "New link created (old revoked)." : "Link created.";

          await refreshSharesCache();
          await load(); // re-render badges if you add them later
        } catch (e) {
          if (shareStatus) shareStatus.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
        }
      };
    }

    if (shareCopyBtn) {
      shareCopyBtn.onclick = async () => {
        const link = shareOut ? shareOut.value : "";
        const ok = link ? await copyText(link) : false;
        if (shareStatus) shareStatus.textContent = ok ? "Copied." : "Copy failed.";
      };
    }

    openShareModal();
  }


  // Open an item context menu at (x,y).
  // Handles selection-mode: if multiple items are selected and the clicked item
  // is within that selection, show selection actions as well.
  function openMenuAt(x, y, item) {
    if (!ctxEl) return;

    // If properties modal is open, close it before showing a menu.
    if (propsModal && propsModal.classList.contains("show")) {
      closePropsModal();
    }

    const key = `${item.type}:${item.name}`;
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    const rel = currentRelPathFor(item);
    const share = existingShareFor(rel, item.type === "dir" ? "dir" : "file");
    const shareLabel = share ? "Shared… (copy/revoke)" : "Share link…";

    // Selection menu mode (multi-select where clicked item is part of selection).
    const selectionMode = (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key));
    if (selectionMode) {
      buildSelectionMenuOnly();
      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    // If multiple are selected and this item is in the selection, offer selection actions.
    if (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key)) {
      ctxEl.appendChild(menuItem(`Properties (selection)…`, "", () => showSelectionProperties()));
      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip()));
      ctxEl.appendChild(menuItem(`Delete selection (${selectedKeys.size})…`, "", () => deleteSelection(), { danger: true }));
      ctxEl.appendChild(menuSep());
    }

    // Directory menu
    if (item.type === "dir") {
      ctxEl.appendChild(menuItem("Open", "↩", () => {
        curPath = joinPath(curPath, item.name);
        clearSelection();
        load();
      }));

      ctxEl.appendChild(menuItem("Download folder (zip)", "", () => {
        const relDir = joinPath(curPath, item.name);
        downloadFolderZip(relDir);
      }));

      // Share (single place; label changes if already shared)
      ctxEl.appendChild(menuItem(shareLabel, "", () => openShareDialogFor(item)));

      ctxEl.appendChild(menuItem("New folder here…", "", () => {
        const relDir = joinPath(curPath, item.name);
        doMkdirAt(relDir);
      }));

      // Properties is single-item only (keeps UI clean when multi-select active).
      if (!(selectedKeys && selectedKeys.size > 1)) {
        ctxEl.appendChild(menuSep());
        ctxEl.appendChild(menuItem("Properties…", "", () => showProperties(item)));
      }

      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));

    } else {
      // File menu
      ctxEl.appendChild(menuItem("Download", "⤓", () => doDownload(item)));

      // Share (single place; label changes if already shared)
      ctxEl.appendChild(menuItem(shareLabel, "", () => openShareDialogFor(item)));

      if (!(selectedKeys && selectedKeys.size > 1)) {
        ctxEl.appendChild(menuSep());
        ctxEl.appendChild(menuItem("Properties…", "", () => showProperties(item)));
      }

      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));
    }

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  // Background menu opens when right-clicking empty space.
  // Behavior:
  // - If selection exists => show selection actions (like desktop file manager)
  // - If no selection => show upload/create/refresh actions
  function openBackgroundMenuAt(x, y) {
    if (!ctxEl) return;

    // If properties modal is open, close it before showing a menu.
    if (propsModal && propsModal.classList.contains("show")) {
      closePropsModal();
    }

    const key = "__bg__";
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    // If there is ANY selection, background menu becomes "selection menu".
    if (selectedKeys && selectedKeys.size > 0) {
      if (selectedKeys.size > 1) {
        buildSelectionMenuOnly();
      } else {
        // Single-select: behave as if user right-clicked that item.
        const onlyKey = Array.from(selectedKeys)[0];
        const p = keyToItemRelPath(onlyKey);
        if (p) {
          const name = p.split("/").pop() || p;
          const type = String(onlyKey).startsWith("dir:") ? "dir" : "file";
          openMenuAt(x, y, { type, name });
          return; // openMenuAt already placed + displayed
        } else {
          buildSelectionMenuOnly();
        }
      }

      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    // No selection: "background" actions.
    ctxEl.appendChild(menuItem("Upload files…", "", () => pickFiles()));
    ctxEl.appendChild(menuItem("Upload folder…", "", () => pickFolder()));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Download current folder (zip)", "", () => downloadFolderZip(curPath)));
    // NOTE: No "Share link…" here because there is no single item in background context.
    ctxEl.appendChild(menuItem("New folder…", "", () => doMkdirAt(curPath)));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Refresh", "", () => load()));

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  // Click outside menu closes it (normal desktop menu behavior).
  document.addEventListener("click", (e) => {
    if (!ctxEl || !ctxEl.classList.contains("show")) return;
    if (e.target === ctxEl || ctxEl.contains(e.target)) return;
    closeMenu();
  });

  // Keyboard shortcuts:
  // - Esc: close modal first, then menu
  // - Delete: delete selection
  // - Ctrl/Cmd+A: select all
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (shareModal && shareModal.classList.contains("show")) {
        closeShareModal();
        return;
      }
      if (propsModal && propsModal.classList.contains("show")) {
        closePropsModal();
        return;
      }
      closeMenu();
      return;
    }

    if (e.key === "Delete" && selectedKeys && selectedKeys.size > 0) {
      e.preventDefault();
      deleteSelection();
      return;
    }

    if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === "a") {
      e.preventDefault();
      selectedKeys = new Set(
          Array.from(gridEl.querySelectorAll(".tile")).map(el => el.dataset.key)
      );
      applySelectionToDom();
      status.textContent = `Selected: ${selectedKeys.size}`;
    }
  });


  // If the page scrolls or resizes, hide menu (avoids awkward floating menu).
  window.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu);

  // Long-press support (touch):
  // - On touch pointerdown, start a timer.
  // - If still pressed after ~520ms, open the item menu.
  // - Any movement/cancel ends the timer.
  function installLongPress(el, item) {
    el.addEventListener("pointerdown", (e) => {
      if (e.pointerType === "mouse") return;
      clearTimeout(longPressTimer);

      const x = e.clientX;
      const y = e.clientY;

      longPressTimer = setTimeout(() => {
        setSingleSelection(`${item.type}:${item.name}`);
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
      // Cancel if finger moves significantly (treat as scroll/drag).
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 8) cancel();
    });
  }

  /*
    downloadFolderBtn?.addEventListener("click", () => {
      // Download the *current* directory as zip
      downloadFolderZip(curPath);
    });
  */

  // Right-click on empty grid area opens background menu.
  gridEl?.addEventListener("contextmenu", (e) => {
    if (e.target && e.target.closest && e.target.closest(".tile")) return;
    e.preventDefault();
    openBackgroundMenuAt(e.clientX, e.clientY);
  });

  // ===========================================================================
  // Tile rendering + per-item interactions
  // ===========================================================================
  function tile(item) {
    const key = `${item.type}:${item.name}`;

    const t = document.createElement("div");
    t.className = "tile";
    t.dataset.key = key;

    // Icon
    const img = document.createElement("img");
    img.className = "ico";
    img.alt = "";
    img.src = iconFor(item);

    // Name (one-line ellipsis)
    const nm = document.createElement("div");
    nm.className = "name";
    nm.textContent = item.name || "(unnamed)";

    // Meta line: size/dir + mtime
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

    // ---- Shared badge overlay (top-right) ----
    try {
      const rel = currentRelPathFor(item);
      const type = (item.type === "dir") ? "dir" : "file";
      const share = existingShareFor(rel, type);

      if (share) {
        const expired = isShareExpired(share);

        const b = document.createElement("div");
        b.className = "shareBadge" + (expired ? " expired" : "");
        b.title = expired ? "Share link expired" : "Shared";
        b.textContent = expired ? "⏰" : "🔗";

        t.appendChild(b);
      }
    } catch (_) {}


    // Single click selection:
    // - Ctrl/Cmd toggles
    // - plain click selects only this item
    t.addEventListener("click", (e) => {
      if (marqueeOn) return; // ignore accidental click after marquee drag
      if (e.ctrlKey || e.metaKey) toggleSelection(key);
      else setSingleSelection(key);
    });

    // Right click: ensure item is selected, then show menu.
    t.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      ensureSelected(key);
      openMenuAt(e.clientX, e.clientY, item);
    });

    // Touch long-press: open menu.
    installLongPress(t, item);

    // Double click:
    // - dir: enter folder
    // - file: download
    t.addEventListener("dblclick", () => {
      if (item.type === "dir") {
        curPath = joinPath(curPath, item.name);
        clearSelection();
        load();
      } else if (item.type === "file") {
        doDownload(item);
      }
    });

    return t;
  }

  // Key/Value row builder for properties modal.
  function kvRow(k, v) {
    const kEl = document.createElement("div");
    kEl.className = "k";
    kEl.textContent = k;

    const vEl = document.createElement("div");
    vEl.className = "v mono";
    vEl.textContent = v == null ? "" : String(v);

    return [kEl, vEl];
  }



  // Show single-item properties:
  // - Render fast info from list() immediately
  // - Then POST /api/v4/files/stat to get authoritative details
  // - Finally render a clean summary + optional Raw JSON
  async function showProperties(item) {
    if (!item) return;

    // Stop any previous countdown timer for Properties modal
    if (propsShareTimer) {
      clearInterval(propsShareTimer);
      propsShareTimer = null;
    }

    const rel = joinPath(curPath, item.name || "");
    const isDirHint = item.type === "dir";

    if (propsTitle) propsTitle.textContent = isDirHint ? "Folder properties" : "File properties";
    if (propsPath) propsPath.textContent = "/" + (rel || "");

    if (propsBody) propsBody.innerHTML = "";

    // --- helpers local to this function ---
    const pad2 = (n) => String(n).padStart(2, "0");

    // Server returns epoch seconds; show local time for user friendliness.
    const fmtUnix = (sec) => {
      if (!sec) return "";
      const d = new Date(Number(sec) * 1000);
      if (isNaN(d.getTime())) return String(sec);
      return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    };

    // Convert octal mode (e.g. "0664") to rwx string (e.g. "rw-rw-r--").
    const permsFromOctal = (modeStr) => {
      if (!modeStr || typeof modeStr !== "string") return "";
      const s = modeStr.trim();
      if (!/^[0-7]{3,4}$/.test(s)) return "";
      const oct = s.length === 4 ? s.slice(1) : s; // ignore special leading digit if present
      const bits = oct.split("").map((c) => parseInt(c, 8));
      if (bits.length !== 3 || bits.some((x) => Number.isNaN(x))) return "";

      const rwx = (b) => {
        const r = (b & 4) ? "r" : "-";
        const w = (b & 2) ? "w" : "-";
        const x = (b & 1) ? "x" : "-";
        return r + w + x;
      };
      return rwx(bits[0]) + rwx(bits[1]) + rwx(bits[2]);
    };
    const isoUtcToMs = (iso) => {
      if (!iso || typeof iso !== "string") return null;
      // expected "YYYY-MM-DDTHH:MM:SSZ"
      const ms = Date.parse(iso);
      return Number.isFinite(ms) ? ms : null;
    };

    const fmtCountdown = (msLeft) => {
      if (msLeft == null) return "";
      if (msLeft <= 0) return "Expired";
      const s = Math.floor(msLeft / 1000);
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      const se = s % 60;
      if (d > 0) return `${d}d ${pad2(h)}:${pad2(m)}:${pad2(se)}`;
      return `${pad2(h)}:${pad2(m)}:${pad2(se)}`;
    };

    const pushRow = (rows, k, v) => {
      if (v === undefined || v === null || v === "") return;
      rows.push([k, v]);
    };

    // --- initial render from list() item (fast) ---
    const rows = [];
    pushRow(rows, "Name", item.name || "");
    pushRow(rows, "Type", isDirHint ? "Folder" : "File");
    pushRow(rows, "Path", "/" + (rel || ""));

    // list() is a hint; stat() is authoritative
    if (!isDirHint && item.size_bytes != null) pushRow(rows, "Size", fmtSize(item.size_bytes || 0));
    if (item.mtime_unix) pushRow(rows, "Modified", fmtTime(item.mtime_unix));
    rows.push(["Details", "Loading…"]);

    if (propsBody) {
      for (const [k, v] of rows) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    // --- fetch stat() from server ---
    let st = null;
    try {
      const qs = new URLSearchParams();
      // Use "." for root; otherwise use rel (already relative, no leading slash).
      qs.set("path", rel ? rel : ".");
      const r = await fetch(`/api/v4/files/stat?${qs.toString()}`, {
        method: "POST",
        credentials: "include",
        headers: { "Accept": "application/json" }
      });
      st = await r.json();
    } catch (e) {
      st = { ok: false, error: "client_error", message: String(e) };
    }

    // --- render authoritative result ---
    if (!propsBody) {
      openPropsModal?.();
      return;
    }

    propsBody.innerHTML = "";

    if (!st || !st.ok) {
      const msg = (st && (st.message || st.error))
          ? `${st.error || "error"}: ${st.message || ""}`.trim()
          : "Failed to load properties";

      for (const [k, v] of [["Name", item.name || ""], ["Path", "/" + (rel || "")], ["Error", msg]]) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
      openPropsModal?.();
      return;
    }

    const isDir = st.type === "dir";
    if (propsTitle) propsTitle.textContent = isDir ? "Folder properties" : (st.type === "file" ? "File properties" : "Item properties");
    if (propsPath) propsPath.textContent = st.path_norm || ("/" + (rel || ""));

    const rows2 = [];
    pushRow(rows2, "Name", st.name || "");
    pushRow(rows2, "Type", st.type === "dir" ? "Folder" : (st.type === "file" ? "File" : "Other"));
    pushRow(rows2, "Path", st.path_norm || ("/" + (rel || "")));

    // Permissions/owner/mode
    if (st.mode_octal) {
      const rwx = permsFromOctal(st.mode_octal);
      pushRow(rows2, "Permissions", rwx ? `${st.mode_octal} (${rwx})` : st.mode_octal);
    }

    // Time
    if (st.mtime_epoch) pushRow(rows2, "Modified", fmtUnix(st.mtime_epoch));

    // File-specific fields
    if (st.type === "file") {
      if (st.bytes != null) pushRow(rows2, "Size", fmtSize(st.bytes));
      if (st.mime) pushRow(rows2, "MIME", st.mime);
      if (typeof st.is_text === "boolean") pushRow(rows2, "Looks like text", st.is_text ? "Yes" : "No");
    }

    // Dir-specific fields (recursive scan may be partial/limited)
    if (st.type === "dir") {
      if (st.children) {
        const c = st.children;
        const parts = [];
        if (c.files != null) parts.push(`${c.files} files`);
        if (c.dirs != null) parts.push(`${c.dirs} folders`);
        if (c.other != null && c.other !== 0) parts.push(`${c.other} other`);
        pushRow(rows2, "Children", parts.join(", "));
      }
      if (st.bytes_recursive != null) pushRow(rows2, "Size (recursive)", fmtSize(st.bytes_recursive));
      if (st.recursive_scanned_entries != null) pushRow(rows2, "Scanned entries", String(st.recursive_scanned_entries));
      if (typeof st.recursive_complete === "boolean") pushRow(rows2, "Scan complete", st.recursive_complete ? "Yes" : "No");
    }

    // Render readable rows
    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }
// -------------------------------------------------------------------------
// Share info (from cache), with expiry countdown + copy/revoke actions
// -------------------------------------------------------------------------
    {
      // NOTE: rel has no leading "/" by construction (joinPath)
      const type = (item.type === "dir") ? "dir" : "file";
      const share = existingShareFor(rel, type);

      // Title row
      {
        const [kEl, vEl] = kvRow("Share", "");
        vEl.classList.remove("mono");
        vEl.innerHTML = "";
        vEl.style.display = "flex";
        vEl.style.flexDirection = "column";
        vEl.style.gap = "8px";

        const topLine = document.createElement("div");
        topLine.textContent = share ? "Shared" : "Not shared";
        topLine.style.opacity = "0.92";

        vEl.appendChild(topLine);

        if (share) {
          const fullUrl = `${window.location.origin}${share.url || ("/s/" + (share.token || ""))}`;

          // URL (readonly)
          const urlRow = document.createElement("div");
          urlRow.style.display = "flex";
          urlRow.style.gap = "8px";
          urlRow.style.alignItems = "center";

          const inp = document.createElement("input");
          inp.type = "text";
          inp.value = fullUrl;
          inp.readOnly = true;
          inp.style.flex = "1";
          inp.style.minWidth = "0";

          const btnCopy = document.createElement("button");
          btnCopy.type = "button";
          btnCopy.textContent = "Copy";
          btnCopy.onclick = async () => {
            const ok = await copyText(fullUrl);
            btnCopy.textContent = ok ? "Copied" : "Copy failed";
            setTimeout(() => (btnCopy.textContent = "Copy"), 1200);
          };

          urlRow.appendChild(inp);
          urlRow.appendChild(btnCopy);

          // Expiry + countdown
          const expLine = document.createElement("div");
          expLine.style.display = "flex";
          expLine.style.gap = "10px";
          expLine.style.flexWrap = "wrap";
          expLine.style.opacity = "0.92";

          const expAt = share.expires_at || "";
          const expMs = isoUtcToMs(expAt);

          const expLabel = document.createElement("span");
          expLabel.textContent = expAt ? `Expires: ${expAt}` : "Expires: never";

          const cdLabel = document.createElement("span");
          cdLabel.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
          cdLabel.style.opacity = "0.95";

          const updateCountdown = () => {
            if (!expMs) {
              cdLabel.textContent = ""; // no countdown if never
              return;
            }
            const left = expMs - Date.now();
            cdLabel.textContent = `Remaining: ${fmtCountdown(left)}`;
          };
          updateCountdown();

          // Only start timer if exp exists (otherwise pointless)
          if (expMs) {
            propsShareTimer = setInterval(updateCountdown, 1000);
          }

          expLine.appendChild(expLabel);
          expLine.appendChild(cdLabel);

          // Downloads (if present)
          const dl = document.createElement("div");
          dl.style.opacity = "0.85";
          if (share.downloads != null) dl.textContent = `Downloads: ${share.downloads}`;

          // Revoke
          const actions = document.createElement("div");
          actions.style.display = "flex";
          actions.style.gap = "8px";
          actions.style.alignItems = "center";

          const btnRevoke = document.createElement("button");
          btnRevoke.type = "button";
          btnRevoke.textContent = "Revoke";
          btnRevoke.onclick = async () => {
            const ok = confirm("Revoke this share link?\n\nThis will invalidate the URL immediately.");
            if (!ok) return;

            btnRevoke.disabled = true;
            btnRevoke.textContent = "Revoking…";

            try {
              const r = await fetch("/api/v4/shares/revoke", {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ token: share.token })
              });
              const j = await r.json().catch(() => null);
              if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || "revoke failed");
              }

              // refresh cache + refresh properties view
              await refreshSharesCache();
              await showProperties(item);
              return;

            } catch (e) {
              btnRevoke.textContent = "Revoke failed";
              setTimeout(() => {
                btnRevoke.textContent = "Revoke";
                btnRevoke.disabled = false;
              }, 1400);
              return;
            }
          };

          actions.appendChild(btnRevoke);

          vEl.appendChild(urlRow);
          vEl.appendChild(expLine);
          if (share.downloads != null) vEl.appendChild(dl);
          vEl.appendChild(actions);
        } else {
          // Not shared: offer create shortcut
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = "Create share link…";
          btn.onclick = () => openShareDialogFor(item);
          vEl.appendChild(btn);
        }

        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    // Collapsible Raw JSON (developer-friendly, not noisy)
    {
      const [kEl, vEl] = kvRow("Details", "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";

      const details = document.createElement("details");
      details.style.width = "100%";

      const summary = document.createElement("summary");
      summary.textContent = "Raw JSON";
      summary.style.cursor = "pointer";
      summary.style.userSelect = "none";

      const pre = document.createElement("pre");
      pre.className = "mono pre";
      pre.style.margin = "10px 0 0 0";
      pre.style.whiteSpace = "pre-wrap";
      pre.style.wordBreak = "break-word";
      pre.textContent = JSON.stringify(st, null, 2);

      details.appendChild(summary);
      details.appendChild(pre);

      vEl.appendChild(details);

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    openPropsModal?.();
  }

  // ===========================================================================
  // Directory listing / render
  // ===========================================================================
  async function load() {
    closeMenu();
    setBadge("warn", "loading…");
    status.textContent = "Loading…";
    clear();
    await refreshSharesCache();

    try {
      // /list at root takes no query param; subfolders use ?path=<rel>
      const url = curPath
          ? `/api/v4/files/list?path=${encodeURIComponent(curPath)}`
          : `/api/v4/files/list`;

      const r = await fetch(url, { credentials: "include", cache: "no-store" });
      const j = await r.json().catch(() => null);

      if (!r.ok || !j || !j.ok) {
        setBadge("err", "error");
        status.textContent = `List failed: HTTP ${r.status}`;

        const msg = j && (j.message || j.error)
            ? `${j.error || ""} ${j.message || ""}`.trim()
            : "bad response";

        // Render an error tile (keeps UI consistent and visible)
        const err = document.createElement("div");
        err.className = "tile mono";
        err.style.cursor = "default";
        err.textContent = msg;
        gridEl.appendChild(err);
        return;
      }

      // Server echoes canonical path; trust it (stays in sync with server rules)
      curPath = typeof j.path === "string" ? j.path : curPath;
      renderBreadcrumb();

      setBadge("ok", "ready");

      // Sort folders first, then alphabetical
      const items = Array.isArray(j.items) ? j.items.slice() : [];
      items.sort((a, b) => {
        if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
        return String(a.name || "").localeCompare(String(b.name || ""));
      });

      status.textContent = `Items: ${items.length}`;

      // Friendly empty state
      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "tile mono";
        empty.style.cursor = "default";
        empty.textContent = "(empty)\n\nTip: drag & drop files/folders here to upload.";
        gridEl.appendChild(empty);
        return;
      }

      // Render tiles
      for (const it of items) gridEl.appendChild(tile(it));

      // Restore selection highlights (keys are stable per folder listing)
      applySelectionToDom();

    } catch (e) {
      // Network/unexpected errors: show a "network" badge and a diagnostic tile
      setBadge("err", "network");
      status.textContent = "Network error";

      const err = document.createElement("div");
      err.className = "tile mono";
      err.style.cursor = "default";
      err.textContent = String(e && e.stack ? e.stack : e);
      gridEl.appendChild(err);
    }
  }

  // Toolbar hooks
  refreshBtn?.addEventListener("click", load);
  upBtn?.addEventListener("click", () => {
    curPath = parentPath(curPath);
    clearSelection();
    load();
  });

  // Initial load on startup
  load();
})();
