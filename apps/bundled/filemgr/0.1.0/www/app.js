(() => {
  "use strict";

  // ===========================================================================
  // PQ-NAS File Manager (example bundled app)
  //
  // Files API used:
  //     GET    /api/v4/files/list?path=<rel>
  //     GET    /api/v4/files/get?path=<rel>
  //     POST   /api/v4/files/mkdir?path=<rel>
  //     POST   /api/v4/files/move?from=<rel>&to=<rel>
  //     DELETE /api/v4/files/delete?path=<rel>
  //     PUT    /api/v4/files/put?path=<rel>             (upload)
  //
  // Folder upload:
  // - Picker: <input webkitdirectory> provides File.webkitRelativePath
  // - Drag&Drop (Chromium): DataTransferItem.webkitGetAsEntry() recursion
  //
  // Selection:
  // - Single click selects 1 tile
  // - Ctrl/Cmd click toggles tiles
  // - Drag on empty space draws a rectangle (marquee) selecting tiles inside
  // - Ctrl/Cmd + drag adds to existing selection
  // ===========================================================================
  try {
    if (window.self !== window.top) document.body.classList.add("embedded");
  } catch (_) {
    document.body.classList.add("embedded");
  }

  const gridEl = document.getElementById("grid");
  const gridWrap = document.getElementById("gridWrap");
  const dropOverlay = document.getElementById("dropOverlay");

  const pathLine = document.getElementById("pathLine");
  const badge = document.getElementById("badge");
  const status = document.getElementById("status");
  const refreshBtn = document.getElementById("refreshBtn");
  const upBtn = document.getElementById("upBtn");
  const titleLine = document.getElementById("titleLine");
  const upIcon = document.getElementById("upIcon");

  const uploadBtn = document.getElementById("uploadBtn");
  const uploadFolderBtn = document.getElementById("uploadFolderBtn");
  const downloadFolderBtn = document.getElementById("downloadFolderBtn");

  const filePick = document.getElementById("filePick");
  const folderPick = document.getElementById("folderPick");

  const ctxEl = document.getElementById("ctxMenu");

  let curPath = "";
  // Multi-select: keys are stable within the *current folder listing*:
  // "dir:<name>" or "file:<name>" (name is a single path segment).
  let selectedKeys = new Set();
  let ctxOpenForKey = "";
  let longPressTimer = null;

  function detectVersionFromUrl() {
    const p = String(location.pathname || "");
    const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
    return m ? m[1] : "";
  }
  const appVer = detectVersionFromUrl();
  if (titleLine && appVer) titleLine.textContent = `File Manager • ${appVer}`;

  function setBadge(kind, text) {
    badge.className = `badge ${kind}`;
    badge.textContent = text;
  }

  // ---- Theme + icons --------------------------------------------------------
  function getActiveThemeName() {
    const dt = document.documentElement.getAttribute("data-theme") || "";
    if (dt) return dt;
    try { return localStorage.getItem("pqnas_theme") || ""; } catch (_) { return ""; }
  }
  function iconBase() {
    const t = String(getActiveThemeName() || "").toLowerCase();
    return (t === "cpunk_orange") ? "./icons/orange/" : "./icons/";
  }
  function applyIconsNow() {
    if (upIcon) upIcon.src = iconBase() + "updir_small.png";
  }
  applyIconsNow();
  window.addEventListener("storage", (e) => {
    if (!e || e.key !== "pqnas_theme") return;
    applyIconsNow();
    load();
  });
  window.addEventListener("focus", () => applyIconsNow());

  // ---- path utils -----------------------------------------------------------
  function joinPath(base, name) {
    if (!base) return name;
    return `${base}/${name}`;
  }
  function parentPath(p) {
    if (!p) return "";
    const i = p.lastIndexOf("/");
    if (i < 0) return "";
    return p.slice(0, i);
  }
  function fmtSize(n) {
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = Number(n || 0);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
  }

  function fmtTime(unix) {
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toISOString().replace("T", " ").replace("Z", "");
  }

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

  function clear() { gridEl.innerHTML = ""; }

  // ---- Selection helpers (multi-select + marquee) ----------------------------
  function clearSelectionDom() {
    for (const el of gridEl.querySelectorAll(".tile")) el.classList.remove("sel");
  }

  function applySelectionToDom() {
    for (const el of gridEl.querySelectorAll(".tile")) {
      el.classList.toggle("sel", selectedKeys.has(el.dataset.key));
    }
  }

  function clearSelection() {
    selectedKeys.clear();
    clearSelectionDom();
  }

  function setSingleSelection(key) {
    selectedKeys = new Set([key]);
    applySelectionToDom();
  }

  function toggleSelection(key) {
    if (selectedKeys.has(key)) selectedKeys.delete(key);
    else selectedKeys.add(key);
    applySelectionToDom();
  }

  function ensureSelected(key) {
    if (!selectedKeys.has(key)) setSingleSelection(key);
  }

  // Marquee rectangle (viewport-based):
  // We draw it on <body> so it can overlay the scroll container. Selection uses
  // getBoundingClientRect() so everything stays in the same coordinate space.
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

  function tileRects() {
    const out = [];
    for (const el of gridEl.querySelectorAll(".tile")) {
      out.push({ key: el.dataset.key, rect: el.getBoundingClientRect() });
    }
    return out;
  }

  function rectIntersects(a, b) {
    return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);
  }

  function endMarquee() {
    if (!marqueeOn) return;
    marqueeOn = false;
    marquee.style.display = "none";
    marqueeBaseSelection = null;
  }

  // Start marquee only when dragging on empty space inside gridWrap
  gridWrap?.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return; // left only
    if (e.target && e.target.closest && e.target.closest(".tile")) return; // tiles handle clicks
    // Don't start marquee if context menu open (rare but safe)
    if (ctxEl && ctxEl.classList.contains("show")) return;

    marqueeOn = true;
    marqueeStartX = e.clientX;
    marqueeStartY = e.clientY;

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

  // If we lose focus mid-drag, stop marquee
  window.addEventListener("blur", endMarquee);

  // ===========================================================================
  // Upload helpers (files + folders)
  // ===========================================================================
  function showDropOverlay(show) {
    if (!dropOverlay) return;
    dropOverlay.classList.toggle("show", !!show);
    dropOverlay.setAttribute("aria-hidden", show ? "false" : "true");
  }

  function normalizeRelPath(rel) {
    // Normalize to forward slashes; strip leading slashes.
    rel = String(rel || "").replace(/\\/g, "/");
    rel = rel.replace(/^\/+/, "");
    // Remove empty segments.
    rel = rel.split("/").filter(Boolean).join("/");
    return rel;
  }

  // Client-side guardrails only (UX). Server still enforces strict path rules.
  function validateRelPath(rel) {
    // Reject traversal / weird segments
    const parts = String(rel || "").split("/").filter(Boolean);
    if (!parts.length) return false;
    for (const p of parts) {
      if (p === "." || p === "..") return false;
      if (p.includes("/") || p.includes("\\")) return false;
    }
    return true;
  }

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

      // mkdir might fail if already exists; tolerate that.
      if (r.ok && j && j.ok) {
        created.add(full);
      } else {
        // If server returns ok:false but folder exists, next steps may still succeed.
        created.add(full);
      }
    }
  }

  async function putFileTo(relPath, file) {
    const full = curPath ? `${curPath}/${relPath}` : relPath;

    setBadge("warn", "upload…");
    status.textContent = `Uploading: ${relPath} (${fmtSize(file.size)})`;

    const url = `/api/v4/files/put?path=${encodeURIComponent(full)}`;
    const r = await fetch(url, {
      method: "PUT",
      credentials: "include",
      cache: "no-store",
      body: file,
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      throw new Error(msg || "upload failed");
    }
  }

  async function uploadRelFiles(relFiles) {
    // relFiles: Array<{ rel: string, file: File }>
    if (!relFiles.length) return;

    const created = new Set();

    let done = 0;
    const total = relFiles.length;

    for (const it of relFiles) {
      const rel = normalizeRelPath(it.rel);
      if (!validateRelPath(rel)) {
        setBadge("err", "error");
        status.textContent = `Upload skipped (unsafe path): ${it.rel}`;
        continue;
      }

      const dir = parentPath(rel);
      if (dir) await mkdirIfNeeded(dir, created);

      try {
        await putFileTo(rel, it.file);
        done++;
        setBadge("warn", "upload…");
        status.textContent = `Uploaded ${done}/${total}: ${rel}`;
      } catch (e) {
        setBadge("err", "error");
        status.textContent = `Upload failed: ${rel} — ${String(e && e.message ? e.message : e)}`;
        // continue to next file
      }
    }

    setBadge("ok", "ready");
    status.textContent = `Upload finished. Files: ${done}/${total}`;
    await load();
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

  uploadBtn?.addEventListener("click", pickFiles);
  uploadFolderBtn?.addEventListener("click", pickFolder);

  filePick?.addEventListener("change", async () => {
    const files = Array.from(filePick.files || []);
    const relFiles = files.map(f => ({ rel: f.name, file: f }));
    await uploadRelFiles(relFiles);
    filePick.value = "";
  });

  folderPick?.addEventListener("change", async () => {
    const files = Array.from(folderPick.files || []);
    // In folder picker, webkitRelativePath includes folder structure.
    const relFiles = files.map(f => ({
      rel: f.webkitRelativePath || f.name,
      file: f
    }));
    await uploadRelFiles(relFiles);
    folderPick.value = "";
  });

  // ---- Drag & Drop folder recursion (Chromium) ------------------------------
  function hasFiles(dt) {
    if (!dt) return false;
    try { return Array.from(dt.types || []).includes("Files"); } catch (_) {}
    return !!dt.files && dt.files.length > 0;
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
      if (f) out.push({ rel: prefix + f.name, file: f });
      return;
    }

    if (entry.isDirectory) {
      const dirReader = entry.createReader();
      const name = entry.name ? (entry.name + "/") : "";
      const nextPrefix = prefix + name;

      // readEntries is chunked
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

  // Folder drag&drop is Chromium-only via webkitGetAsEntry().
  // Firefox typically provides files without directory structure (except some cases).
  async function collectDroppedFiles(dt) {
    const out = [];

    // Prefer entry API if available (folders)
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

  gridWrap?.addEventListener("dragenter", (e) => {
    if (!hasFiles(e.dataTransfer)) return;
    e.preventDefault();
    showDropOverlay(true);
  });

  gridWrap?.addEventListener("dragover", (e) => {
    if (!hasFiles(e.dataTransfer)) return;
    e.preventDefault();
    showDropOverlay(true);
  });

  gridWrap?.addEventListener("dragleave", (e) => {
    if (e.target === gridWrap) showDropOverlay(false);
  });

  gridWrap?.addEventListener("drop", async (e) => {
    if (!hasFiles(e.dataTransfer)) return;
    e.preventDefault();
    showDropOverlay(false);

    try {
      const relFiles = await collectDroppedFiles(e.dataTransfer);
      await uploadRelFiles(relFiles);
    } catch (err) {
      setBadge("err", "error");
      status.textContent = `Drop upload failed: ${String(err && err.message ? err.message : err)}`;
    }
  });

  // ===========================================================================
  // Context menu / UI (same as before, just adds upload items in background menu)
  // ===========================================================================
  function closeMenu() {
    if (!ctxEl) return;
    ctxEl.classList.remove("show");
    ctxEl.setAttribute("aria-hidden", "true");
    ctxEl.innerHTML = "";
    ctxOpenForKey = "";
  }

  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

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

  function menuSep() {
    const d = document.createElement("div");
    d.className = "ctxSep";
    return d;
  }

  function currentRelPathFor(item) {
    return joinPath(curPath, item.name);
  }

  function doDownload(item) {
    const p = currentRelPathFor(item);
    window.location.href = `/api/v4/files/get?path=${encodeURIComponent(p)}`;
  }

  function downloadFolderZip(relDir) {
    // relDir: "" means current root
    const p = relDir || "";
    // Server endpoint:
    //   GET /api/v4/files/zip?path=<relDir>
    window.location.href = `/api/v4/files/zip?path=${encodeURIComponent(p)}`;
  }

  function keyToItemRelPath(key) {
    // key is "dir:<name>" or "file:<name>" in *current* folder
    const s = String(key || "");
    const i = s.indexOf(":");
    if (i < 0) return null;
    const name = s.slice(i + 1);
    if (!name) return null;
    return curPath ? `${curPath}/${name}` : name;
  }

  function selectedRelPaths() {
    // Convert current selection to absolute-rel paths for server
    const out = [];
    for (const k of selectedKeys) {
      const p = keyToItemRelPath(k);
      if (p) out.push(p);
    }
    // stable order (nice UX)
    out.sort((a, b) => String(a).localeCompare(String(b)));
    return out;
  }
  // Download a zip of the current selection (requires server: POST /api/v4/files/zip_sel).
  // Uses fetch+Blob so we can send JSON body (list of selected paths).
  async function downloadSelectionZip() {
    const paths = selectedRelPaths();
    if (!paths.length) {
      status.textContent = "Nothing selected.";
      return;
    }

    setBadge("warn", "zip…");
    status.textContent = `Preparing zip (${paths.length} items)…`;

    // Server endpoint (you need to implement this):
    // POST /api/v4/files/zip_sel
    // Body: { paths: ["rel/file", "rel/dir", ...] }
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

    // filename from server is best; fallback if missing
    const cd = r.headers.get("Content-Disposition") || "";
    let filename = "pqnas_selection.zip";
    const m = cd.match(/filename="([^"]+)"/i);
    if (m && m[1]) filename = m[1];

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

  async function doRename(item) {
    const oldRel = currentRelPathFor(item);
    const oldName = String(item.name || "");
    const newName = prompt("Rename to:", oldName);
    if (!newName) return;

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

  function openMenuAt(x, y, item) {
    if (!ctxEl) return;

    const key = `${item.type}:${item.name}`;
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    // If multiple items are selected and the right-clicked item is part of that selection,
    // show selection-level actions here too (not only in background menu).
    if (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key)) {
      ctxEl.appendChild(
          menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip())
      );
      ctxEl.appendChild(menuSep());
    }

    if (item.type === "dir") {
      ctxEl.appendChild(menuItem("Open", "↩", () => {
        curPath = joinPath(curPath, item.name);
        clearSelection();
        load();
      }));

      ctxEl.appendChild(
          menuItem("Download folder (zip)", "", () => {
            const relDir = joinPath(curPath, item.name);
            downloadFolderZip(relDir);
          })
      );

      ctxEl.appendChild(menuItem("New folder here…", "", () => {
        const relDir = joinPath(curPath, item.name);
        doMkdirAt(relDir);
      }));

      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));
    } else {
      ctxEl.appendChild(menuItem("Download", "⤓", () => doDownload(item)));
      // if selected -> add download selection + menuSep()
      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));
    }

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  function openBackgroundMenuAt(x, y) {
    if (!ctxEl) return;

    const key = "__bg__";
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    ctxEl.appendChild(menuItem("Upload files…", "", () => pickFiles()));
    ctxEl.appendChild(menuItem("Upload folder…", "", () => pickFolder()));

    //if we have selected many files/folders
    if (selectedKeys && selectedKeys.size > 0) {
      ctxEl.appendChild(
          menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip())
      );
      ctxEl.appendChild(menuSep());
    }

    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Download current folder (zip)", "", () => downloadFolderZip(curPath)));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("New folder…", "", () => doMkdirAt(curPath)));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Refresh", "", () => load()));

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  document.addEventListener("click", (e) => {
    if (!ctxEl || !ctxEl.classList.contains("show")) return;
    if (e.target === ctxEl || ctxEl.contains(e.target)) return;
    closeMenu();
  });

  // Global keyboard shortcuts:
  // - Esc closes context menu
  // - Ctrl/Cmd + A selects all tiles in the current view
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeMenu();
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

  window.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu);

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
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 8) cancel();
    });
  }

  downloadFolderBtn?.addEventListener("click", () => {
    // Download the *current* directory as zip
    downloadFolderZip(curPath);
  });

  gridEl?.addEventListener("contextmenu", (e) => {
    if (e.target && e.target.closest && e.target.closest(".tile")) return;
    e.preventDefault();
    openBackgroundMenuAt(e.clientX, e.clientY);
  });

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

    t.addEventListener("click", (e) => {
      // Ignore click if we were marquee-selecting
      if (marqueeOn) return;

      if (e.ctrlKey || e.metaKey) toggleSelection(key);
      else setSingleSelection(key);
    });

    t.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      ensureSelected(key);
      openMenuAt(e.clientX, e.clientY, item);
    });

    installLongPress(t, item);

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

  async function load() {
    closeMenu();
    setBadge("warn", "loading…");
    status.textContent = "Loading…";
    clear();

    try {
      const url = curPath
          ? `/api/v4/files/list?path=${encodeURIComponent(curPath)}`
          : `/api/v4/files/list`;

      const r = await fetch(url, { credentials: "include", cache: "no-store" });
      const j = await r.json().catch(() => null);

      if (!r.ok || !j || !j.ok) {
        setBadge("err", "error");
        status.textContent = `List failed: HTTP ${r.status}`;
        const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : "bad response";

        const err = document.createElement("div");
        err.className = "tile mono";
        err.style.cursor = "default";
        err.textContent = msg;
        gridEl.appendChild(err);
        return;
      }

      curPath = typeof j.path === "string" ? j.path : curPath;
      pathLine.textContent = `path: ${curPath ? "/" + curPath : "/"}`;

      setBadge("ok", "ready");

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
        empty.textContent = "(empty)\n\nTip: drag & drop files/folders here to upload.";
        gridEl.appendChild(empty);
        return;
      }

      for (const it of items) gridEl.appendChild(tile(it));

      // restore selection highlights (keys are stable per folder listing)
      applySelectionToDom();
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

  refreshBtn?.addEventListener("click", load);
  upBtn?.addEventListener("click", () => {
    curPath = parentPath(curPath);
    clearSelection();
    load();
  });

  load();
})();
