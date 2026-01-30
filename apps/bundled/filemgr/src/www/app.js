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

  // for upload progress bar
  const uploadProg = document.getElementById("uploadProg");
  const uploadProgText = document.getElementById("uploadProgText");
  const uploadProgPct = document.getElementById("uploadProgPct");
  const uploadProgFill = document.getElementById("uploadProgFill");

  const propsModal = document.getElementById("propsModal");
  const propsClose = document.getElementById("propsClose");
  const propsTitle = document.getElementById("propsTitle");
  const propsPath = document.getElementById("propsPath");
  const propsBody = document.getElementById("propsBody");



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

  propsClose?.addEventListener("click", closePropsModal);
  propsModal?.addEventListener("click", (e) => {
    // click outside card closes
    if (e.target === propsModal) closePropsModal();
  });

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
  function setPathAndLoad(p) {
    curPath = p || "";
    clearSelection();
    load();
  }

  // breadcrumb path on the top bar
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

  // --- add near your other helpers, e.g. close to downloadSelectionZip() ---

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

    // Delete sequentially for predictable behavior
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
      // Keep it short in UI; full list in console.
      status.textContent = `Deleted ${paths.length - failed}/${paths.length}. Failed: ${failed}. See console.`;
      console.warn("Multi-delete failures:", failures);
    } else {
      setBadge("ok", "ready");
      status.textContent = `Deleted ${paths.length} item(s).`;
    }

    await load();
  }


  function setUploadProgress(pct, text) {
    pct = Math.max(0, Math.min(100, Number(pct || 0)));
    if (uploadProgFill) uploadProgFill.style.width = `${pct.toFixed(1)}%`;
    if (uploadProgPct) uploadProgPct.textContent = `${Math.round(pct)}%`;
    if (uploadProgText && text) uploadProgText.textContent = text;
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
        // Server returns JSON {ok:true} for /put
        let j = null;
        try { j = JSON.parse(xhr.responseText || ""); } catch (_) {}

        if (xhr.status >= 200 && xhr.status < 300 && j && j.ok) {
          resolve(j);
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


  async function uploadRelFiles(relFiles) {
    // relFiles: Array<{ rel: string, file: File }>
    if (!relFiles.length) return;

    const created = new Set();

    // Filter/normalize first so totals are accurate
    const items = [];
    for (const it of relFiles) {
      const rel = normalizeRelPath(it.rel);
      if (!validateRelPath(rel)) {
        // Skip unsafe paths but keep going
        continue;
      }
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

    showUploadProgress(true);
    setBadge("warn", "upload…");
    setUploadProgress(0, `Uploading 0/${totalFiles}…`);

    for (let idx = 0; idx < items.length; idx++) {
      const { rel, file } = items[idx];

      const dir = parentPath(rel);
      if (dir) await mkdirIfNeeded(dir, created);

      let lastLoaded = 0;

      try {
        status.textContent = `Uploading: ${rel} (${fmtSize(file.size)})`;

        await xhrPutFileTo(rel, file, (loaded) => {
          // overall = committed + current loaded delta
          lastLoaded = Math.max(lastLoaded, loaded || 0);
          const overall = uploadedBytesCommitted + lastLoaded;
          const pct = (overall / totalBytes) * 100;

          setBadge("warn", "upload…");
          setUploadProgress(
              pct,
              `Uploading ${doneFiles}/${totalFiles} • ${rel} • ${fmtSize(overall)} / ${fmtSize(totalBytes)}`
          );
        });

        // file finished => commit its full size
        uploadedBytesCommitted += (Number(file.size) || lastLoaded || 0);
        doneFiles++;

        const pct = (uploadedBytesCommitted / totalBytes) * 100;
        setUploadProgress(
            pct,
            `Uploaded ${doneFiles}/${totalFiles} • ${rel}`
        );

      } catch (e) {
        setBadge("err", "error");
        status.textContent = `Upload failed: ${rel} — ${String(e && e.message ? e.message : e)}`;
        // continue to next file
        // NOTE: we do NOT commit bytes on failure
      }
    }

    // End state
    setBadge("ok", "ready");
    setUploadProgress(100, `Upload finished • ${doneFiles}/${totalFiles} files`);
    status.textContent = `Upload finished. Files: ${doneFiles}/${totalFiles}`;

    // Hide after a short moment (optional). If you prefer keep it visible, remove this.
    setTimeout(() => showUploadProgress(false), 900);

    await load();
  }

  function pickFiles() {
    if (!filePick) return;
    // reset so selecting same file twice still triggers "change"
    filePick.value = "";
    filePick.click();
  }

  function pickFolder() {
    if (!folderPick) return;
    folderPick.value = "";
    folderPick.click();
  }



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

  function buildSelectionMenuOnly() {
    if (!ctxEl) return;

    ctxEl.innerHTML = "";

    ctxEl.appendChild(menuItem(`Properties (selection)…`, "", () => showSelectionProperties()));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip()));
    ctxEl.appendChild(menuItem(`Delete selection (${selectedKeys.size})…`, "", () => deleteSelection(), { danger: true }));
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
  async function showSelectionProperties() {
    const paths = selectedRelPaths();
    if (!paths.length) return;

    if (propsTitle) propsTitle.textContent = `Selection properties`;
    if (propsPath) propsPath.textContent = `${paths.length} item(s)`;
    if (propsBody) propsBody.innerHTML = "";

    // initial rows
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

    // fetch aggregated stats
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
      if (!r.ok && st && !st.ok) {
        // keep whatever server said
      }
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

    const pushRow = (arr, k, v) => {
      if (v === undefined || v === null || v === "") return;
      arr.push([k, v]);
    };

    const rows2 = [];
    pushRow(rows2, "Items", String(st.count != null ? st.count : paths.length));
    pushRow(rows2, "Files", st.files != null ? String(st.files) : "");
    pushRow(rows2, "Folders", st.dirs != null ? String(st.dirs) : "");
    if (st.other != null && st.other !== 0) pushRow(rows2, "Other", String(st.other));

    if (st.bytes_total != null) pushRow(rows2, "Total size", fmtSize(st.bytes_total));

    if (typeof st.partial === "boolean") {
      pushRow(rows2, "Complete", st.partial ? "No (partial)" : "Yes");
    }

    if (st.limits) {
      if (st.limits.max_items != null) pushRow(rows2, "Max items", String(st.limits.max_items));
      if (st.limits.time_cap_ms != null) pushRow(rows2, "Dir scan time cap", `${st.limits.time_cap_ms} ms`);
      if (st.limits.scan_cap != null) pushRow(rows2, "Dir scan entry cap", String(st.limits.scan_cap));
    }

    // Errors summary
    const errCount = Array.isArray(st.errors) ? st.errors.length : 0;
    if (errCount) pushRow(rows2, "Errors", String(errCount));

    // Collapsible Raw JSON
    const rawDetails = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Raw JSON";
    rawDetails.appendChild(summary);

    const pre = document.createElement("pre");
    pre.className = "pre mono";
    pre.textContent = JSON.stringify(st, null, 2);
    rawDetails.appendChild(pre);

    // Render rows
    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    // add details block spanning full width: append empty key cell + value cell
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

    // If properties modal is open, close it before showing a menu
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

    const selectionMode = (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key));
    if (selectionMode) {
      buildSelectionMenuOnly();
      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }
    // If multiple items are selected and the right-clicked item is part of that selection,
    // show selection-level actions here too (not only in background menu).
    if (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key)) {
      ctxEl.appendChild(
          menuItem(`Properties (selection)…`, "", () => showSelectionProperties())
      );
      ctxEl.appendChild(menuSep());

      ctxEl.appendChild(
          menuItem(`Download selection (zip) (${selectedKeys.size})`, "", () => downloadSelectionZip())
      );
      ctxEl.appendChild(
          menuItem(`Delete selection (${selectedKeys.size})…`, "", () => deleteSelection(), { danger: true })
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

// Properties (single only)
      if (!(selectedKeys && selectedKeys.size > 1)) {
        ctxEl.appendChild(menuSep());
        ctxEl.appendChild(menuItem("Properties…", "", () => showProperties(item)));
      }
      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem("Rename…", "", () => doRename(item)));
      ctxEl.appendChild(menuItem("Delete…", "", () => doDelete(item), { danger: true }));

    } else {
      ctxEl.appendChild(menuItem("Download", "⤓", () => doDownload(item)));

      // Properties (single only)
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

  function openBackgroundMenuAt(x, y) {
    if (!ctxEl) return;

    // If properties modal is open, close it before showing a menu
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

    // If there is ANY selection, background right-click should behave like selection menu,
    // not show upload/create folder actions.
    if (selectedKeys && selectedKeys.size > 0) {
      if (selectedKeys.size > 1) {
        // Multi-select: selection-only actions
        buildSelectionMenuOnly();
      } else {
        // Single-select: show the same menu as right-clicking that item
        const onlyKey = Array.from(selectedKeys)[0];
        const p = keyToItemRelPath(onlyKey);
        if (p) {
          const name = p.split("/").pop() || p;
          const type = String(onlyKey).startsWith("dir:") ? "dir" : "file";
          openMenuAt(x, y, { type, name });
          return; // openMenuAt already places + shows
        } else {
          // fallback: at least show selection menu
          buildSelectionMenuOnly();
        }
      }

      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    // No selection: background actions (upload / folder / refresh)
    ctxEl.appendChild(menuItem("Upload files…", "", () => pickFiles()));
    ctxEl.appendChild(menuItem("Upload folder…", "", () => pickFolder()));
    ctxEl.appendChild(menuSep());
    ctxEl.appendChild(menuItem("Download current folder (zip)", "", () => downloadFolderZip(curPath)));
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

      // Close properties modal first if open
      if (propsModal && propsModal.classList.contains("show")) {
        closePropsModal();
        return;
      }

      // Otherwise close context menu
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
  /*
    downloadFolderBtn?.addEventListener("click", () => {
      // Download the *current* directory as zip
      downloadFolderZip(curPath);
    });
  */
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
  function kvRow(k, v) {
    const kEl = document.createElement("div");
    kEl.className = "k";
    kEl.textContent = k;

    const vEl = document.createElement("div");
    vEl.className = "v mono";
    vEl.textContent = v == null ? "" : String(v);

    return [kEl, vEl];
  }

  async function showProperties(item) {
    if (!item) return;

    const rel = joinPath(curPath, item.name || "");
    const isDirHint = item.type === "dir";

    if (propsTitle) propsTitle.textContent = isDirHint ? "Folder properties" : "File properties";
    if (propsPath) propsPath.textContent = "/" + (rel || "");

    if (propsBody) propsBody.innerHTML = "";

    // --- helpers local to this function (no global guesses) ---
    const pad2 = (n) => String(n).padStart(2, "0");

    const fmtUnix = (sec) => {
      if (!sec) return "";
      // Your server returns epoch seconds (UTC). Show local time by default.
      const d = new Date(Number(sec) * 1000);
      if (isNaN(d.getTime())) return String(sec);
      return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    };

    const permsFromOctal = (modeStr) => {
      // mode_octal is like "0664" or "0775"
      if (!modeStr || typeof modeStr !== "string") return "";
      const s = modeStr.trim();
      if (!/^[0-7]{3,4}$/.test(s)) return "";
      const oct = s.length === 4 ? s.slice(1) : s; // ignore leading special digit if present
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

    const pushRow = (rows, k, v) => {
      if (v === undefined || v === null || v === "") return;
      rows.push([k, v]);
    };

    // --- render initial rows from list-item (fast) ---
    const rows = [];
    pushRow(rows, "Name", item.name || "");
    pushRow(rows, "Type", isDirHint ? "Folder" : "File");
    pushRow(rows, "Path", "/" + (rel || ""));

    // Show list-derived size/mtime only as fallback (server stat will override)
    if (!isDirHint && item.size_bytes != null) pushRow(rows, "Size", fmtSize(item.size_bytes || 0));
    if (item.mtime_unix) pushRow(rows, "Modified", fmtTime(item.mtime_unix));

    // Temporary row while loading
    rows.push(["Details", "Loading…"]);

    if (propsBody) {
      for (const [k, v] of rows) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    // --- fetch stat from server ---
    let st = null;
    try {
      const qs = new URLSearchParams();
      // Use "." for root; otherwise use rel (already relative, no leading slash)
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

    // --- re-render based on stat ground truth ---
    if (!propsBody) {
      openPropsModal?.();
      return;
    }

    propsBody.innerHTML = "";

    if (!st || !st.ok) {
      const msg = (st && (st.message || st.error)) ? `${st.error || "error"}: ${st.message || ""}` : "Failed to load properties";
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

    // Permissions
    if (st.mode_octal) {
      const rwx = permsFromOctal(st.mode_octal);
      pushRow(rows2, "Permissions", rwx ? `${st.mode_octal} (${rwx})` : st.mode_octal);
    }

    // Time
    if (st.mtime_epoch) pushRow(rows2, "Modified", fmtUnix(st.mtime_epoch));

    if (st.type === "file") {
      if (st.bytes != null) pushRow(rows2, "Size", fmtSize(st.bytes));
      if (st.mime) pushRow(rows2, "MIME", st.mime);
      if (typeof st.is_text === "boolean") pushRow(rows2, "Looks like text", st.is_text ? "Yes" : "No");
    }

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

// Render normal rows first (no raw JSON yet)
    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

// Collapsible Raw JSON (developer-friendly, not noisy)
    {
      const [kEl, vEl] = kvRow("Details", "");
      vEl.classList.remove("mono"); // we'll control formatting inside
      vEl.innerHTML = ""; // safe: we only add DOM nodes (no untrusted HTML)

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
      renderBreadcrumb();


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
