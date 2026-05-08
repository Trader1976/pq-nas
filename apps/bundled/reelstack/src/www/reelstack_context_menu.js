(() => {
  "use strict";

  let api = null;
  let menu = null;
  let installed = false;

  let uploadCancelRequested = false;
  let uploadActiveXhr = null;

  function basename(path) {
    const parts = String(path || "").split("/").filter(Boolean);
    return parts.length ? parts[parts.length - 1] : String(path || "");
  }

  function cleanRelPath(path) {
    return String(path || "")
      .replace(/\\+/g, "/")
      .replace(/^\/+|\/+$/g, "")
      .split("/")
      .filter(Boolean)
      .join("/");
  }

  function joinPath(parent, name) {
    parent = cleanRelPath(parent);
    name = cleanRelPath(name);
    if (!parent) return name;
    if (!name) return parent;
    return `${parent}/${name}`;
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 B";

    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }

    return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function setStatus(text) {
    if (api && typeof api.setStatus === "function") {
      api.setStatus(text);
      return;
    }

    const status = document.getElementById("statusText");
    if (status) status.textContent = text || "";
  }

  async function postJson(url, body) {
    const r = await fetch(url, {
      method: "POST",
      cache: "no-store",
      credentials: "include",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body || {})
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) {
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
    }

    return j;
  }

  function ensureUploadProgressModal() {
    let backdrop = document.getElementById("rsUploadProgressBackdrop");
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.id = "rsUploadProgressBackdrop";
    backdrop.className = "rsUploadProgressBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="rsUploadProgressCard" role="dialog" aria-modal="true" aria-labelledby="rsUploadProgressTitle">
        <div class="rsUploadProgressHead">
          <div>
            <div class="rsUploadDestKicker">Reel Stack upload</div>
            <h2 id="rsUploadProgressTitle">Uploading videos</h2>
            <p id="rsUploadProgressSub">Preparing upload…</p>
          </div>
          <button id="rsUploadProgressCancelTop" class="rsUploadDestClose" type="button">Cancel</button>
        </div>

        <div class="rsUploadProgressBody">
          <div class="rsUploadProgressFile" id="rsUploadProgressFile">Waiting…</div>

          <div class="rsUploadProgressRow">
            <div id="rsUploadProgressText" class="rsUploadProgressText">0 B / 0 B</div>
            <div id="rsUploadProgressPct" class="rsUploadProgressPct">0%</div>
          </div>

          <div class="rsUploadProgressBar" aria-hidden="true">
            <div id="rsUploadProgressFill" class="rsUploadProgressFill"></div>
          </div>

          <div id="rsUploadProgressMeta" class="rsUploadProgressMeta">Chunk 0/0</div>
        </div>

        <div class="rsUploadProgressFoot">
          <button id="rsUploadProgressCancel" class="rsUploadDestBtn secondary" type="button">Cancel upload</button>
          <button id="rsUploadProgressClose" class="rsUploadDestBtn primary" type="button" hidden>Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);

    const cancel = () => requestUploadCancel();
    backdrop.querySelector("#rsUploadProgressCancel")?.addEventListener("click", cancel);
    backdrop.querySelector("#rsUploadProgressCancelTop")?.addEventListener("click", cancel);
    backdrop.querySelector("#rsUploadProgressClose")?.addEventListener("click", () => {
      backdrop.hidden = true;
    });

    return backdrop;
  }

  function openUploadProgressModal(fileCount, totalBytes) {
    const backdrop = ensureUploadProgressModal();

    const sub = backdrop.querySelector("#rsUploadProgressSub");
    const close = backdrop.querySelector("#rsUploadProgressClose");
    const cancel = backdrop.querySelector("#rsUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#rsUploadProgressCancelTop");

    if (sub) {
      sub.textContent = `${fileCount} video${fileCount === 1 ? "" : "s"} · ${fmtBytes(totalBytes)} total`;
    }

    if (close) close.hidden = true;
    if (cancel) {
      cancel.hidden = false;
      cancel.disabled = false;
      cancel.textContent = "Cancel upload";
    }
    if (cancelTop) {
      cancelTop.hidden = false;
      cancelTop.disabled = false;
      cancelTop.textContent = "Cancel";
    }

    backdrop.hidden = false;
  }

  function setUploadProgressModal(data) {
    const backdrop = ensureUploadProgressModal();

    const fileEl = backdrop.querySelector("#rsUploadProgressFile");
    const textEl = backdrop.querySelector("#rsUploadProgressText");
    const pctEl = backdrop.querySelector("#rsUploadProgressPct");
    const fillEl = backdrop.querySelector("#rsUploadProgressFill");
    const metaEl = backdrop.querySelector("#rsUploadProgressMeta");

    const loaded = Math.max(0, Number(data && data.loaded || 0));
    const total = Math.max(0, Number(data && data.total || 0));
    const pct = total > 0 ? Math.max(0, Math.min(100, (loaded / total) * 100)) : 0;

    if (fileEl) fileEl.textContent = data && data.file ? data.file : "Uploading…";
    if (textEl) textEl.textContent = `${fmtBytes(loaded)} / ${fmtBytes(total)}`;
    if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
    if (fillEl) fillEl.style.width = `${pct.toFixed(1)}%`;

    if (metaEl) {
      const fileIndex = Number(data && data.fileIndex || 0);
      const fileCount = Number(data && data.fileCount || 0);
      const chunkIndex = Number(data && data.chunkIndex || 0);
      const chunksTotal = Number(data && data.chunksTotal || 0);
      const speed = data && data.speedBps ? ` · ${fmtBytes(data.speedBps)}/s` : "";

      metaEl.textContent =
        `File ${fileIndex}/${fileCount} · chunk ${chunkIndex}/${chunksTotal}${speed}`;
    }
  }

  function finishUploadProgressModal(message, ok) {
    const backdrop = ensureUploadProgressModal();

    const fileEl = backdrop.querySelector("#rsUploadProgressFile");
    const metaEl = backdrop.querySelector("#rsUploadProgressMeta");
    const fillEl = backdrop.querySelector("#rsUploadProgressFill");
    const pctEl = backdrop.querySelector("#rsUploadProgressPct");
    const close = backdrop.querySelector("#rsUploadProgressClose");
    const cancel = backdrop.querySelector("#rsUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#rsUploadProgressCancelTop");

    if (fileEl) {
      fileEl.textContent = message || (ok ? "Upload complete." : "Upload stopped.");
      fileEl.classList.toggle("rsUploadProgressOk", !!ok);
      fileEl.classList.toggle("rsUploadProgressFail", !ok);
    }

    if (ok) {
      if (fillEl) fillEl.style.width = "100%";
      if (pctEl) pctEl.textContent = "100%";
    }

    if (metaEl) metaEl.textContent = ok ? "Ready." : "Cancelled or failed.";

    if (cancel) cancel.hidden = true;
    if (cancelTop) cancelTop.hidden = true;
    if (close) close.hidden = false;
  }

  function requestUploadCancel() {
    uploadCancelRequested = true;
    setStatus("Cancelling upload…");

    const backdrop = ensureUploadProgressModal();
    const cancel = backdrop.querySelector("#rsUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#rsUploadProgressCancelTop");

    if (cancel) {
      cancel.disabled = true;
      cancel.textContent = "Cancelling…";
    }

    if (cancelTop) {
      cancelTop.disabled = true;
      cancelTop.textContent = "Cancelling…";
    }

    try {
      if (uploadActiveXhr) uploadActiveXhr.abort();
    } catch (_) {}
  }

    function putChunkXhr(url, blob, onProgress) {
    return new Promise((resolve, reject) => {
      if (uploadCancelRequested) {
        reject(Object.assign(new Error("upload cancelled"), { kind: "cancelled" }));
        return;
      }

      const xhr = new XMLHttpRequest();
      uploadActiveXhr = xhr;

      xhr.open("PUT", url, true);
      xhr.withCredentials = true;
      xhr.timeout = 0;
      xhr.setRequestHeader("Accept", "application/json");
      xhr.setRequestHeader("Content-Type", "application/octet-stream");

      xhr.upload.onprogress = (ev) => {
        if (ev && ev.lengthComputable && onProgress) {
          onProgress(Math.max(0, Number(ev.loaded || 0)), Math.max(0, Number(ev.total || blob.size || 0)));
        }
      };

      xhr.onload = () => {
        if (uploadActiveXhr === xhr) uploadActiveXhr = null;

        let j = {};
        try { j = xhr.responseText ? JSON.parse(xhr.responseText) : {}; } catch (_) {}

        if (xhr.status >= 200 && xhr.status < 300 && j.ok !== false) {
          resolve(j);
          return;
        }

        reject(new Error(j.message || j.error || `HTTP ${xhr.status}`));
      };

      xhr.onerror = () => {
        if (uploadActiveXhr === xhr) uploadActiveXhr = null;
        reject(new Error("upload chunk failed: network error"));
      };

      xhr.ontimeout = () => {
        if (uploadActiveXhr === xhr) uploadActiveXhr = null;
        reject(new Error("upload chunk failed: timeout"));
      };

      xhr.onabort = () => {
        if (uploadActiveXhr === xhr) uploadActiveXhr = null;

        if (uploadCancelRequested) {
          reject(Object.assign(new Error("upload cancelled"), { kind: "cancelled" }));
        } else {
          reject(new Error("upload chunk aborted"));
        }
      };

      xhr.send(blob);
    });
  }

  async function cancelChunkedUploadBestEffort(uploadId) {
    if (!uploadId) return;

    try {
      await postJson("/api/v4/uploads/cancel", { upload_id: uploadId });
    } catch (_) {}
  }

  async function uploadFileChunked(relPath, file, onProgress) {
    let uploadId = "";

    try {
      if (uploadCancelRequested) {
        throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
      }

      const start = await postJson("/api/v4/uploads/start", {
        path: relPath,
        size_bytes: Number(file.size || 0)
      });

      uploadId = String(start.upload_id || "");
      const chunkSize = Math.max(1, Number(start.chunk_size || 0));
      const chunksTotal = Math.max(1, Number(start.chunks_total || Math.ceil(Number(file.size || 0) / chunkSize)));

      if (!uploadId || !chunkSize || !Number.isFinite(chunkSize)) {
        throw new Error("invalid chunked upload session");
      }

      let committed = 0;

      for (let index = 0; index < chunksTotal; index++) {
        if (uploadCancelRequested) {
          throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
        }

        const startByte = index * chunkSize;
        const endByte = Math.min(Number(file.size || 0), startByte + chunkSize);
        const blob = file.slice(startByte, endByte);

        const url =
          `/api/v4/uploads/chunk?upload_id=${encodeURIComponent(uploadId)}` +
          `&index=${encodeURIComponent(String(index))}`;

        await putChunkXhr(url, blob, (loaded) => {
          if (onProgress) onProgress(committed + loaded, Number(file.size || 0), index + 1, chunksTotal);
        });

        committed += blob.size;

        if (onProgress) onProgress(committed, Number(file.size || 0), index + 1, chunksTotal);
      }

      if (uploadCancelRequested) {
        throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
      }

      const finish = await postJson("/api/v4/uploads/finish", { upload_id: uploadId });
      uploadId = "";
      return finish;
    } catch (e) {
      if (uploadId) await cancelChunkedUploadBestEffort(uploadId);
      throw e;
    }
  }

  function chooseVideoFiles() {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.multiple = true;
      input.accept = [
        "video/*",
        ".mp4",
        ".m4v",
        ".mov",
        ".webm",
        ".mkv",
        ".avi",
        ".wmv",
        ".flv",
        ".mpeg",
        ".mpg",
        ".3gp"
      ].join(",");

      input.style.position = "fixed";
      input.style.left = "-9999px";
      input.style.top = "-9999px";

      input.addEventListener("change", () => {
        const files = Array.from(input.files || []);
        input.remove();
        resolve(files);
      }, { once: true });

      document.body.appendChild(input);
      input.click();
    });
  }

  async function refreshIndexFromMenu() {
    if (api && typeof api.refreshIndex === "function") {
      await api.refreshIndex();
      return;
    }

    const scanBtn = document.getElementById("scanBtn");
    if (scanBtn) {
      scanBtn.click();
      return;
    }

    window.location.reload();
  }

  function foldersFromVisibleVideos() {
    const folders = new Set(["Videos"]);

    for (const card of document.querySelectorAll(".rsCard[data-rs-path]")) {
      const path = cleanRelPath(card.dataset.rsPath || "");
      const i = path.lastIndexOf("/");
      if (i > 0) folders.add(path.slice(0, i));
    }

    return Array.from(folders).sort((a, b) => {
      if (a === "Videos") return -1;
      if (b === "Videos") return 1;
      return a.localeCompare(b, undefined, { sensitivity: "base" });
    });
  }

  function ensureUploadDestModal() {
    let backdrop = document.getElementById("rsUploadDestBackdrop");
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.id = "rsUploadDestBackdrop";
    backdrop.className = "rsUploadDestBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="rsUploadDestCard" role="dialog" aria-modal="true" aria-labelledby="rsUploadDestTitle">
        <div class="rsUploadDestHead">
          <div>
            <div class="rsUploadDestKicker">Reel Stack upload</div>
            <h2 id="rsUploadDestTitle">Upload selected videos</h2>
            <p id="rsUploadDestSub">Choose destination folder.</p>
          </div>
          <button id="rsUploadDestClose" class="rsUploadDestClose" type="button">Close</button>
        </div>

        <div class="rsUploadDestBody">
          <label class="rsUploadDestField">
            <span>Destination folder</span>
            <input id="rsUploadDestInput" type="text" value="Videos" autocomplete="off" spellcheck="false">
          </label>

          <div class="rsUploadDestHint">
            Use a relative folder path, for example <b>Videos</b> or <b>Movies/Family</b>.
          </div>

          <div class="rsUploadDestQuickTitle">Quick folders</div>
          <div id="rsUploadDestQuick" class="rsUploadDestQuick"></div>
        </div>

        <div class="rsUploadDestFoot">
          <button id="rsUploadDestCancel" class="rsUploadDestBtn secondary" type="button">Cancel</button>
          <button id="rsUploadDestOk" class="rsUploadDestBtn primary" type="button">Upload here</button>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);
    return backdrop;
  }

  function chooseUploadDestinationFolder(files) {
    return new Promise((resolve) => {
      const backdrop = ensureUploadDestModal();
      const card = backdrop.querySelector(".rsUploadDestCard");
      const input = backdrop.querySelector("#rsUploadDestInput");
      const quick = backdrop.querySelector("#rsUploadDestQuick");
      const sub = backdrop.querySelector("#rsUploadDestSub");
      const ok = backdrop.querySelector("#rsUploadDestOk");
      const cancel = backdrop.querySelector("#rsUploadDestCancel");
      const close = backdrop.querySelector("#rsUploadDestClose");

      const list = Array.isArray(files) ? files : [];
      const count = list.length;
      const total = list.reduce((sum, f) => sum + Number(f && f.size || 0), 0);

      if (sub) {
        sub.textContent =
          `${count} video${count === 1 ? "" : "s"} selected · ${fmtBytes(total)} total`;
      }

      if (quick) {
        quick.innerHTML = "";

        for (const folder of foldersFromVisibleVideos()) {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = folder;
          btn.addEventListener("click", () => {
            input.value = folder;
            input.focus();
            input.select();
          });
          quick.appendChild(btn);
        }
      }

      let done = false;

      const cleanup = () => {
        backdrop.hidden = true;
        backdrop.removeEventListener("mousedown", onBackdropMouseDown);
        document.removeEventListener("keydown", onKeydown, true);
        ok?.removeEventListener("click", onOk);
        cancel?.removeEventListener("click", onCancel);
        close?.removeEventListener("click", onCancel);
      };

      const finish = (value) => {
        if (done) return;
        done = true;
        cleanup();
        resolve(value);
      };

      const onOk = () => {
        const folder = cleanRelPath(input && input.value || "Videos") || "Videos";
        finish(folder);
      };

      const onCancel = () => finish(null);

      const onBackdropMouseDown = (ev) => {
        if (ev.target === backdrop) onCancel();
      };

      const onKeydown = (ev) => {
        if (backdrop.hidden) return;

        if (ev.key === "Escape") {
          ev.preventDefault();
          ev.stopPropagation();
          onCancel();
          return;
        }

        if (ev.key === "Enter" && ev.target === input) {
          ev.preventDefault();
          ev.stopPropagation();
          onOk();
        }
      };

      ok?.addEventListener("click", onOk);
      cancel?.addEventListener("click", onCancel);
      close?.addEventListener("click", onCancel);
      backdrop.addEventListener("mousedown", onBackdropMouseDown);
      document.addEventListener("keydown", onKeydown, true);

      backdrop.hidden = false;

      requestAnimationFrame(() => {
        try {
          input.focus();
          input.select();
        } catch (_) {}

        try {
          card.scrollIntoView({ block: "center", inline: "center" });
        } catch (_) {}
      });
    });
  }

  function setViewModeFromMenu(mode) {
    if (api && typeof api.setViewMode === "function") {
      api.setViewMode(mode);
      return;
    }

    const select = document.getElementById("viewModeSelect");
    if (select) {
      select.value = mode;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  function uploadBrowserParent(path) {
    path = cleanRelPath(path);
    if (!path) return "";

    const parts = path.split("/").filter(Boolean);
    parts.pop();
    return parts.join("/");
  }

  async function uploadBrowserGetJson(url) {
    const r = await fetch(url, {
      method: "GET",
      cache: "no-store",
      credentials: "include",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) {
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
    }

    return j;
  }

  function uploadBrowserItemsFromJson(j) {
    if (!j || typeof j !== "object") return [];

    const candidates = [
      j.items,
      j.entries,
      j.children,
      j.files,
      j.data,
      j.dirs,
      j.directories
    ];

    for (const x of candidates) {
      if (Array.isArray(x)) return x;
    }

    return [];
  }

  function uploadBrowserIsFolderItem(item) {
    if (!item) return false;
    if (typeof item === "string") return true;

    if (item.is_dir === true || item.dir === true || item.directory === true || item.isDirectory === true) {
      return true;
    }

    const t = String(item.type || item.kind || item.file_type || item.mode || "").toLowerCase();
    return t === "dir" || t === "folder" || t === "directory";
  }

  function uploadBrowserFolderFromItem(item, currentPath) {
    if (typeof item === "string") {
      const path = cleanRelPath(item);
      return {
        name: basename(path) || path || "/",
        path: path || cleanRelPath(currentPath)
      };
    }

    const rawPath = item.path || item.rel_path || item.relative_path || item.full_path || "";
    const rawName = item.name || item.filename || basename(rawPath) || "";

    const name = String(rawName || "").trim();
    let path = cleanRelPath(rawPath);

    if (!path && name) {
      path = joinPath(currentPath, name);
    }

    if (!name || name === "." || name === "..") return null;
    if (!path) return null;

    return { name, path };
  }

  async function uploadBrowserListFolders(path) {
    path = cleanRelPath(path);
    const url = `/api/v4/files/list?path=${encodeURIComponent(path)}`;
    const j = await uploadBrowserGetJson(url);

    const folders = [];

    for (const item of uploadBrowserItemsFromJson(j)) {
      if (!uploadBrowserIsFolderItem(item)) continue;

      const folder = uploadBrowserFolderFromItem(item, path);
      if (!folder) continue;

      folders.push(folder);
    }

    const seen = new Set();
    return folders
      .filter(f => {
        const k = cleanRelPath(f.path).toLowerCase();
        if (!k || seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  }

  function ensureUploadDestBrowserModal() {
    let backdrop = document.getElementById("rsUploadDestBrowserBackdrop");
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.id = "rsUploadDestBrowserBackdrop";
    backdrop.className = "rsUploadDestBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="rsUploadDestCard rsUploadDestBrowserCard" role="dialog" aria-modal="true" aria-labelledby="rsUploadBrowserTitle">
        <div class="rsUploadDestHead">
          <div>
            <div class="rsUploadDestKicker">Reel Stack upload</div>
            <h2 id="rsUploadBrowserTitle">Upload selected videos</h2>
            <p id="rsUploadBrowserSub">Choose destination folder.</p>
          </div>
          <button id="rsUploadBrowserClose" class="rsUploadDestClose" type="button">Close</button>
        </div>

        <div class="rsUploadDestBody">
          <label class="rsUploadDestField">
            <span>Destination folder</span>
            <input id="rsUploadBrowserInput" type="text" value="Videos" autocomplete="off" spellcheck="false">
          </label>

          <div class="rsUploadDestHint">
            Select an existing folder below, or type a relative folder path such as <b>Videos</b> or <b>Movies/Family</b>.
          </div>

          <div class="rsUploadDestQuickTitle">Quick folders from Reel Stack</div>
          <div id="rsUploadBrowserQuick" class="rsUploadDestQuick"></div>

          <div class="rsUploadBrowserBox">
            <div class="rsUploadBrowserTop">
              <div>
                <div class="rsUploadBrowserLabel">Browse your files</div>
                <div id="rsUploadBrowserCrumb" class="rsUploadBrowserCrumb">/</div>
              </div>
              <div class="rsUploadBrowserActions">
                <button id="rsUploadBrowserUseCurrent" type="button">Use current</button>
                <button id="rsUploadBrowserUp" type="button">Up</button>
                <button id="rsUploadBrowserRefresh" type="button">Refresh</button>
              </div>
            </div>

            <div id="rsUploadBrowserList" class="rsUploadBrowserList">
              Loading folders…
            </div>
          </div>
        </div>

        <div class="rsUploadDestFoot">
          <button id="rsUploadBrowserCancel" class="rsUploadDestBtn secondary" type="button">Cancel</button>
          <button id="rsUploadBrowserOk" class="rsUploadDestBtn primary" type="button">Upload here</button>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);
    return backdrop;
  }

  function chooseUploadDestinationFolderWithBrowser(files) {
    return new Promise((resolve) => {
      const backdrop = ensureUploadDestBrowserModal();

      const card = backdrop.querySelector(".rsUploadDestCard");
      const input = backdrop.querySelector("#rsUploadBrowserInput");
      const quick = backdrop.querySelector("#rsUploadBrowserQuick");
      const sub = backdrop.querySelector("#rsUploadBrowserSub");
      const listEl = backdrop.querySelector("#rsUploadBrowserList");
      const crumb = backdrop.querySelector("#rsUploadBrowserCrumb");
      const useCurrent = backdrop.querySelector("#rsUploadBrowserUseCurrent");
      const up = backdrop.querySelector("#rsUploadBrowserUp");
      const refresh = backdrop.querySelector("#rsUploadBrowserRefresh");
      const ok = backdrop.querySelector("#rsUploadBrowserOk");
      const cancel = backdrop.querySelector("#rsUploadBrowserCancel");
      const close = backdrop.querySelector("#rsUploadBrowserClose");

      const selectedFiles = Array.isArray(files) ? files : [];
      const count = selectedFiles.length;
      const total = selectedFiles.reduce((sum, f) => sum + Number(f && f.size || 0), 0);

      let currentPath = "";
      let done = false;

      if (sub) {
        sub.textContent = `${count} video${count === 1 ? "" : "s"} selected · ${fmtBytes(total)} total`;
      }

      if (input && !cleanRelPath(input.value)) {
        input.value = "Videos";
      }

      const selectFolder = (path) => {
        path = cleanRelPath(path);
        if (input) input.value = path || "Videos";
      };

      const renderFolderRows = (folders) => {
        if (!listEl) return;

        listEl.innerHTML = "";

        if (!folders.length) {
          const empty = document.createElement("div");
          empty.className = "rsUploadBrowserEmpty";
          empty.textContent = "No subfolders here.";
          listEl.appendChild(empty);
          return;
        }

        for (const folder of folders) {
          const row = document.createElement("button");
          row.type = "button";
          row.className = "rsUploadBrowserRow";
          row.title = "/" + cleanRelPath(folder.path);

          const icon = document.createElement("span");
          icon.className = "rsUploadBrowserIcon";
          icon.textContent = "📁";

          const text = document.createElement("span");
          text.className = "rsUploadBrowserText";

          const name = document.createElement("strong");
          name.textContent = folder.name;

          const pathLine = document.createElement("small");
          pathLine.textContent = "/" + cleanRelPath(folder.path);

          text.appendChild(name);
          text.appendChild(pathLine);

          row.appendChild(icon);
          row.appendChild(text);

          row.addEventListener("click", () => {
            selectFolder(folder.path);
            loadFolder(folder.path);
          });

          listEl.appendChild(row);
        }
      };

      const renderBrowserError = (message) => {
        if (!listEl) return;

        listEl.innerHTML = "";

        const error = document.createElement("div");
        error.className = "rsUploadBrowserEmpty";
        error.textContent = message || "Could not load folders.";
        listEl.appendChild(error);
      };

      const loadFolder = async (path) => {
        currentPath = cleanRelPath(path);

        if (crumb) crumb.textContent = currentPath ? "/" + currentPath : "/";
        if (up) up.disabled = !currentPath;
        if (useCurrent) {
          useCurrent.textContent = currentPath ? "Use current" : "Use root";
        }

        if (listEl) {
          listEl.innerHTML = '<div class="rsUploadBrowserEmpty">Loading folders…</div>';
        }

        try {
          const folders = await uploadBrowserListFolders(currentPath);
          renderFolderRows(folders);
        } catch (e) {
          renderBrowserError(e && e.message ? e.message : String(e));
        }
      };

      if (quick) {
        quick.innerHTML = "";

        for (const folder of foldersFromVisibleVideos()) {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = folder;
          btn.addEventListener("click", () => {
            selectFolder(folder);
            loadFolder(folder);
          });
          quick.appendChild(btn);
        }
      }

      const cleanup = () => {
        backdrop.hidden = true;
        backdrop.removeEventListener("mousedown", onBackdropMouseDown);
        document.removeEventListener("keydown", onKeydown, true);
        ok?.removeEventListener("click", onOk);
        cancel?.removeEventListener("click", onCancel);
        close?.removeEventListener("click", onCancel);
        useCurrent?.removeEventListener("click", onUseCurrent);
        up?.removeEventListener("click", onUp);
        refresh?.removeEventListener("click", onRefresh);
      };

      const finish = (value) => {
        if (done) return;
        done = true;
        cleanup();
        resolve(value);
      };

      const onOk = () => {
        const folder = cleanRelPath(input && input.value || "Videos") || "Videos";
        finish(folder);
      };

      const onCancel = () => finish(null);

      const onUseCurrent = () => {
        selectFolder(currentPath);
        try {
          input.focus();
          input.select();
        } catch (_) {}
      };

      const onUp = () => {
        loadFolder(uploadBrowserParent(currentPath));
      };

      const onRefresh = () => {
        loadFolder(currentPath);
      };

      const onBackdropMouseDown = (ev) => {
        if (ev.target === backdrop) onCancel();
      };

      const onKeydown = (ev) => {
        if (backdrop.hidden) return;

        if (ev.key === "Escape") {
          ev.preventDefault();
          ev.stopPropagation();
          onCancel();
          return;
        }

        if (ev.key === "Enter" && ev.target === input) {
          ev.preventDefault();
          ev.stopPropagation();
          onOk();
        }
      };

      ok?.addEventListener("click", onOk);
      cancel?.addEventListener("click", onCancel);
      close?.addEventListener("click", onCancel);
      useCurrent?.addEventListener("click", onUseCurrent);
      up?.addEventListener("click", onUp);
      refresh?.addEventListener("click", onRefresh);
      backdrop.addEventListener("mousedown", onBackdropMouseDown);
      document.addEventListener("keydown", onKeydown, true);

      backdrop.hidden = false;

      loadFolder("");

      requestAnimationFrame(() => {
        try {
          input.focus();
          input.select();
        } catch (_) {}

        try {
          card.scrollIntoView({ block: "center", inline: "center" });
        } catch (_) {}
      });
    });
  }

  async function uploadVideosFromEmptyAreaMenu() {
    const files = await chooseVideoFiles();
    if (!files.length) {
      setStatus("Upload cancelled.");
      return;
    }

    const folder = await chooseUploadDestinationFolderWithBrowser(files);
    if (folder === null) {
      setStatus("Upload cancelled.");
      return;
    }

    uploadCancelRequested = false;
    uploadActiveXhr = null;

    const totalBytes = files.reduce((sum, f) => sum + Number(f && f.size || 0), 0);
    const uploadStartedAt = performance.now();
    let uploadedBytesCommitted = 0;
    let done = 0;

    openUploadProgressModal(files.length, totalBytes);

    try {
      for (const file of files) {
        if (uploadCancelRequested) {
          throw Object.assign(new Error("upload cancelled"), { kind: "cancelled" });
        }

        const relPath = joinPath(folder, file.name || "video.bin");
        const fileBaseCommitted = uploadedBytesCommitted;

        setStatus(`Uploading ${file.name} to /${relPath}…`);

        await uploadFileChunked(relPath, file, (loadedForFile, fileTotal, chunkIndex, chunksTotal) => {
          const overallLoaded = fileBaseCommitted + Math.max(0, Number(loadedForFile || 0));
          const elapsedSec = Math.max(0.001, (performance.now() - uploadStartedAt) / 1000);
          const speedBps = overallLoaded / elapsedSec;

          setUploadProgressModal({
            file: file.name || relPath,
            loaded: overallLoaded,
            total: totalBytes,
            fileIndex: done + 1,
            fileCount: files.length,
            chunkIndex,
            chunksTotal,
            speedBps
          });

          const pct = totalBytes > 0 ? Math.max(0, Math.min(100, (overallLoaded / totalBytes) * 100)) : 0;
          setStatus(
            `Uploading ${file.name}: ${Math.round(pct)}% · ${fmtBytes(overallLoaded)} / ${fmtBytes(totalBytes)}`
          );
        });

        uploadedBytesCommitted += Number(file.size || 0);
        done++;

        setUploadProgressModal({
          file: `${file.name || relPath} uploaded`,
          loaded: uploadedBytesCommitted,
          total: totalBytes,
          fileIndex: done,
          fileCount: files.length,
          chunkIndex: 0,
          chunksTotal: 0,
          speedBps: uploadedBytesCommitted / Math.max(0.001, (performance.now() - uploadStartedAt) / 1000)
        });

        setStatus(`Uploaded ${file.name} (${done}/${files.length}).`);
      }

      finishUploadProgressModal(`Uploaded ${done} video${done === 1 ? "" : "s"} to /${folder}.`, true);
      setStatus(`Uploaded ${done} video${done === 1 ? "" : "s"} to /${folder}. Refreshing index…`);
      await refreshIndexFromMenu();
    } catch (e) {
      const cancelled = uploadCancelRequested || (e && e.kind === "cancelled");
      const msg = cancelled
        ? `Upload cancelled after ${done} of ${files.length} video${files.length === 1 ? "" : "s"}.`
        : `Upload failed: ${e && e.message ? e.message : String(e)}`;

      finishUploadProgressModal(msg, false);
      setStatus(msg);

      if (!cancelled) throw e;
    } finally {
      uploadActiveXhr = null;
      uploadCancelRequested = false;
    }
  }

  function ensureMenu() {
    if (menu) return menu;

    menu = document.createElement("div");
    menu.className = "rsContextMenu";
    menu.hidden = true;
    menu.setAttribute("role", "menu");

    document.body.appendChild(menu);
    return menu;
  }

  function hideMenu() {
    if (menu) menu.hidden = true;
  }

  function placeMenu(x, y) {
    const m = ensureMenu();
    m.hidden = false;

    const rect = m.getBoundingClientRect();
    const pad = 8;

    const left = Math.max(pad, Math.min(x, window.innerWidth - rect.width - pad));
    const top = Math.max(pad, Math.min(y, window.innerHeight - rect.height - pad));

    m.style.left = `${left}px`;
    m.style.top = `${top}px`;
  }

  function makeButton(label, hint, danger, onClick) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("role", "menuitem");
    if (danger) btn.classList.add("rsDanger");

    const text = document.createElement("span");
    text.textContent = label;

    const h = document.createElement("span");
    h.className = "rsContextMenuHint";
    h.textContent = hint || "";

    btn.appendChild(text);
    btn.appendChild(h);

    btn.addEventListener("click", async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();

      const path = menu ? menu.dataset.rsPath : "";
      hideMenu();

      try {
        await onClick(path);
      } catch (e) {
        if (api && typeof api.setStatus === "function") {
          api.setStatus(e && e.message ? e.message : String(e));
        } else {
          console.error(e);
        }
      }
    });

    return btn;
  }

  function videoForPath(path) {
    if (!api || typeof api.videoByPath !== "function") return null;
    return api.videoByPath(path);
  }

  function renderMenu(path) {
    const m = ensureMenu();
    m.innerHTML = "";
    m.dataset.rsPath = path || "";

    const title = document.createElement("div");
    title.className = "rsContextMenuTitle";
    title.textContent = basename(path || "Video");
    m.appendChild(title);

    m.appendChild(makeButton("Play", "Enter", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.openPlayer) api.openPlayer(v);
    }));

    m.appendChild(makeButton("Edit metadata", "Space", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.editMetadata) await api.editMetadata(v);
    }));

    m.appendChild(makeButton("Rename", "", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.renameVideo) await api.renameVideo(v);
    }));

    m.appendChild(makeButton("Share link", "", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.shareVideo) await api.shareVideo(v);
    }));

    m.appendChild(makeButton("Download", "", false, async (p) => {
      if (!api.downloadUrl) return;
      const a = document.createElement("a");
      a.href = api.downloadUrl(p);
      a.download = basename(p);
      document.body.appendChild(a);
      a.click();
      a.remove();
    }));

    m.appendChild(makeButton("Delete", "", true, async (p) => {
      const v = videoForPath(p);
      if (v && api.deleteVideo) await api.deleteVideo(v);
    }));
  }

  function appendSep(target) {
    const sep = document.createElement("div");
    sep.className = "rsContextMenuSep";
    target.appendChild(sep);
  }

  function renderAppMenu() {
    const m = ensureMenu();
    m.innerHTML = "";
    m.dataset.rsPath = "";

    const title = document.createElement("div");
    title.className = "rsContextMenuTitle";
    title.textContent = "Reel Stack";
    m.appendChild(title);

    m.appendChild(makeButton("Upload video", "", false, async () => {
      await uploadVideosFromEmptyAreaMenu();
    }));

    m.appendChild(makeButton("Refresh index", "", false, async () => {
      await refreshIndexFromMenu();
    }));

    appendSep(m);

    m.appendChild(makeButton("View: All videos", "", false, async () => setViewModeFromMenu("all")));
    m.appendChild(makeButton("View: By folder", "", false, async () => setViewModeFromMenu("folders")));
    m.appendChild(makeButton("View: Recently added", "", false, async () => setViewModeFromMenu("recent_added")));
    m.appendChild(makeButton("View: Recently watched", "", false, async () => setViewModeFromMenu("recent_watched")));
    m.appendChild(makeButton("View: Favorites", "", false, async () => setViewModeFromMenu("favorites")));
    m.appendChild(makeButton("View: Unrated", "", false, async () => setViewModeFromMenu("unrated")));
    m.appendChild(makeButton("View: Missing thumbnails", "", false, async () => setViewModeFromMenu("missing_thumbnails")));
  }

  function isEmptyAreaContextTarget(target) {
    if (!target || !target.closest) return false;
    if (target.closest(".rsContextMenu")) return false;
    if (target.closest(".rsModal")) return false;
    if (target.closest(".rsCard[data-rs-path]")) return false;
    if (target.closest("button,a,input,select,textarea,video")) return false;

    return !!target.closest(".rsApp");
  }

  function onContextMenu(ev) {
    const card = ev.target && ev.target.closest
      ? ev.target.closest(".rsCard[data-rs-path]")
      : null;

    if (card) {
      const path = card.dataset.rsPath || "";
      if (!path) return;

      ev.preventDefault();
      ev.stopPropagation();

      if (api && typeof api.selectPath === "function") {
        api.selectPath(path, { focus: true });
      }

      renderMenu(path);
      placeMenu(ev.clientX, ev.clientY);
      return;
    }

    if (!isEmptyAreaContextTarget(ev.target)) return;

    ev.preventDefault();
    ev.stopPropagation();

    renderAppMenu();
    placeMenu(ev.clientX, ev.clientY);
  }

  function onKeydown(ev) {
    if (ev.key === "Escape") {
      hideMenu();
      return;
    }

    if ((ev.key === "ContextMenu" || (ev.shiftKey && ev.key === "F10")) && api) {
      const selected = typeof api.selectedVideo === "function" ? api.selectedVideo() : null;
      if (!selected || !selected.path) return;

      ev.preventDefault();
      ev.stopPropagation();

      if (typeof api.selectPath === "function") {
        api.selectPath(selected.path, { focus: true });
      }

      const card = document.querySelector(`.rsCard[data-rs-path="${CSS.escape(selected.path)}"]`);
      const r = card ? card.getBoundingClientRect() : { left: 80, top: 80 };

      renderMenu(selected.path);
      placeMenu(r.left + 24, r.top + 24);
    }
  }

  function install(appApi) {
    api = appApi || api;
    if (installed) return;
    installed = true;

    ensureMenu();

    document.addEventListener("contextmenu", onContextMenu, true);
    document.addEventListener("click", (ev) => {
      if (menu && !menu.hidden && !menu.contains(ev.target)) hideMenu();
    }, true);
    document.addEventListener("keydown", onKeydown, true);
    window.addEventListener("blur", hideMenu);
    window.addEventListener("scroll", hideMenu, true);
    window.addEventListener("resize", hideMenu);
  }

  window.PQNAS_REELSTACK_CONTEXT_MENU = { install };

  window.addEventListener("pqnas-reelstack-ready", (ev) => {
    install(ev.detail);
  });

  if (window.PQNAS_REELSTACK_APP) {
    install(window.PQNAS_REELSTACK_APP);
  }
})();
