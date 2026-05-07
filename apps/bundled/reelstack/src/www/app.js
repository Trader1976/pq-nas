(() => {
  "use strict";

  const VIDEO_EXTS = new Set([
    "mp4", "m4v", "mov", "webm", "mkv", "avi", "wmv", "flv", "mpeg", "mpg", "3gp"
  ]);

  const el = (id) => document.getElementById(id);

  const grid = el("grid");
  const emptyState = el("emptyState");
  const statusText = el("statusText");
  const countText = el("countText");
  const filterInput = el("filterInput");
  const scanBtn = el("scanBtn");

  const modal = el("playerModal");
  const player = el("player");
  const playerTitle = el("playerTitle");
  const playerPath = el("playerPath");
  const closePlayerBtn = el("closePlayerBtn");

  let allVideos = [];

  function setStatus(text) {
    if (statusText) statusText.textContent = text || "";
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

  function basename(path) {
    const s = String(path || "");
    const p = s.split("/").filter(Boolean);
    return p.length ? p[p.length - 1] : "";
  }

  function extOf(name) {
    const s = String(name || "");
    const i = s.lastIndexOf(".");
    return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
  }

  function joinPath(parent, name) {
    parent = String(parent || "").replace(/^\/+|\/+$/g, "");
    name = String(name || "").replace(/^\/+|\/+$/g, "");
    if (!parent) return name;
    if (!name) return parent;
    return `${parent}/${name}`;
  }

  function fileStreamUrl(path) {
    // File Manager video preview uses /api/v4/files/get for preview/open.
    return `/api/v4/files/get?path=${encodeURIComponent(path || "")}`;
  }

  function fileDownloadUrl(path) {
    return `/api/v4/files/download?path=${encodeURIComponent(path || "")}&download=1`;
  }

  function videoMimeForName(name) {
    const ext = extOf(name);
    if (ext === "mp4" || ext === "m4v") return "video/mp4";
    if (ext === "webm") return "video/webm";
    if (ext === "ogv" || ext === "ogg") return "video/ogg";
    if (ext === "mov") return "video/quicktime";
    return "video/mp4";
  }

  function fileDeleteUrl(path) {
    return `/api/v4/files/delete?path=${encodeURIComponent(path)}`;
  }

  async function apiJson(url, opts) {
    const r = await fetch(url, Object.assign({
      cache: "no-store",
      credentials: "include",
      headers: { "Accept": "application/json" }
    }, opts || {}));

    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) {
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
    }
    return j;
  }

  function extractItems(j) {
    if (Array.isArray(j.items)) return j.items;
    if (Array.isArray(j.entries)) return j.entries;
    if (Array.isArray(j.files)) return j.files;
    return [];
  }

  function itemName(item) {
    return item.name || item.filename || basename(item.path || item.rel_path || "");
  }

  function itemPath(parent, item) {
    const direct = item.path || item.rel_path || item.logical_rel_path;
    if (typeof direct === "string" && direct.length) return direct.replace(/^\/+/, "");
    return joinPath(parent, itemName(item));
  }

  function isDir(item) {
    const t = String(item.type || item.kind || "").toLowerCase();
    return t === "dir" || t === "directory" || item.is_dir === true;
  }

  function isFile(item) {
    const t = String(item.type || item.kind || "").toLowerCase();
    return t === "file" || item.is_file === true || (!isDir(item) && itemName(item));
  }

  async function listFolder(path) {
    const url = `/api/v4/files/list?path=${encodeURIComponent(path || "")}`;
    const j = await apiJson(url);
    return extractItems(j);
  }

  async function scanVideos() {
    scanBtn.disabled = true;
    allVideos = [];
    render();

    const queue = [""];
    let folders = 0;
    let seen = 0;
    const maxFolders = 2000;

    try {
      while (queue.length) {
        const folder = queue.shift();
        folders++;

        if (folders > maxFolders) {
          setStatus(`Stopped after ${maxFolders} folders. Found ${allVideos.length} videos.`);
          break;
        }

        setStatus(`Scanning /${folder || ""}`);

        const items = await listFolder(folder);

        for (const item of items) {
          const name = itemName(item);
          const path = itemPath(folder, item);
          if (!name) continue;

          if (isDir(item)) {
            queue.push(path);
            continue;
          }

          if (!isFile(item)) continue;

          seen++;
          if (VIDEO_EXTS.has(extOf(name))) {
            allVideos.push({
              name,
              path,
              size_bytes: item.size_bytes || item.size || 0,
              mtime_epoch: item.mtime_epoch || item.modified_epoch || 0
            });
          }
        }

        if (folders % 8 === 0) render();
      }

      setStatus(`Scan complete. Checked ${seen} files in ${folders} folders.`);
      render();
    } catch (e) {
      setStatus(`Scan failed: ${e && e.message ? e.message : String(e)}`);
    } finally {
      scanBtn.disabled = false;
    }
  }

  function currentFilter() {
    return String(filterInput && filterInput.value || "").trim().toLowerCase();
  }

  function filteredVideos() {
    const q = currentFilter();
    if (!q) return allVideos;
    return allVideos.filter(v =>
      String(v.name || "").toLowerCase().includes(q) ||
      String(v.path || "").toLowerCase().includes(q)
    );
  }

  function render() {
    const videos = filteredVideos();

    if (countText) {
      countText.textContent = `${videos.length} video${videos.length === 1 ? "" : "s"}`;
    }

    if (!grid) return;
    grid.innerHTML = "";

    if (emptyState) {
      emptyState.style.display = allVideos.length ? "none" : "";
    }

    for (const v of videos) {
      const card = document.createElement("article");
      card.className = "rsCard";

      const thumb = document.createElement("div");
      thumb.className = "rsThumb rsThumbPlaceholder";

      const icon = document.createElement("div");
      icon.className = "rsVideoIcon";
      icon.textContent = "▶";

      const play = document.createElement("button");
      play.className = "rsPlay";
      play.type = "button";
      play.textContent = "▶";
      play.title = "Play";
      play.addEventListener("click", () => openPlayer(v));

      thumb.appendChild(icon);
      thumb.appendChild(play);

      const body = document.createElement("div");
      body.className = "rsBody";

      const title = document.createElement("div");
      title.className = "rsTitle";
      title.textContent = v.name;

      const meta = document.createElement("div");
      meta.className = "rsMeta";
      meta.textContent = `${fmtBytes(v.size_bytes)} · /${v.path}`;

      const actions = document.createElement("div");
      actions.className = "rsCardActions";

      const openBtn = document.createElement("button");
      openBtn.className = "rsBtn";
      openBtn.type = "button";
      openBtn.textContent = "Play";
      openBtn.addEventListener("click", () => openPlayer(v));

      const dl = document.createElement("a");
      dl.className = "rsBtn";
      dl.textContent = "Download";
      dl.href = fileDownloadUrl(v.path);
      dl.download = v.name;

      const delBtn = document.createElement("button");
      delBtn.className = "rsBtn";
      delBtn.type = "button";
      delBtn.textContent = "Delete";
      delBtn.addEventListener("click", () => deleteVideo(v));

      actions.appendChild(openBtn);
      actions.appendChild(dl);
      actions.appendChild(delBtn);

      body.appendChild(title);
      body.appendChild(meta);
      body.appendChild(actions);

      card.appendChild(thumb);
      card.appendChild(body);
      grid.appendChild(card);
    }
  }

  function openPlayer(v) {
    if (!modal || !player) return;

    player.pause();
    player.innerHTML = "";
    player.removeAttribute("src");
    player.load();

    playerTitle.textContent = v.name || "Video";
    playerPath.textContent = "/" + (v.path || "");

    const source = document.createElement("source");
    source.src = fileStreamUrl(v.path);
    source.type = videoMimeForName(v.name || v.path || "");
    player.appendChild(source);

    modal.hidden = false;
    player.load();
    player.focus();
  }

  function closePlayer() {
    if (!modal || !player) return;
    player.pause();
    player.innerHTML = "";
    player.removeAttribute("src");
    player.load();
    modal.hidden = true;
  }

  async function deleteVideo(v) {
    if (!v || !v.path) return;

    if (!confirm(`Move this video to trash?\n\n/${v.path}`)) return;

    try {
      setStatus(`Deleting /${v.path}…`);
      await apiJson(fileDeleteUrl(v.path), { method: "POST" });
      allVideos = allVideos.filter(x => x.path !== v.path);
      setStatus(`Moved to trash: ${v.name}`);
      render();
    } catch (e) {
      setStatus(`Delete failed: ${e && e.message ? e.message : String(e)}`);
    }
  }

  scanBtn?.addEventListener("click", scanVideos);
  filterInput?.addEventListener("input", render);
  closePlayerBtn?.addEventListener("click", closePlayer);

  modal?.addEventListener("click", (ev) => {
    if (ev.target === modal) closePlayer();
  });

  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && modal && !modal.hidden) closePlayer();
  });

  setStatus("Ready.");
  render();
})();
