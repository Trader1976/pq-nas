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
  const metaCache = new Map();
  const metaInFlight = new Set();

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

  function fileThumbUrl(path) {
    return `/api/v4/reelstack/thumb?path=${encodeURIComponent(path || "")}&size=480`;
  }


  function fileMetaUrl(path) {
    return `/api/v4/reelstack/meta?path=${encodeURIComponent(path || "")}`;
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

  function fmtBitrate(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "";
    if (n >= 1000000) return `${(n / 1000000).toFixed(1)} Mbps`;
    if (n >= 1000) return `${(n / 1000).toFixed(0)} Kbps`;
    return `${Math.round(n)} bps`;
  }

  function fmtFps(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "";
    return `${n.toFixed(n >= 10 ? 0 : 1)} fps`;
  }

  function metaForVideo(v) {
    if (!v || !v.path) return null;
    return v.meta || metaCache.get(v.path) || null;
  }

  function videoMetaSummary(v) {
    const m = metaForVideo(v);
    if (!m) return "Metadata loading…";
    if (m._error) return `Metadata unavailable: ${m._error}`;

    const parts = [];
    if (m.duration_text) parts.push(m.duration_text);
    if (m.resolution) parts.push(m.resolution);
    if (m.fps) parts.push(fmtFps(m.fps));
    if (m.video_codec) parts.push(String(m.video_codec).toUpperCase());
    if (m.audio_codec) parts.push(`audio ${String(m.audio_codec).toUpperCase()}`);
    if (m.bit_rate) parts.push(fmtBitrate(m.bit_rate));

    return parts.filter(Boolean).join(" · ") || "No metadata";
  }

  function durationBadgeText(v) {
    const m = metaForVideo(v);
    if (!m || m._error || !m.duration_text) return "";
    return String(m.duration_text);
  }

  function updateMetaEls(path) {
    for (const node of document.querySelectorAll("[data-rs-meta-path]")) {
      if (node.dataset.rsMetaPath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        node.textContent = videoMetaSummary(v);
      }
    }

    for (const node of document.querySelectorAll("[data-rs-duration-path]")) {
      if (node.dataset.rsDurationPath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        const txt = durationBadgeText(v);
        node.textContent = txt;
        node.style.display = txt ? "" : "none";
      }
    }
  }

  async function ensureVideoMeta(v) {
    if (!v || !v.path) return;

    if (metaCache.has(v.path)) {
      v.meta = metaCache.get(v.path);
      updateMetaEls(v.path);
      return;
    }

    if (metaInFlight.has(v.path)) return;
    metaInFlight.add(v.path);

    try {
      const j = await apiJson(fileMetaUrl(v.path));
      metaCache.set(v.path, j);
      v.meta = j;
      updateMetaEls(v.path);
    } catch (e) {
      const err = { _error: String(e && e.message ? e.message : e) };
      metaCache.set(v.path, err);
      v.meta = err;
      updateMetaEls(v.path);
    } finally {
      metaInFlight.delete(v.path);
    }
  }

  function queueMetadataLoads(videos) {
    const list = Array.isArray(videos) ? videos.slice(0, 48) : [];
    if (!list.length) return;

    window.setTimeout(() => {
      for (const v of list) {
        if (v && v.path && !metaCache.has(v.path)) {
          ensureVideoMeta(v);
        }
      }
    }, 0);
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

  function normalizeVideoItem(item) {
    item = item || {};

    const directPath = item.path || item.rel_path || item.logical_rel_path || "";
    const path = String(directPath || "").replace(/^\/+/, "");
    const name = item.name || item.filename || basename(path);

    return {
      name,
      path,
      size_bytes: Number(item.size_bytes || item.size || 0),
      mtime_epoch: Number(item.mtime_epoch || item.modified_epoch || 0),
      duration_seconds: Number(item.duration_seconds || 0),
      width: Number(item.width || 0),
      height: Number(item.height || 0),
      source: item.source || ""
    };
  }

  function applyIndexResponse(j, verb) {
    const items = extractItems(j)
      .map(normalizeVideoItem)
      .filter(v => v.path && VIDEO_EXTS.has(extOf(v.name || v.path)));

    allVideos = items;
    render();

    const stats = j && j.stats ? j.stats : {};
    const generated = Number(j && j.generated_at_epoch || 0);
    const warningCount = Array.isArray(j && j.warnings) ? j.warnings.length : 0;
    const truncated = !!stats.truncated;

    if (!generated && !items.length) {
      setStatus("No saved Reel Stack index yet. Click Refresh index.");
      return;
    }

    const parts = [
      `${verb || "Loaded"} ${items.length} video${items.length === 1 ? "" : "s"}`
    ];

    if (Number.isFinite(Number(stats.files_seen)) && Number(stats.files_seen) > 0) {
      parts.push(`checked ${Number(stats.files_seen)} file${Number(stats.files_seen) === 1 ? "" : "s"}`);
    }

    if (generated > 0) {
      parts.push(`indexed ${new Date(generated * 1000).toLocaleString()}`);
    }

    if (truncated) parts.push("truncated");
    if (warningCount) parts.push(`${warningCount} warning${warningCount === 1 ? "" : "s"}`);

    setStatus(parts.join(" · "));
  }

  async function loadIndex() {
    setStatus("Loading saved Reel Stack index…");
    const j = await apiJson("/api/v4/reelstack/index");
    applyIndexResponse(j, "Loaded");
  }

  async function scanVideos() {
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Refreshing…";
    }

    try {
      setStatus("Refreshing Reel Stack index…");

      const j = await apiJson("/api/v4/reelstack/scan", {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: "{}"
      });

      applyIndexResponse(j, "Refreshed");
    } catch (e) {
      setStatus(`Refresh failed: ${e && e.message ? e.message : String(e)}`);
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = "Refresh index";
      }
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

      const img = document.createElement("img");
      img.loading = "lazy";
      img.decoding = "async";
      img.alt = "";
      img.addEventListener("load", () => {
        thumb.classList.remove("rsThumbPlaceholder");
      });
      img.addEventListener("error", () => {
        try { img.remove(); } catch (_) {}
        thumb.classList.add("rsThumbPlaceholder");
      }, { once: true });
      img.src = fileThumbUrl(v.path);

      const play = document.createElement("button");
      play.className = "rsPlay";
      play.type = "button";
      play.textContent = "▶";
      play.title = "Play";
      play.addEventListener("click", () => openPlayer(v));

      thumb.appendChild(img);
      const durationBadge = document.createElement("div");
      durationBadge.className = "rsDurationBadge";
      durationBadge.dataset.rsDurationPath = v.path;
      durationBadge.textContent = durationBadgeText(v);
      durationBadge.style.display = durationBadge.textContent ? "" : "none";

      thumb.appendChild(icon);
      thumb.appendChild(play);
      thumb.appendChild(durationBadge);

      const body = document.createElement("div");
      body.className = "rsBody";

      const title = document.createElement("div");
      title.className = "rsTitle";
      title.textContent = v.name;

      const meta = document.createElement("div");
      meta.className = "rsMeta";
      meta.textContent = `${fmtBytes(v.size_bytes)} · /${v.path}`;

      const details = document.createElement("div");
      details.className = "rsDetails";
      details.dataset.rsMetaPath = v.path;
      details.textContent = videoMetaSummary(v);

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
      body.appendChild(details);
      body.appendChild(actions);

      card.appendChild(thumb);
      card.appendChild(body);
      grid.appendChild(card);
    }

    queueMetadataLoads(videos);
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

  loadIndex().catch((e) => {
    setStatus(`Could not load saved index: ${e && e.message ? e.message : String(e)}`);
    render();
  });

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
