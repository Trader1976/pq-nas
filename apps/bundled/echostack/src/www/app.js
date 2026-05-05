(() => {
  "use strict";

  const API = "/api/v4/echostack";

  const el = (id) => document.getElementById(id);

  const state = {
    items: [],
    q: ""
  };

  function setStatus(msg, kind) {
    const s = el("status");
    if (!s) return;
    s.textContent = msg || "";
    s.className = "status" + (kind ? ` ${kind}` : "");
  }

  async function api(path, opts = {}) {
    const r = await fetch(API + path, {
      credentials: "include",
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        ...(opts.body ? { "Content-Type": "application/json" } : {})
      },
      ...opts
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) {
      const reason = j.archive_error || j.error || j.message || `HTTP ${r.status}`;
      const detail = j.message && j.message !== reason ? `${reason}: ${j.message}` : reason;
      throw new Error(detail);
    }
    return j;
  }

  function fmtTime(epoch) {
    const n = Number(epoch || 0);
    if (!n) return "";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch {
      return "";
    }
  }

  function faviconFromUrl(url) {
    try {
      const u = new URL(url);
      return `${u.origin}/favicon.ico`;
    } catch {
      return "";
    }
  }

  function metaLine(item) {
    const parts = [];

    if (item.site_name) parts.push(item.site_name);
    if (item.collection) parts.push(`Collection: ${item.collection}`);
    if (item.tags_text) parts.push(`Tags: ${item.tags_text}`);
    if (item.favorite) parts.push("Favorite");

    const archive = item.archive_status || "none";
    if (archive === "none") {
      parts.push("Saved link");
    } else if (archive === "failed" && item.archive_error) {
      parts.push(`Archive: failed — ${item.archive_error}`);
    } else {
      parts.push(`Archive: ${archive}`);
    }

    const t = fmtTime(item.created_epoch);
    if (t) parts.push(t);

    return parts.join(" • ");
  }

  async function loadItems() {
    const q = state.q ? `?q=${encodeURIComponent(state.q)}` : "";
    const j = await api(`/items${q}`);
    state.items = Array.isArray(j.items) ? j.items : [];
    render();
  }

  function render() {
    const root = el("items");
    const tpl = el("itemTemplate");
    if (!root || !tpl) return;

    root.innerHTML = "";

    if (!state.items.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No links saved yet. Paste a URL above to start your stack.";
      root.appendChild(empty);
      return;
    }

    for (const item of state.items) {
      const node = tpl.content.firstElementChild.cloneNode(true);

      const title = node.querySelector(".itemTitle");
      const url = node.querySelector(".itemUrl");
      const meta = node.querySelector(".itemMeta");
      const notes = node.querySelector(".itemNotes");
      const favBtn = node.querySelector(".favBtn");
      const readBtn = node.querySelector(".readBtn");
      const saveBtn = node.querySelector(".saveItemBtn");
      const deleteBtn = node.querySelector(".deleteBtn");
      const archiveStatus = item.archive_status || "none";

      const head = document.createElement("div");
      head.className = "itemHead";

      const fav = document.createElement("img");
      fav.className = "favicon";
      fav.alt = "";
      fav.loading = "lazy";
      fav.referrerPolicy = "no-referrer";
      const favSrc = item.favicon_url || "";
      if (favSrc) {
        fav.src = favSrc;
      } else {
        fav.style.display = "none";
      }

      fav.onerror = () => {
        fav.style.display = "none";
      };

      const titleWrap = document.createElement("div");
      titleWrap.className = "itemTitleWrap";

      title.textContent = item.title || item.url || "Untitled";

      const stateBadge = document.createElement("span");
      stateBadge.className = `readBadge ${item.read_state === "read" ? "read" : "unread"}`;
      stateBadge.textContent = item.read_state === "read" ? "Read" : "Unread";

      titleWrap.appendChild(title);
      titleWrap.appendChild(stateBadge);
      head.appendChild(fav);
      head.appendChild(titleWrap);

      node.querySelector(".itemMain").prepend(head);

      url.href = item.url || "#";
      url.textContent = item.url || "";

      if (item.description) {
        const desc = document.createElement("div");
        desc.className = "itemDescription";
        desc.textContent = item.description;
        url.insertAdjacentElement("afterend", desc);
      }

      if (item.preview_image_url) {
        const previewWrap = document.createElement("a");
        previewWrap.className = "itemPreview";
        previewWrap.href = item.url || item.preview_image_url;
        previewWrap.target = "_blank";
        previewWrap.rel = "noopener noreferrer";

        const previewImg = document.createElement("img");
        previewImg.alt = "";
        previewImg.loading = "lazy";
        previewImg.referrerPolicy = "no-referrer";
        previewImg.src = item.preview_image_url;
        previewImg.onerror = () => {
          previewWrap.remove();
        };

        previewWrap.appendChild(previewImg);

        const descEl = node.querySelector(".itemDescription");
        if (descEl) {
          descEl.insertAdjacentElement("afterend", previewWrap);
        } else {
          url.insertAdjacentElement("afterend", previewWrap);
        }
      }

      meta.textContent = metaLine(item);
      notes.value = item.notes || "";

      favBtn.textContent = item.favorite ? "★ Favorite" : "☆ Favorite";
      readBtn.textContent = item.read_state === "read" ? "Mark unread" : "Mark read";

      favBtn.addEventListener("click", async () => {
        await updateItem(item.id, { favorite: !item.favorite });
      });

      readBtn.addEventListener("click", async () => {
        await updateItem(item.id, {
          read_state: item.read_state === "read" ? "unread" : "read"
        });
      });

      if (archiveStatus === "archived") {
        const openArchiveBtn = document.createElement("button");
        openArchiveBtn.type = "button";
        openArchiveBtn.textContent = "Open archive";
        openArchiveBtn.addEventListener("click", () => {
          window.open(`${API}/archive/view?id=${encodeURIComponent(item.id)}`, "_blank", "noopener,noreferrer");
        });
        node.querySelector(".itemActions").insertBefore(openArchiveBtn, saveBtn);
      } else if (archiveStatus === "archiving") {
        const archivingBtn = document.createElement("button");
        archivingBtn.type = "button";
        archivingBtn.textContent = "Archiving…";
        archivingBtn.disabled = true;
        node.querySelector(".itemActions").insertBefore(archivingBtn, saveBtn);
      } else {
        const archiveBtn = document.createElement("button");
        archiveBtn.type = "button";
        archiveBtn.textContent = archiveStatus === "failed" ? "Retry archive" : "Archive";
        archiveBtn.addEventListener("click", () => {
          archiveItem(item.id);
        });
        node.querySelector(".itemActions").insertBefore(archiveBtn, saveBtn);
      }
      saveBtn.addEventListener("click", async () => {
        await updateItem(item.id, { notes: notes.value || "" });
      });

      deleteBtn.addEventListener("click", async () => {
        const ok = confirm("Delete this Echo Stack item?");
        if (!ok) return;
        await deleteItem(item.id);
      });

      root.appendChild(node);
    }
  }

  async function saveNewItem() {
    const url = (el("urlInput")?.value || "").trim();
    const title = (el("titleInput")?.value || "").trim();
    const collection = (el("collectionInput")?.value || "").trim();
    const tags = (el("tagsInput")?.value || "").trim();
    const notes = (el("notesInput")?.value || "").trim();

    if (!url) {
      setStatus("Paste a URL first.", "bad");
      return;
    }

    setStatus("Fetching preview…");

    let preview = {};
    try {
      preview = await api("/preview", {
        method: "POST",
        body: JSON.stringify({ url })
      });
    } catch (e) {
      // Preview is best-effort. Saving the link should still work.
      preview = {};
    }

    setStatus("Saving…");

    await api("/items/create", {
      method: "POST",
      body: JSON.stringify({
        url,
        final_url: preview.final_url || "",
        title: title || preview.title || url,
        description: preview.description || "",
        site_name: preview.site_name || "",
        favicon_url: preview.favicon_url || faviconFromUrl(url),
        preview_image_url: preview.preview_image_url || "",
        collection,
        tags_text: tags,
        notes,
        read_state: "unread"
      })
    });

    el("urlInput").value = "";
    el("titleInput").value = "";
    el("notesInput").value = "";

    setStatus("Saved.", "good");
    await loadItems();
  }

  async function updateItem(id, patch) {
    setStatus("Saving changes…");
    await api("/items/update", {
      method: "POST",
      body: JSON.stringify({ id, ...patch })
    });
    setStatus("Updated.", "good");
    await loadItems();
  }

  async function deleteItem(id) {
    setStatus("Deleting…");
    await api("/items/delete", {
      method: "POST",
      body: JSON.stringify({ id })
    });
    setStatus("Deleted.", "good");
    await loadItems();
  }

  async function archiveItem(id) {
    setStatus("Archiving page snapshot…");

    try {
      const j = await api("/items/archive", {
        method: "POST",
        body: JSON.stringify({ id })
      });

      if (j.already_archived) {
        setStatus("Already archived.", "good");
      } else {
        setStatus("Archived.", "good");
      }
    } catch (e) {
      setStatus(`Archive failed: ${e.message || String(e)}`, "bad");
    } finally {
      try {
        await loadItems();
      } catch (_) {
        // Keep the archive error visible if refresh itself fails.
      }
    }
  }

  function bind() {
    el("saveBtn")?.addEventListener("click", () => {
      saveNewItem().catch((e) => setStatus(e.message || String(e), "bad"));
    });

    el("archiveBtn")?.addEventListener("click", async () => {
      try {
        await saveNewItem();
        setStatus("Saved. Use Archive on the item card to store the HTML snapshot.", "good");
      } catch (err) {
        setStatus(err.message || String(err), "bad");
      }
    });

    el("refreshBtn")?.addEventListener("click", () => {
      loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
    });

    el("searchInput")?.addEventListener("input", () => {
      state.q = (el("searchInput").value || "").trim();
      clearTimeout(bind._timer);
      bind._timer = setTimeout(() => {
        loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
      }, 220);
    });

    el("urlInput")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        saveNewItem().catch((err) => setStatus(err.message || String(err), "bad"));
      }
    });
  }

  bind();
  loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
})();
