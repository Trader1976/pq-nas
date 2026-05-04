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
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
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

    if (item.collection) parts.push(`Collection: ${item.collection}`);
    if (item.tags_text) parts.push(`Tags: ${item.tags_text}`);
    if (item.favorite) parts.push("Favorite");

    const archive = item.archive_status || "none";
    parts.push(archive === "none" ? "Saved link" : `Archive: ${archive}`);

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

      const head = document.createElement("div");
      head.className = "itemHead";

      const fav = document.createElement("img");
      fav.className = "favicon";
      fav.alt = "";
      fav.loading = "lazy";
      fav.referrerPolicy = "no-referrer";
      fav.src = item.favicon_url || faviconFromUrl(item.url);
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

    setStatus("Saving…");

    await api("/items/create", {
      method: "POST",
      body: JSON.stringify({
        url,
        title,
        collection,
        tags_text: tags,
        notes,
        read_state: "unread",
        favicon_url: faviconFromUrl(url)
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

  function bind() {
    el("saveBtn")?.addEventListener("click", () => {
      saveNewItem().catch((e) => setStatus(e.message || String(e), "bad"));
    });

    el("archiveBtn")?.addEventListener("click", () => {
      setStatus("Archiving comes in the quota-safe archive patch.", "bad");
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
