(() => {
    "use strict";

    const el = (id) => document.getElementById(id);

    const detailsEl = el("metaEmbeddedDetails");
    const stateEl = el("metaEmbeddedState");
    const bodyEl = el("metaEmbeddedBody");

    let currentPath = "";
    let lastLoadedPath = "";
    let loading = false;

    function setState(text) {
        if (stateEl) stateEl.textContent = String(text || "");
    }

    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function isPlainObject(v) {
        return !!v && typeof v === "object" && !Array.isArray(v);
    }

    function renderGroup(title, obj) {
        const wrap = document.createElement("div");
        wrap.className = "embeddedGroup";

        const h = document.createElement("div");
        h.className = "embeddedGroupTitle";
        h.textContent = title;
        wrap.appendChild(h);

        if (!isPlainObject(obj) || !Object.keys(obj).length) {
            const empty = document.createElement("div");
            empty.className = "mono";
            empty.style.opacity = ".72";
            empty.textContent = "No fields found.";
            wrap.appendChild(empty);
            return wrap;
        }

        const grid = document.createElement("div");
        grid.className = "embeddedKv";

        for (const [k, v] of Object.entries(obj)) {
            const kEl = document.createElement("div");
            kEl.className = "embeddedK";
            kEl.textContent = k;

            const vEl = document.createElement("div");
            vEl.className = "embeddedV";

            if (Array.isArray(v)) {
                vEl.textContent = v.map(x => String(x)).join(", ");
            } else if (isPlainObject(v)) {
                const pre = document.createElement("pre");
                pre.className = "embeddedPre mono";
                pre.textContent = JSON.stringify(v, null, 2);
                vEl.appendChild(pre);
            } else {
                vEl.textContent = String(v == null ? "" : v);
            }

            grid.appendChild(kEl);
            grid.appendChild(vEl);
        }

        wrap.appendChild(grid);
        return wrap;
    }

    function renderPayload(j) {
        if (!bodyEl) return;
        bodyEl.innerHTML = "";

        const embedded = j && j.embedded && typeof j.embedded === "object" ? j.embedded : {};
        const summary = j && j.summary && typeof j.summary === "object" ? j.summary : {};

        const hasSummary = Object.keys(summary).length > 0;
        const hasExif = embedded.exif && Object.keys(embedded.exif).length > 0;
        const hasIptc = embedded.iptc && Object.keys(embedded.iptc).length > 0;
        const hasXmp = embedded.xmp && Object.keys(embedded.xmp).length > 0;

        if (!hasSummary && !hasExif && !hasIptc && !hasXmp) {
            const d = document.createElement("div");
            d.className = "mono";
            d.style.opacity = ".75";
            d.textContent = "No embedded metadata found in this image.";
            bodyEl.appendChild(d);
            return;
        }

        if (hasSummary) bodyEl.appendChild(renderGroup("Summary", summary));
        if (hasExif) bodyEl.appendChild(renderGroup("EXIF", embedded.exif));
        if (hasIptc) bodyEl.appendChild(renderGroup("IPTC", embedded.iptc));
        if (hasXmp) bodyEl.appendChild(renderGroup("XMP", embedded.xmp));
    }

    async function loadForCurrentPath(force = false) {
        if (!currentPath || !detailsEl || !detailsEl.open) return;
        if (loading) return;
        if (!force && lastLoadedPath === currentPath) return;

        loading = true;
        setState("Loading…");

        if (bodyEl) {
            bodyEl.innerHTML = `<div class="mono" style="opacity:.75;">Loading embedded metadata…</div>`;
        }

        try {
            const r = await fetch("/api/v4/gallery/meta/embedded_get", {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({ path: currentPath })
            });

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.detail || j.message || j.error)
                    ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            renderPayload(j);
            lastLoadedPath = currentPath;
            setState("Loaded");
        } catch (e) {
            if (bodyEl) {
                bodyEl.innerHTML =
                    `<div class="mono" style="opacity:.82;">Could not load embedded metadata: ${escapeHtml(String(e && e.message ? e.message : e))}</div>`;
            }
            setState("Unavailable");
        } finally {
            loading = false;
        }
    }

    function reset(path) {
        currentPath = String(path || "");
        lastLoadedPath = "";
        loading = false;

        if (detailsEl) detailsEl.open = false;
        if (bodyEl) {
            bodyEl.innerHTML =
                `<div class="mono" style="opacity:.75;">Open this section to load metadata stored inside the image file itself.</div>`;
        }
        setState("Hidden");
    }

    detailsEl?.addEventListener("toggle", () => {
        if (detailsEl.open) {
            loadForCurrentPath(false);
        } else {
            setState("Hidden");
        }
    });

    window.PQNAS_PHOTOGALLERY_EMBEDDED_META = {
        reset,
        refresh: () => loadForCurrentPath(true)
    };
})();