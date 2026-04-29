(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY || {};
    const el = (id) => document.getElementById(id);

    const filterInput = el("filterInput");
    if (!filterInput || typeof PG.registerSearchFilterProvider !== "function") return;

    const anchor = el("statsBtn") || el("refreshBtn") || filterInput;
    const toolbar = filterInput.closest(".toolbar") || filterInput.parentElement || document.body;

    const btn = document.createElement("button");
    btn.id = "exifSearchToggleBtn";
    btn.type = "button";
    btn.className = "btn secondary";
    btn.textContent = "EXIF";
    btn.title = "Advanced EXIF search";

    if (anchor && anchor.parentNode) {
        anchor.parentNode.insertBefore(btn, anchor);
    }

    const panel = document.createElement("div");
    panel.id = "exifSearchPanel";
    panel.className = "exifSearchPanel";
    panel.hidden = true;

    panel.innerHTML = `
        <div class="exifSearchHead">
            <div>
                <div class="exifSearchTitle">Advanced EXIF search</div>
                <div class="exifSearchSub">Filter photos by camera, lens, ISO, GPS, and capture date.</div>
            </div>
            <button id="exifSearchClearBtn" class="btn secondary" type="button">Clear EXIF filters</button>
        </div>

        <div class="exifSearchGrid">
            <label>
                <span>Camera make</span>
                <input id="exifMakeInput" class="input" type="text" placeholder="Panasonic, Samsung, Canon…">
            </label>

            <label>
                <span>Camera model</span>
                <input id="exifModelInput" class="input" type="text" placeholder="DMC-G7, GT-I9505…">
            </label>

            <label>
                <span>Lens</span>
                <input id="exifLensInput" class="input" type="text" placeholder="Lumix, 25mm, Leica…">
            </label>

            <label>
                <span>ISO</span>
                <input id="exifIsoInput" class="input" type="text" placeholder="200 or 100-800 or 200,400">
            </label>

            <label>
                <span>GPS</span>
                <select id="exifGpsSelect" class="input">
                    <option value="">Any</option>
                    <option value="yes">Has GPS</option>
                    <option value="no">No GPS</option>
                </select>
            </label>

            <label>
                <span>Taken from</span>
                <input id="exifDateFromInput" class="input" type="date">
            </label>

            <label>
                <span>Taken to</span>
                <input id="exifDateToInput" class="input" type="date">
            </label>
        </div>
    `;

    if (toolbar && toolbar.parentNode) {
        toolbar.parentNode.insertBefore(panel, toolbar.nextSibling);
    } else {
        document.body.appendChild(panel);
    }

    const fields = {
        make: el("exifMakeInput"),
        model: el("exifModelInput"),
        lens: el("exifLensInput"),
        iso: el("exifIsoInput"),
        gps: el("exifGpsSelect"),
        from: el("exifDateFromInput"),
        to: el("exifDateToInput"),
        clear: el("exifSearchClearBtn")
    };

    const norm = (v) => String(v == null ? "" : v).trim().toLowerCase();

    function textContains(value, query) {
        const q = norm(query);
        if (!q) return true;
        return norm(value).includes(q);
    }

    function parseIsoMatcher(raw) {
        const s = String(raw || "").trim();
        if (!s) return null;

        if (s.includes(",")) {
            const vals = s.split(",")
                .map(v => Number(String(v).trim()))
                .filter(v => Number.isFinite(v) && v > 0);
            if (!vals.length) return null;
            return (iso) => vals.includes(Number(iso || 0));
        }

        const m = s.match(/^(\d+)\s*-\s*(\d+)$/);
        if (m) {
            const a = Number(m[1]);
            const b = Number(m[2]);
            if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
            const lo = Math.min(a, b);
            const hi = Math.max(a, b);
            return (iso) => Number(iso || 0) >= lo && Number(iso || 0) <= hi;
        }

        const exact = Number(s);
        if (!Number.isFinite(exact) || exact <= 0) return null;
        return (iso) => Number(iso || 0) === exact;
    }

    function dateStartEpoch(dateText) {
        if (!dateText) return 0;
        const t = new Date(`${dateText}T00:00:00`).getTime();
        return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
    }

    function dateEndEpoch(dateText) {
        if (!dateText) return 0;
        const t = new Date(`${dateText}T23:59:59`).getTime();
        return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
    }

    function getValues() {
        return {
            make: fields.make ? fields.make.value.trim() : "",
            model: fields.model ? fields.model.value.trim() : "",
            lens: fields.lens ? fields.lens.value.trim() : "",
            iso: fields.iso ? fields.iso.value.trim() : "",
            gps: fields.gps ? fields.gps.value : "",
            from: fields.from ? fields.from.value : "",
            to: fields.to ? fields.to.value : ""
        };
    }

    function isActive() {
        const v = getValues();
        return !!(v.make || v.model || v.lens || v.iso || v.gps || v.from || v.to);
    }

    function summary() {
        const v = getValues();
        const bits = [];

        if (v.make) bits.push(`make:${v.make}`);
        if (v.model) bits.push(`model:${v.model}`);
        if (v.lens) bits.push(`lens:${v.lens}`);
        if (v.iso) bits.push(`ISO:${v.iso}`);
        if (v.gps === "yes") bits.push("GPS");
        if (v.gps === "no") bits.push("no GPS");
        if (v.from || v.to) bits.push(`date:${v.from || "…"}–${v.to || "…"}`);

        return bits.length ? `EXIF ${bits.join(" ")}` : "";
    }

    function matches(item) {
        if (!item || item.type !== "file") return false;

        const v = getValues();
        const exif = item.exif && typeof item.exif === "object" ? item.exif : {};

        if (v.make && !textContains(exif.make, v.make)) return false;
        if (v.model && !textContains(exif.model, v.model)) return false;
        if (v.lens && !textContains(exif.lens_model, v.lens)) return false;

        const isoMatcher = parseIsoMatcher(v.iso);
        if (isoMatcher && !isoMatcher(exif.iso)) return false;

        if (v.gps === "yes" && !item.has_gps) return false;
        if (v.gps === "no" && item.has_gps) return false;

        const ts = Number(item.capture_time_unix || 0);
        const from = dateStartEpoch(v.from);
        const to = dateEndEpoch(v.to);

        if (from && (!ts || ts < from)) return false;
        if (to && (!ts || ts > to)) return false;

        return true;
    }

    const provider = { isActive, matches, summary };
    PG.registerSearchFilterProvider(provider);

    let timer = 0;

    function refreshSoon(force = false) {
        btn.classList.toggle("active", isActive());

        window.clearTimeout(timer);
        timer = window.setTimeout(() => {
            if (typeof PG.refreshSearchFilters === "function") {
                PG.refreshSearchFilters(force);
            } else if (typeof PG.reload === "function") {
                PG.reload(force);
            }
        }, 160);
    }

    btn.addEventListener("click", () => {
        panel.hidden = !panel.hidden;
        btn.classList.toggle("active", !panel.hidden || isActive());
    });

    for (const key of ["make", "model", "lens", "iso", "from", "to"]) {
        fields[key]?.addEventListener("input", () => refreshSoon(false));
        fields[key]?.addEventListener("change", () => refreshSoon(false));
    }

    fields.gps?.addEventListener("change", () => refreshSoon(false));

    fields.clear?.addEventListener("click", () => {
        for (const key of ["make", "model", "lens", "iso", "from", "to"]) {
            if (fields[key]) fields[key].value = "";
        }
        if (fields.gps) fields.gps.value = "";
        refreshSoon(false);
    });
})();
