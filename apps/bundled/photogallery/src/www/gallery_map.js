(() => {
    "use strict";

    window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    const mod = {
        runtime: {
            leafletPromise: null,
            map: null,
            markersLayer: null,
            tileLayer: null
        },

        escapeHtml(s) {
            return String(s || "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        },

        destroyMap() {
            if (mod.runtime.map) {
                try { mod.runtime.map.remove(); } catch (_) {}
            }
            mod.runtime.map = null;
            mod.runtime.markersLayer = null;
            mod.runtime.tileLayer = null;
        },

        ensureLeafletLoaded() {
            if (window.L) return Promise.resolve(window.L);
            if (mod.runtime.leafletPromise) return mod.runtime.leafletPromise;

            mod.runtime.leafletPromise = new Promise((resolve, reject) => {
                const cssHref = "./leaflet.css";
                const jsSrc = "./leaflet.js";

                const hasCss = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
                    .some((el) => (el.getAttribute("href") || "") === cssHref);

                if (!hasCss) {
                    const link = document.createElement("link");
                    link.rel = "stylesheet";
                    link.href = cssHref;
                    document.head.appendChild(link);
                }

                const existingScript = Array.from(document.querySelectorAll("script"))
                    .find((el) => (el.getAttribute("src") || "") === jsSrc);

                if (window.L) {
                    resolve(window.L);
                    return;
                }

                if (existingScript) {
                    existingScript.addEventListener("load", () => resolve(window.L), { once: true });
                    existingScript.addEventListener("error", () => reject(new Error("Failed to load Leaflet script")), { once: true });
                    return;
                }

                const script = document.createElement("script");
                script.src = jsSrc;
                script.async = true;
                script.onload = () => {
                    if (window.L) resolve(window.L);
                    else reject(new Error("Leaflet loaded but window.L is missing"));
                };
                script.onerror = () => reject(new Error("Failed to load Leaflet script"));
                document.head.appendChild(script);
            });

            return mod.runtime.leafletPromise;
        },

        buildSideList(items, markerByPath, deps) {
            const list = document.createElement("div");
            list.className = "mapPhotoList";

            for (const item of items) {
                const rel = deps.currentRelPathFor(item);

                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "mapPhotoBtn";

                const main = document.createElement("div");
                main.className = "mapPhotoMain";

                const name = document.createElement("div");
                name.className = "mapPhotoName";
                name.textContent = item.name || "(unnamed)";

                const path = document.createElement("div");
                path.className = "mapPhotoPath";
                path.textContent = "/" + rel;

                const coord = document.createElement("div");
                coord.className = "mapPhotoCoord";
                coord.textContent = `${Number(item.gps_latitude).toFixed(6)}, ${Number(item.gps_longitude).toFixed(6)}`;

                const time = document.createElement("div");
                time.className = "mapPhotoTime";
                time.textContent = deps.fmtTime(item.capture_time_unix || 0) || "no capture time";

                main.appendChild(name);
                main.appendChild(path);
                main.appendChild(coord);
                main.appendChild(time);

                btn.appendChild(main);

                btn.addEventListener("click", () => {
                    const marker = markerByPath.get(rel);
                    if (marker && mod.runtime.map) {
                        mod.runtime.map.setView(marker.getLatLng(), Math.max(mod.runtime.map.getZoom(), 13), { animate: true });
                        marker.openPopup();
                    }
                    deps.openPreviewFor(item);
                });

                list.appendChild(btn);
            }

            return list;
        },

        render(mapCanvas, items, deps) {
            if (!mapCanvas) return;

            mod.destroyMap();
            mapCanvas.replaceChildren();

            if (!items.length) {
                const empty = document.createElement("div");
                empty.className = "emptyState";
                empty.innerHTML = `
                    <div class="h">No photos with location</div>
                    <div class="p">Nothing in the current view has GPS coordinates yet.</div>
                `;
                mapCanvas.appendChild(empty);
                deps.refreshFooterStats?.();
                return;
            }

            const pane = document.createElement("div");
            pane.className = "mapPaneReal";

            const viewport = document.createElement("div");
            viewport.className = "mapViewport";

            const mapHost = document.createElement("div");
            mapHost.className = "mapHost";
            viewport.appendChild(mapHost);

            const side = document.createElement("div");
            side.className = "mapSide";

            const summary = document.createElement("div");
            summary.className = "mapSummary";
            summary.innerHTML = `
                <div class="h">Map</div>
                <div class="p">GPS photos in current view: ${items.length}</div>
            `;

            side.appendChild(summary);
            pane.appendChild(viewport);
            pane.appendChild(side);
            mapCanvas.appendChild(pane);

            deps.refreshFooterStats?.();

            mod.ensureLeafletLoaded().then((L) => {
                if (!mapHost.isConnected) return;

                mod.runtime.map = L.map(mapHost, {
                    zoomControl: true,
                    worldCopyJump: true
                });

                mod.runtime.tileLayer = L.tileLayer(
                    "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
                    {
                        maxZoom: 19,
                        attribution: "&copy; OpenStreetMap contributors"
                    }
                ).addTo(mod.runtime.map);

                mod.runtime.markersLayer = L.layerGroup().addTo(mod.runtime.map);

                const bounds = [];
                const markerByPath = new Map();

                for (const item of items) {
                    const lat = Number(item.gps_latitude);
                    const lon = Number(item.gps_longitude);
                    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;

                    const rel = deps.currentRelPathFor(item);
                    const marker = L.marker([lat, lon]);

                    const popupHtml = `
                        <div class="mapLeafletPopup">
                            <div class="mapLeafletPopupTitle">${mod.escapeHtml(item.name || "(unnamed)")}</div>
                            <div class="mapLeafletPopupMeta">
                                <div>${mod.escapeHtml("/" + rel)}</div>
                                <div>${mod.escapeHtml(deps.fmtTime(item.capture_time_unix || 0) || "no capture time")}</div>
                                <div>${mod.escapeHtml(lat.toFixed(6) + ", " + lon.toFixed(6))}</div>
                            </div>
                        </div>
                    `;

                    marker.bindPopup(popupHtml);
                    marker.on("click", () => {
                        deps.openPreviewFor(item);
                    });

                    marker.addTo(mod.runtime.markersLayer);
                    markerByPath.set(rel, marker);
                    bounds.push([lat, lon]);
                }

                side.appendChild(mod.buildSideList(items, markerByPath, deps));

                if (bounds.length === 1) {
                    mod.runtime.map.setView(bounds[0], 13);
                } else if (bounds.length > 1) {
                    mod.runtime.map.fitBounds(bounds, { padding: [28, 28] });
                } else {
                    mod.runtime.map.setView([0, 0], 2);
                }

                window.setTimeout(() => {
                    try { mod.runtime.map.invalidateSize(); } catch (_) {}
                }, 0);
            }).catch((e) => {
                if (!mapHost.isConnected) return;

                const msg = String(e && e.message ? e.message : e || "Map failed to load");
                viewport.replaceChildren();

                const errBox = document.createElement("div");
                errBox.className = "emptyState";
                errBox.innerHTML = `
                    <div class="h">Map failed to load</div>
                    <div class="p">${mod.escapeHtml(msg)}</div>
                `;
                viewport.appendChild(errBox);
            });
        }
    };

    window.PQNAS_PHOTOGALLERY.map = mod;
})();