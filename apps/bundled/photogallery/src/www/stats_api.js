(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    function num(v, d = 0) {
        const n = Number(v);
        return Number.isFinite(n) ? n : d;
    }

    function str(v, d = "") {
        return v == null ? d : String(v);
    }

    function arr(v) {
        return Array.isArray(v) ? v : [];
    }

    function pickLabel(x) {
        return str(
            x?.label ??
            x?.name ??
            x?.key ??
            x?.value ??
            x?.bucket ??
            x?.month ??
            ""
        ).trim();
    }

    function pickCount(x) {
        return num(
            x?.count ??
            x?.photos ??
            x?.n ??
            x?.items ??
            x?.value_count ??
            0
        );
    }

    function normalizeBuckets(list) {
        return arr(list)
            .map((x) => ({
                label: pickLabel(x),
                count: pickCount(x)
            }))
            .filter((x) => x.label && x.count > 0);
    }

    function normalizeStats(j) {
        const s = j?.stats || j || {};

        const totalBytes = num(
            s.total_bytes ??
            s.bytes_total ??
            s.library_bytes ??
            s.size_bytes_total
        );

        const totalPhotos = num(
            s.total_photos ??
            s.photos_total ??
            s.image_count ??
            s.files_total
        );

        return {
            totalPhotos,
            totalBytes,
            totalMegabytes: totalBytes / (1024 * 1024),

            photosWithExif: num(
                s.photos_with_exif ??
                s.exif_photos ??
                s.photos_with_embedded_meta
            ),

            uniqueCameras: num(
                s.unique_cameras ??
                s.camera_count
            ),

            uniqueLenses: num(
                s.unique_lenses ??
                s.lens_count
            ),

            firstTakenAt: str(
                s.first_taken_at ??
                s.date_range_start ??
                s.first_photo_date
            ),

            lastTakenAt: str(
                s.last_taken_at ??
                s.date_range_end ??
                s.last_photo_date
            ),

            topCameras: normalizeBuckets(
                s.top_cameras ?? s.cameras ?? []
            ),

            topLenses: normalizeBuckets(
                s.top_lenses ?? s.lenses ?? []
            ),

            iso: normalizeBuckets(
                s.iso_buckets ?? s.iso ?? []
            ),

            aperture: normalizeBuckets(
                s.aperture_buckets ?? s.aperture ?? []
            ),

            shutter: normalizeBuckets(
                s.shutter_buckets ?? s.shutter ?? []
            ),

            focal: normalizeBuckets(
                s.focal_length_buckets ?? s.focal ?? s.focal_lengths ?? []
            ),

            byMonth: normalizeBuckets(
                s.by_month ?? s.months ?? []
            )
        };
    }

    async function fetchStats(opts = {}) {
        const baseUrl =
            (PG.api && typeof PG.api.statsUrl === "function")
                ? PG.api.statsUrl()
                : "/api/v4/photogallery/stats";

        const url = new URL(baseUrl, window.location.origin);

        const path =
            opts.path != null
                ? String(opts.path || "")
                : ((typeof PG.getCurrentPath === "function")
                    ? String(PG.getCurrentPath() || "")
                    : "");

        if (path) {
            url.searchParams.set("path", path);
        }

        const r = await fetch(url.toString(), {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg =
                j && (j.message || j.error || j.detail)
                    ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                    : `HTTP ${r.status}`;
            throw new Error(msg || `HTTP ${r.status}`);
        }

        return normalizeStats(j);
    }

    PG.statsApi = {
        fetchStats,
        normalizeStats
    };
})();