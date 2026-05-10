(function () {
    "use strict";

    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function fileExtLower(name) {
        const base = String(name || "").split("/").pop().split("?")[0].split("#")[0];
        const i = base.lastIndexOf(".");
        if (i < 0 || i === base.length - 1) return "";
        return base.slice(i + 1).toLowerCase();
    }

    function normalizeIconExt(ext) {
        const e = String(ext || "").toLowerCase();
        const aliases = {
            jpeg: "jpg",
            jpe: "jpg",
            htm: "html",
            xhtml: "html",
            markdown: "md",
            text: "txt",
            yml: "yaml",
            tgz: "gz",
            cxx: "cpp",
            cc: "cpp",
            hpp: "h",
            hxx: "h",
            m4v: "mp4",
            tif: "tiff"
        };
        return aliases[e] || e;
    }

    function iconMarkupFor(name, isDir) {
        const icons = window.PQNAS_FILE_ICONS || {};

        if (isDir) {
            return icons.folder || icons.directory || icons.default || "";
        }

        const ext = normalizeIconExt(fileExtLower(name));
        if (ext && icons[ext]) return icons[ext];

        const genericMap = {
            zip: "generic_archive", "7z": "generic_archive", rar: "generic_archive",
            tar: "generic_archive", gz: "generic_archive", bz2: "generic_archive",
            xz: "generic_archive", deb: "generic_archive", rpm: "generic_archive",
            dmg: "generic_archive", apk: "generic_archive",

            mp3: "generic_audio", wav: "generic_audio", ogg: "generic_audio",
            flac: "generic_audio", m4a: "generic_audio", aac: "generic_audio",

            mp4: "generic_video", mov: "generic_video", mkv: "generic_video",
            avi: "generic_video", webm: "generic_video",

            png: "generic_image", jpg: "generic_image", gif: "generic_image",
            bmp: "generic_image", svg: "generic_image", webp: "generic_image",
            tiff: "generic_image", ico: "generic_image", heic: "generic_image",

            xls: "generic_spreadsheet", xlsx: "generic_spreadsheet",
            csv: "generic_spreadsheet", ods: "generic_spreadsheet",

            ppt: "generic_presentation", pptx: "generic_presentation",
            odp: "generic_presentation", key: "generic_presentation",

            doc: "generic_document", docx: "generic_document", pdf: "generic_document",
            txt: "generic_document", md: "generic_document", rtf: "generic_document",
            odt: "generic_document", ini: "generic_document", cfg: "generic_document",
            conf: "generic_document", log: "generic_document",

            db: "generic_database", sqlite: "generic_database", sql: "generic_database",

            c: "generic_code", cpp: "generic_code", h: "generic_code",
            java: "generic_code", kt: "generic_code", ts: "generic_code",
            tsx: "generic_code", js: "generic_code", jsx: "generic_code",
            json: "generic_code", html: "generic_code", css: "generic_code",
            scss: "generic_code", php: "generic_code", py: "generic_code",
            rb: "generic_code", rs: "generic_code", go: "generic_code",
            sh: "generic_code", bash: "generic_code", zsh: "generic_code",
            lua: "generic_code", swift: "generic_code", xml: "generic_code",
            yaml: "generic_code", toml: "generic_code", so: "generic_code",
            dll: "generic_code", exe: "generic_code"
        };

        const generic = ext ? genericMap[ext] : "";
        if (generic && icons[generic]) return icons[generic];

        return icons.default || "";
    }

    function fileIconHtml(name, isDir) {
        const svg = iconMarkupFor(name, !!isDir);
        if (svg && String(svg).trim().startsWith("<svg")) {
            return `<div class="fileIcon svgFileIcon" aria-hidden="true">${svg}</div>`;
        }

        return `<div class="fileIcon">${isDir ? "📁" : "📄"}</div>`;
    }

    window.PQNAS_EXTERNAL_ICONS = {
        fileIconHtml,
        iconMarkupFor,
        normalizeIconExt,
        fileExtLower
    };
})();
