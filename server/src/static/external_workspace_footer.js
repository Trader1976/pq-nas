(() => {
    "use strict";

    function fallbackFmtSize(n) {
        const units = ["B", "KiB", "MiB", "GiB", "TiB"];
        let v = Number(n || 0);
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return i === 0 ? `${v | 0} ${units[i]}` : `${v.toFixed(1)} ${units[i]}`;
    }

    function firstNumber(...values) {
        for (const v of values) {
            if (v === null || v === undefined || v === "") continue;
            const n = Number(v);
            if (Number.isFinite(n) && n >= 0) return n;
        }
        return NaN;
    }

    function storageBytesFromResponse(j) {
        const root = j && typeof j === "object" ? j : {};
        const storage = root.storage && typeof root.storage === "object" ? root.storage : {};
        const workspaceStorage = root.workspace_storage && typeof root.workspace_storage === "object" ? root.workspace_storage : {};
        const quota = root.quota && typeof root.quota === "object" ? root.quota : {};
        const workspace = root.workspace && typeof root.workspace === "object" ? root.workspace : {};
        const usage = root.usage && typeof root.usage === "object" ? root.usage : {};

        return {
            used: firstNumber(
                root.used_bytes,
                root.storage_used_bytes,
                root.workspace_used_bytes,
                root.bytes_used,
                storage.used_bytes,
                storage.used,
                storage.bytes_used,
                workspaceStorage.used_bytes,
                workspaceStorage.used,
                quota.used_bytes,
                workspace.used_bytes,
                workspace.storage_used_bytes,
                usage.used_bytes
            ),
            quota: firstNumber(
                root.quota_bytes,
                root.storage_quota_bytes,
                root.workspace_quota_bytes,
                storage.quota_bytes,
                storage.quota,
                workspaceStorage.quota_bytes,
                workspaceStorage.quota,
                quota.quota_bytes,
                workspace.quota_bytes,
                workspace.storage_quota_bytes,
                usage.quota_bytes
            )
        };
    }

    function removeLegacyDuplicateLines(keepLine) {
        const nodes = Array.from(document.querySelectorAll(".externalWorkspaceStorage, #externalWorkspaceStorage"));
        for (const node of nodes) {
            if (node === keepLine) continue;
            if (node.id === "workspaceStorageLine") continue;
            try { node.remove(); } catch (_) {}
        }
    }

    function ensureFooter() {
        let footer = document.getElementById("externalWorkspaceFooter");

        if (!footer) {
            footer = document.createElement("div");
            footer.id = "externalWorkspaceFooter";
            footer.className = "externalWorkspaceFooter";
            footer.innerHTML = `
                <div class="externalWorkspaceStorage" id="workspaceStorageLine">Workspace storage: —</div>
                <div class="externalWorkspaceBrand">
                    <div>DNA-Nexus external workspace</div>
                    <div>© CPUNK 2026 • DNA-Nexus</div>
                </div>
            `;

            const files = document.getElementById("files");
            if (files && files.parentNode) {
                files.parentNode.insertBefore(footer, files.nextSibling);
            } else {
                document.body.appendChild(footer);
            }
        }

        let line = document.getElementById("workspaceStorageLine");
        if (!line) {
            line = document.createElement("div");
            line.id = "workspaceStorageLine";
            line.className = "externalWorkspaceStorage";
            line.textContent = "Workspace storage: —";
            footer.prepend(line);
        }

        removeLegacyDuplicateLines(line);
        return line;
    }

    function update(j, opts = {}) {
        const line = ensureFooter();
        const fmtSize = typeof opts.fmtSize === "function" ? opts.fmtSize : fallbackFmtSize;
        const bytes = storageBytesFromResponse(j);

        if (!Number.isFinite(bytes.used) && !Number.isFinite(bytes.quota)) {
            line.textContent = "Workspace storage: —";
            return;
        }

        if (Number.isFinite(bytes.quota) && bytes.quota > 0) {
            const used = Number.isFinite(bytes.used) ? bytes.used : 0;
            const pct = Math.max(0, Math.min(999, Math.round((used / bytes.quota) * 100)));
            line.textContent = `Workspace storage: ${fmtSize(used)} / ${fmtSize(bytes.quota)} (${pct}%)`;
            return;
        }

        line.textContent = `Workspace storage: ${fmtSize(Number.isFinite(bytes.used) ? bytes.used : 0)}`;
    }

    window.PQNAS_EXTERNAL_FOOTER = {
        update
    };
})();
