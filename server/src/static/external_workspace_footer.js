(() => {
    "use strict";

    function fmtSize(n) {
        const units = ["B", "KiB", "MiB", "GiB", "TiB"];
        let v = Number(n || 0);
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return i === 0 ? `${v | 0} ${units[i]}` : `${v.toFixed(1)} ${units[i]}`;
    }

    function firstFiniteNumber(...values) {
        for (const v of values) {
            if (v === null || v === undefined || v === "") continue;
            const n = Number(v);
            if (Number.isFinite(n) && n >= 0) return n;
        }
        return null;
    }

    function storageBytesFromResponse(j) {
        if (!j || typeof j !== "object") return { used:null, quota:null };

        const storage = j.storage && typeof j.storage === "object" ? j.storage : {};
        const quota = j.quota && typeof j.quota === "object" ? j.quota : {};
        const workspace = j.workspace && typeof j.workspace === "object" ? j.workspace : {};
        const usage = j.usage && typeof j.usage === "object" ? j.usage : {};
        const workspaceStorage = j.workspace_storage && typeof j.workspace_storage === "object" ? j.workspace_storage : {};

        const used = firstFiniteNumber(
            j.used_bytes,
            j.storage_used_bytes,
            j.workspace_used_bytes,
            j.bytes_used,
            storage.used_bytes,
            storage.used,
            storage.bytes_used,
            quota.used_bytes,
            workspace.used_bytes,
            workspace.storage_used_bytes,
            workspaceStorage.used_bytes,
            workspaceStorage.used,
            usage.used_bytes
        );

        const quotaBytes = firstFiniteNumber(
            j.quota_bytes,
            j.storage_quota_bytes,
            j.workspace_quota_bytes,
            storage.quota_bytes,
            storage.quota,
            quota.quota_bytes,
            workspace.quota_bytes,
            workspace.storage_quota_bytes,
            workspaceStorage.quota_bytes,
            workspaceStorage.quota,
            usage.quota_bytes
        );

        return { used, quota: quotaBytes };
    }

    function ensure(anchorEl) {
        const footers = Array.from(document.querySelectorAll("#externalWorkspaceFooter"));
        let footer = footers[0] || null;
        footers.slice(1).forEach((el) => el.remove());

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

            if (anchorEl && anchorEl.parentNode) {
                anchorEl.parentNode.insertBefore(footer, anchorEl.nextSibling);
            } else {
                document.body.appendChild(footer);
            }
        }

        let line = footer.querySelector("#workspaceStorageLine") ||
            footer.querySelector(".externalWorkspaceStorage");

        if (!line) {
            line = document.createElement("div");
            footer.prepend(line);
        }

        line.id = "workspaceStorageLine";
        line.className = "externalWorkspaceStorage";

        Array.from(document.querySelectorAll("#workspaceStorageLine, #externalWorkspaceStorage, .externalWorkspaceStorage"))
            .forEach((el) => {
                if (el !== line) el.remove();
            });

        return { footer, line };
    }

    function update(j, anchorEl) {
        const { line } = ensure(anchorEl);
        const bytes = storageBytesFromResponse(j);
        const used = bytes.used;
        const quota = bytes.quota;

        if (used == null && quota == null) {
            line.textContent = "Workspace storage: —";
            return;
        }

        if (quota != null && quota > 0) {
            const pct = Math.max(0, Math.min(999, Math.round((Number(used || 0) / quota) * 100)));
            line.textContent = `Workspace storage: ${fmtSize(used || 0)} / ${fmtSize(quota)} (${pct}%)`;
            return;
        }

        line.textContent = `Workspace storage: ${fmtSize(used || 0)}`;
    }

    window.PQNAS_EXTERNAL_WORKSPACE_FOOTER = {
        ensure,
        update
    };
})();
