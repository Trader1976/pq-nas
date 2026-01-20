(async () => {
    const out = document.getElementById("out");
    const admin = document.getElementById("admin_block");

    try {
        const r = await fetch("/api/v4/me", { credentials: "include" });
        const txt = await r.text();

        let j = null;
        try { j = JSON.parse(txt); } catch {}

        if (j) out.textContent = JSON.stringify(j, null, 2);
        else out.textContent = `${r.status}\n${txt}`;

        if (j && j.ok && j.role === "admin") {
            admin.style.display = "block";
        }
    } catch (e) {
        out.textContent = String(e);
    }
})();
