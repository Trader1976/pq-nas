async function loadTail() {
    const el = document.getElementById("log");
    if (!el) return;
    el.textContent = "JS loaded. Fetching…";

    const r = await fetch("/api/v4/audit/tail?n=200", { cache: "no-store" });
    el.textContent = "Fetch status: " + r.status;

    const j = await r.json();
    el.textContent = "Lines: " + (j.lines ? j.lines.length : 0) + "\n\n" +
        (j.lines || []).map(l => JSON.stringify(l)).join("\n");
}

async function verifyChain() {
    const r = await fetch("/api/v4/audit/verify", { cache: "no-store" });
    const j = await r.json();
    alert(j.ok ? "Audit chain OK" : ("Audit chain FAILED\n" + JSON.stringify(j)));
}

window.addEventListener("load", loadTail);
