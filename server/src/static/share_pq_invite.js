(() => {
    "use strict";

    const boot = (window.PQ_SHARE_INVITE_BOOT && typeof window.PQ_SHARE_INVITE_BOOT === "object")
        ? window.PQ_SHARE_INVITE_BOOT
        : {};

    const inviteId = String(boot.invite_id || "").trim();
    const expiresAt = String(boot.expires_at || "").trim();
    const labelHint = String(boot.label_hint || "").trim();
    const preferredKemAlg = String(boot.preferred_kem_alg || "ML-KEM-768").trim();

    const host = document.getElementById("pqShareInviteApp") || document.body;

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function fmtDateTime(s) {
        if (!s) return "—";
        const d = new Date(s);
        if (Number.isNaN(d.getTime())) return s;
        return d.toLocaleString();
    }

    function looksMobile() {
        const ua = String(navigator.userAgent || "");
        return /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
    }

    function defaultDeviceLabel() {
        if (labelHint) return labelHint;
        return looksMobile() ? "My phone browser" : "This browser";
    }

    function algBlurb() {
        const norm = window.PqShareKeysV1
            ? window.PqShareKeysV1.normalizeKemAlg(preferredKemAlg)
            : String(preferredKemAlg || "ML-KEM-768");

        if (norm !== "ML-KEM-768") {
            return "This invite requires ML-KEM-768. Legacy non-post-quantum enrollment is not supported on this page.";
        }

        return "This browser will generate a local ML-KEM-768 keypair. The file key is wrapped for this browser using post-quantum key encapsulation, and the shared file is decrypted locally in your browser.";
    }

    async function enroll(inviteId, deviceLabel, statusEl, submitBtn) {
        if (!inviteId) throw new Error("Missing invite id");
        if (!deviceLabel) throw new Error("Please enter a device name");
        if (!window.PqShareKeysV1) throw new Error("PQ key helper not loaded");

        statusEl.textContent = "Preparing secure browser enrollment…";
        submitBtn.disabled = true;

        const pending = await window.PqShareKeysV1.generatePendingEnrollment(inviteId, {
            preferredAlg: preferredKemAlg
        });

        statusEl.textContent = "Enrolling this browser…";

        const r = await fetch("/api/v4/shares/pq/enroll", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                invite_id: inviteId,
                device_label: deviceLabel,
                kem_alg: pending.kem_alg,
                public_key_b64: pending.public_key_b64
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || "Enrollment failed");
        }

        if (!j.recipient_device_id) {
            throw new Error("Enrollment succeeded but recipient_device_id is missing");
        }

        await window.PqShareKeysV1.claimPendingEnrollment(inviteId, j.recipient_device_id);

        statusEl.textContent = "Enrollment complete. Opening share…";

        const target = String(j.share_url || "").trim();
        if (!target) {
            throw new Error("Enrollment succeeded but share URL is missing");
        }

        window.location.assign(target);
    }

    function render() {
        if (!inviteId) {
            host.innerHTML = `
        <div style="max-width:720px;margin:40px auto;padding:24px;font-family:system-ui,sans-serif">
          <h2>Invalid invite</h2>
          <p>Missing invite id.</p>
        </div>
      `;
            return;
        }

        host.innerHTML = `
      <style>
        :root{
          --bg:#0b1220;
          --panel:#121a2b;
          --fg:#eef3ff;
          --muted:#aab7d1;
          --accent:#7dd3fc;
          --border:rgba(255,255,255,0.10);
          --ok:#6ee7b7;
          --err:#fca5a5;
        }
        html,body{
          margin:0;
          min-height:100%;
          background:
            radial-gradient(1200px 700px at 15% 10%, rgba(125,211,252,0.10), transparent 55%),
            linear-gradient(180deg, #08101d, #0b1220 60%, #0a1220);
          color:var(--fg);
          font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        }
        .wrap{
          max-width:760px;
          margin:0 auto;
          padding:28px 18px 56px;
        }
        .card{
          background:rgba(18,26,43,0.92);
          border:1px solid var(--border);
          border-radius:22px;
          padding:24px;
          box-shadow:0 30px 80px rgba(0,0,0,0.35);
          backdrop-filter:blur(8px);
        }
        .eyebrow{
          font-size:12px;
          font-weight:800;
          letter-spacing:.12em;
          text-transform:uppercase;
          color:var(--accent);
          margin-bottom:8px;
        }
        h1{
          margin:0 0 10px 0;
          font-size:30px;
          line-height:1.1;
        }
        .lead{
          color:var(--muted);
          line-height:1.6;
          margin:0 0 18px 0;
        }
        .good{
          margin:0 0 18px 0;
          padding:12px 14px;
          border-radius:14px;
          background:rgba(110,231,183,0.10);
          border:1px solid rgba(110,231,183,0.22);
          color:#d9fff0;
        }
        .meta{
          display:grid;
          grid-template-columns:160px 1fr;
          gap:10px 14px;
          margin:18px 0 20px 0;
        }
        .k{
          color:var(--muted);
          font-weight:700;
        }
        .v{
          word-break:break-word;
        }
        .mono{
          font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
        }
        .field{
          margin-top:18px;
        }
        label{
          display:block;
          font-size:14px;
          font-weight:700;
          margin-bottom:8px;
        }
        input{
          width:100%;
          box-sizing:border-box;
          border-radius:14px;
          border:1px solid var(--border);
          background:rgba(255,255,255,0.04);
          color:var(--fg);
          padding:14px 15px;
          font-size:16px;
          outline:none;
        }
        input:focus{
          border-color:rgba(125,211,252,0.6);
          box-shadow:0 0 0 3px rgba(125,211,252,0.14);
        }
        .row{
          display:flex;
          gap:12px;
          flex-wrap:wrap;
          margin-top:18px;
          align-items:center;
        }
        button{
          appearance:none;
          border:0;
          border-radius:14px;
          padding:14px 18px;
          font-size:15px;
          font-weight:800;
          cursor:pointer;
          background:linear-gradient(180deg, #8be1ff, #68c8f2);
          color:#082033;
          box-shadow:0 12px 30px rgba(104,200,242,0.25);
        }
        button[disabled]{
          cursor:default;
          opacity:0.65;
        }
        .secondary{
          background:rgba(255,255,255,0.06);
          color:var(--fg);
          box-shadow:none;
          border:1px solid var(--border);
        }
        .status{
          min-height:24px;
          margin-top:16px;
          color:var(--muted);
          font-weight:600;
        }
        .small{
          margin-top:16px;
          color:var(--muted);
          font-size:13px;
          line-height:1.55;
        }
      </style>

      <div class="wrap">
        <div class="card">
        <div class="eyebrow">DNA-Nexus Post-Quantum Share</div>
        <h1>Open post-quantum protected share</h1>
        <p class="lead">
          This page enrolls this browser with ML-KEM-768 and then opens the shared file locally.
        </p>

          <div class="good">
            This invite is one-time and stays valid until enrollment succeeds or the invite expires.
          </div>

          <div class="meta">
            <div class="k">Invite ID</div>
            <div class="v mono">${escapeHtml(inviteId)}</div>

            <div class="k">Expires</div>
            <div class="v">${escapeHtml(fmtDateTime(expiresAt))}</div>

            <div class="k">Post-Quantum KEM</div>
            <div class="v">${escapeHtml(preferredKemAlg || "ML-KEM-768")}</div>
          </div>

          <div class="field">
            <label for="deviceLabel">Device name</label>
            <input id="deviceLabel" type="text" maxlength="80" placeholder="My phone browser" value="${escapeHtml(defaultDeviceLabel())}">
          </div>

          <div class="row">
            <button id="enrollBtn" type="button">Continue</button>
            <button id="copyInviteBtn" type="button" class="secondary">Copy invite ID</button>
          </div>

          <div id="status" class="status"></div>

          <div class="small">
            ${escapeHtml(algBlurb())}
          </div>
        </div>
      </div>
    `;

        const statusEl = document.getElementById("status");
        const enrollBtn = document.getElementById("enrollBtn");
        const copyInviteBtn = document.getElementById("copyInviteBtn");
        const deviceLabelEl = document.getElementById("deviceLabel");

        copyInviteBtn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(inviteId);
                statusEl.textContent = "Invite ID copied.";
            } catch (_) {
                statusEl.textContent = "Copy failed.";
            }
        });

        const run = async () => {
            const deviceLabel = String(deviceLabelEl.value || "").trim();
            try {
                await enroll(inviteId, deviceLabel, statusEl, enrollBtn);
            } catch (e) {
                statusEl.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
                enrollBtn.disabled = false;
            }
        };

        enrollBtn.addEventListener("click", run);
        deviceLabelEl.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                run();
            }
        });
    }

    render();
})();