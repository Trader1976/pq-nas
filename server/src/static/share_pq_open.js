(() => {
    const boot = globalThis.PQ_SHARE_OPEN_BOOT || null;

    function el(id) {
        return document.getElementById(id);
    }

    function ensureUi() {
        if (el("pqshare-root")) return;

        document.body.innerHTML = `
      <main id="pqshare-root" style="max-width:760px;margin:40px auto;padding:24px;font-family:system-ui,sans-serif;">
        <h1 style="margin:0 0 12px 0;">Protected share</h1>
        <div id="pqshare-file" style="margin:0 0 10px 0;color:#666;"></div>
        <div id="pqshare-status" style="margin:0 0 16px 0;">Preparing secure open…</div>
        <button id="pqshare-open-btn" type="button">Decrypt and download</button>
      </main>
    `;
    }

    function setStatus(msg) {
        ensureUi();
        const n = el("pqshare-status");
        if (n) n.textContent = msg;
    }

    function setFileName(name) {
        ensureUi();
        const n = el("pqshare-file");
        if (n) n.textContent = name ? `File: ${name}` : "";
    }

    function downloadBytes(bytes, fileName, mimeType) {
        const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName || "download.bin";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    async function fetchEnvelope() {
        const res = await fetch((boot && boot.open_api) || "/api/v4/shares/pq/open", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                share_token: boot.share_token
            })
        });

        const text = await res.text();
        let data = {};
        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            throw new Error(`Open API returned non-JSON response (${res.status})`);
        }

        if (!res.ok || data.ok === false) {
            throw new Error(data.message || data.error || `Open API failed (${res.status})`);
        }

        return data.envelope || data;
    }

    async function decryptEnvelope(env) {
        if (!window.PqShareKeysV1) {
            throw new Error("PQ key helper not loaded");
        }

        const aad = PqShareKeysV1.b64ToBytes(env.aad_b64);
        const cekRaw = await PqShareKeysV1.unwrapCekFromEnvelope(env);

        const cek = await crypto.subtle.importKey(
            "raw",
            cekRaw,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const plaintext = new Uint8Array(await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: PqShareKeysV1.b64ToBytes(env.payload.iv_b64),
                additionalData: aad
            },
            cek,
            PqShareKeysV1.b64ToBytes(env.payload.ciphertext_b64)
        ));

        const gotSha = (await PqShareKeysV1.sha256Hex(plaintext)).toLowerCase();
        const wantSha = String(env.snapshot?.sha256_hex || "").toLowerCase();
        if (wantSha && gotSha !== wantSha) {
            throw new Error("Decrypted file digest mismatch");
        }

        const wantSize = Number(env.snapshot?.size_bytes || 0);
        if (wantSize > 0 && plaintext.byteLength !== wantSize) {
            throw new Error("Decrypted file size mismatch");
        }

        return plaintext;
    }

    async function openAndDownload() {
        if (!boot?.share_token) {
            throw new Error("Missing PQ share bootstrap data");
        }

        setFileName(boot.file_name || "");
        setStatus("Requesting encrypted envelope…");
        const env = await fetchEnvelope();

        setFileName(env.file_name || boot.file_name || "");
        setStatus("Decrypting locally in this browser…");
        const plaintext = await decryptEnvelope(env);

        setStatus("Download starting…");
        downloadBytes(plaintext, env.file_name || boot.file_name || "download.bin", env.mime_type);
        setStatus("Done.");
    }

    async function start() {
        ensureUi();
        setFileName(boot?.file_name || "");

        const btn = el("pqshare-open-btn");
        if (btn) {
            btn.onclick = async () => {
                btn.disabled = true;
                try {
                    await openAndDownload();
                } catch (err) {
                    setStatus(err?.message || String(err));
                } finally {
                    btn.disabled = false;
                }
            };
        }

        try {
            await openAndDownload();
        } catch (err) {
            setStatus(err?.message || String(err));
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once: true });
    } else {
        start();
    }
})();