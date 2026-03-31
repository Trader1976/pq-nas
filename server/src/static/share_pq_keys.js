(() => {
    const IDENTITY_KEY = "pqshare:identity:v1";
    const PENDING_PREFIX = "pqshare:pending:";
    const DEVICE_PREFIX = "pqshare:device:";

    function normalizeB64(s) {
        return String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    }

    function b64ToBytes(b64) {
        const bin = atob(normalizeB64(b64));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToB64(bytes) {
        let s = "";
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            s += String.fromCharCode(...bytes.subarray(i, i + chunk));
        }
        return btoa(s);
    }

    async function supportsX25519() {
        if (!globalThis.crypto?.subtle) return false;
        try {
            const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
            return !!kp?.publicKey && !!kp?.privateKey;
        } catch {
            return false;
        }
    }

    function supportsNativeMlKem() {
        try {
            return !!(
                globalThis.crypto?.subtle &&
                typeof crypto.subtle.supports === "function" &&
                crypto.subtle.supports("generateKey", "ML-KEM-768")
            );
        } catch {
            return false;
        }
    }

    async function ensureBrowserIdentity() {
        const raw = localStorage.getItem(IDENTITY_KEY);
        if (raw) {
            try {
                const rec = JSON.parse(raw);
                if (rec?.public_key_b64 && rec?.private_key_pkcs8_b64 && rec?.alg === "X25519") {
                    return rec;
                }
            } catch (_) {
            }
        }

        if (!(await supportsX25519())) {
            throw new Error("This browser does not support X25519 WebCrypto");
        }

        const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
        const privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

        const rec = {
            v: 1,
            identity_id: "x25519:" + bytesToB64(publicRaw),
            alg: "X25519",
            created_at: new Date().toISOString(),
            public_key_b64: bytesToB64(publicRaw),
            private_key_pkcs8_b64: bytesToB64(privatePkcs8)
        };

        localStorage.setItem(IDENTITY_KEY, JSON.stringify(rec));
        return rec;
    }

    async function generatePendingEnrollment(inviteId) {
        if (!inviteId) throw new Error("missing inviteId");

        const ident = await ensureBrowserIdentity();

        localStorage.setItem(PENDING_PREFIX + inviteId, JSON.stringify({
            v: 1,
            identity_id: ident.identity_id,
            alg: ident.alg,
            public_key_b64: ident.public_key_b64,
            created_at: new Date().toISOString()
        }));

        return {
            kem_alg: ident.alg,
            public_key_b64: ident.public_key_b64
        };
    }

    function getPendingEnrollment(inviteId) {
        const raw = localStorage.getItem(PENDING_PREFIX + inviteId);
        if (!raw) return null;
        try {
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    async function claimPendingEnrollment(inviteId, recipientDeviceId) {
        if (!inviteId) throw new Error("missing inviteId");
        if (!recipientDeviceId) throw new Error("missing recipientDeviceId");

        const pending = getPendingEnrollment(inviteId);
        if (!pending?.identity_id) throw new Error("pending enrollment key not found");

        const deviceRec = {
            v: 1,
            recipient_device_id: recipientDeviceId,
            identity_id: pending.identity_id,
            alg: pending.alg || "X25519",
            claimed_at: new Date().toISOString()
        };

        localStorage.setItem(DEVICE_PREFIX + recipientDeviceId, JSON.stringify(deviceRec));
        localStorage.removeItem(PENDING_PREFIX + inviteId);
        return deviceRec;
    }

    function getDeviceRecord(recipientDeviceId) {
        const raw = localStorage.getItem(DEVICE_PREFIX + recipientDeviceId);
        if (!raw) return null;
        try {
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    async function loadDevicePrivateKey(recipientDeviceId) {
        const rec = getDeviceRecord(recipientDeviceId);
        if (!rec) {
            throw new Error("recipient private key not found for this browser");
        }

        if (rec.identity_id) {
            const identRaw = localStorage.getItem(IDENTITY_KEY);
            if (!identRaw) throw new Error("browser identity not found for this browser");

            let ident = null;
            try {
                ident = JSON.parse(identRaw);
            } catch (_) {
                ident = null;
            }
            if (!ident?.private_key_pkcs8_b64) {
                throw new Error("browser identity private key missing");
            }

            return crypto.subtle.importKey(
                "pkcs8",
                b64ToBytes(ident.private_key_pkcs8_b64),
                { name: "X25519" },
                false,
                ["deriveBits"]
            );
        }

        // Legacy fallback for older already-enrolled records
        if (rec.private_key_pkcs8_b64) {
            return crypto.subtle.importKey(
                "pkcs8",
                b64ToBytes(rec.private_key_pkcs8_b64),
                { name: "X25519" },
                false,
                ["deriveBits"]
            );
        }

        throw new Error("recipient private key not found for this browser");
    }

    async function importSenderPublicKeyX25519(publicKeyB64) {
        return crypto.subtle.importKey(
            "raw",
            b64ToBytes(publicKeyB64),
            { name: "X25519" },
            false,
            []
        );
    }

    async function deriveWrapKeyFromEnvelope(privateKey, env) {
        const senderPub = await importSenderPublicKeyX25519(env.wrapped_key.sender_public_key_b64);
        const sharedBits = await crypto.subtle.deriveBits(
            { name: "X25519", public: senderPub },
            privateKey,
            256
        );

        const hkdfBaseKey = await crypto.subtle.importKey(
            "raw",
            sharedBits,
            "HKDF",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: b64ToBytes(env.wrapped_key.hkdf_salt_b64),
                info: b64ToBytes(env.wrapped_key.hkdf_info_b64)
            },
            hkdfBaseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
    }

    async function sha256Hex(bytes) {
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
        let out = "";
        for (const b of digest) out += b.toString(16).padStart(2, "0");
        return out;
    }

    globalThis.PqShareKeysV1 = {
        supportsX25519,
        supportsNativeMlKem,
        ensureBrowserIdentity,
        generatePendingEnrollment,
        getPendingEnrollment,
        claimPendingEnrollment,
        getDeviceRecord,
        loadDevicePrivateKey,
        deriveWrapKeyFromEnvelope,
        b64ToBytes,
        bytesToB64,
        sha256Hex
    };
})();