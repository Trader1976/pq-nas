# File Manager loading troubleshooting

This page covers a known deployment symptom where **File Manager sometimes loads slowly, partially, or only after one or more hard refreshes**.

## Symptom

File Manager may appear to hang or load unreliably, especially in Firefox.

Typical signs:

- File Manager opens, but icons or toolbar parts appear late.
- A hard refresh sometimes fixes it.
- Chrome may load the same page normally.
- `/api/v4/files/list` is fast, but static app assets are slow.
- Browser DevTools show some `/apps/filemgr/...` files waiting about 5 seconds before loading.

Example slow resources:

```text
/apps/filemgr/1.0.0/www/office_preview.css
/apps/filemgr/1.0.0/www/pdf_preview.js
/apps/filemgr/1.0.0/www/icons/updir_small.png
```

If the API calls are fast but static assets randomly stall, the problem is usually **not** file listing performance.

## Quick browser check

Open File Manager, then open browser DevTools and run:

```js
console.table(
  performance.getEntriesByType("resource")
    .filter(e =>
      e.name.includes("/api/v4/") ||
      e.name.includes("/apps/filemgr/")
    )
    .map(e => ({
      name: e.name.replace(location.origin, ""),
      start: Math.round(e.startTime),
      requestStart: Math.round(e.requestStart || 0),
      responseStart: Math.round(e.responseStart || 0),
      responseEnd: Math.round(e.responseEnd || 0),
      ms: Math.round(e.duration),
      transfer: e.transferSize,
      decoded: e.decodedBodySize,
      initiator: e.initiatorType
    }))
    .sort((a, b) => a.start - b.start)
);
```

If `/api/v4/files/list` is fast but some `/apps/filemgr/...` static files take around 5000 ms, continue below.

## Check whether Cloudflare HTTP/3 is enabled

From a terminal:

```bash
curl -k -sS -D - -o /dev/null \
  "https://YOUR-DOMAIN.example/apps/filemgr/1.0.0/www/app.js?v=$(date +%s)" \
  | grep -iE 'alt-svc|server|cache-control|content-type'
```

If you see:

```text
server: cloudflare
alt-svc: h3=":443"; ma=86400
```

then Cloudflare is advertising HTTP/3 / QUIC to browsers.

On some Firefox + Cloudflare combinations this can cause random 5-second stalls for static app assets. File Manager may appear unreliable even though the server and APIs are fast.

## Recommended fix: disable HTTP/3 in Cloudflare

In the Cloudflare dashboard for your domain:

```text
Speed
→ Settings
→ Protocol Optimization
→ HTTP/3 (with QUIC)
→ Off
```

Keep HTTP/2 enabled.

After disabling HTTP/3, test again:

```bash
curl -k -sS -D - -o /dev/null \
  "https://YOUR-DOMAIN.example/apps/filemgr/1.0.0/www/app.js?v=$(date +%s)" \
  | grep -iE 'alt-svc|server|cache-control|content-type'
```

The `alt-svc: h3=":443"` line should be gone.

Then fully restart Firefox and reload File Manager.

## Firefox-only local workaround

For testing, a user can disable HTTP/3 locally in Firefox:

1. Open:

```text
about:config
```

2. Search:

```text
http3
```

3. Set this to `false`:

```text
network.http.http3.enable
```

Some Firefox versions may use a slightly different name, such as:

```text
network.http.http3.enabled
```

4. Fully restart Firefox.

This is only a local workaround. For a public/home DNA-Nexus deployment, the better fix is to disable HTTP/3 at the reverse proxy/CDN layer.

## Notes

- A missing `/favicon.ico` may show as a 404 in DevTools. This is harmless and does not affect File Manager loading.
- If `curl` loads `/apps/filemgr/.../app.js` quickly but Firefox shows 5-second waits, the issue is likely browser/protocol related.
- If both `curl` and the browser are slow, inspect the reverse proxy, CDN, DNS, and the server’s static file route.
- Optional preview modules such as PDF, Office, video, and audio preview should not block the initial file list. If File Manager is usable but preview resources load later, that is acceptable.