# DNA-Nexus Guided Tours

This directory contains source-side guided onboarding tour definitions.

V1 uses a frontend tour engine served from:

- `server/src/static/onboarding.js`
- `server/src/static/onboarding.css`
- `server/src/static/onboarding_tours_v1.json`

The frontend is intentionally defensive:

- if an app is missing, no app tour runs
- if a target selector is missing, that step is skipped
- if every step is missing, the tour quietly stops
- user state is stored in browser `localStorage` for v1

Future v2 should move tour state to a server-side per-user store and expose routes such as:

- `GET /api/v4/onboarding/tours`
- `GET /api/v4/onboarding/state`
- `POST /api/v4/onboarding/mark`
- `POST /api/v4/onboarding/reset`

Admin-only tours should be filtered server-side before being returned to the browser.
