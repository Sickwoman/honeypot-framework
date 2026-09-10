# Nightwatch Investigation Dashboard

Nightwatch is a TypeScript/Vite operator dashboard for live honeypot
investigation. It polls the existing alert API every 10 seconds, supports API
keys or bearer tokens, and uses clearly labeled local demo data when the API is
not available.

## Run locally

```bash
npm install
npm run dev
```

Open the URL printed by Vite. Use the gear button to set the alert API URL and
an API key or bearer token. The default endpoint is `/api/v1/alerts`.

Use the gear button with a blank URL to sign out, which clears the stored token.

## Fonts

The dashboard makes no third-party requests, so its two webfonts are expected
locally at `frontend/public/fonts/`:

```bash
mkdir -p public/fonts
# Download the woff2 files from https://fonts.google.com (Space Grotesk, DM Mono)
# and save them as:
#   public/fonts/space-grotesk.woff2
#   public/fonts/dm-mono.woff2
```

Without them the UI falls back to system sans/monospace fonts.

## Production build

```bash
npm run build
npm run preview
```