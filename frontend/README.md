# Nightwatch Alert Console

Nightwatch is a TypeScript/Vite operator dashboard for the honeypot alert API:
a sidebar-navigated console (Dashboard / Alerts / Playbooks) with a dense,
sortable alert table and a detail panel, in the style of a vulnerability
scanner's findings view. It polls the alert API every 10 seconds, supports
API keys or bearer tokens, and uses clearly labeled local demo data when the
API is not available.

## Run locally

```bash
npm install
npm run dev
```

Open the URL printed by Vite. Click **Settings** (sidebar or the gear icon) to
set the alert API URL and an API key or bearer token. The default endpoint is
`/api/v1/alerts`.

Save a blank API URL to sign out, which clears the stored token.

## Fonts

The dashboard uses system font stacks and loads no webfonts, so it makes no
third-party requests and has nothing to download or vendor. Data columns (IPs,
IDs, timestamps, JSON) render in the platform monospace face; everything else
uses the platform UI face.

## Production build

```bash
npm run build
npm run preview
```