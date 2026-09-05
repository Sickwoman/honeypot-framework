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

## Production build

```bash
npm run build
npm run preview
```