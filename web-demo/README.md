# Luca public demonstration for Vercel

This multi-service deployment is a **read-only demonstration using synthetic data**, not a remotely hosted network scanner.

- `site/public/index.html` provides a static device-owner dashboard.
- `api/main.py` provides only `GET /api/health` and `GET /api/report`. Both are safe, stateless, demonstration-only endpoints.
- Root `vercel.json` routes all `/api/*` requests to the demo API and all remaining traffic to the static site.

The full app's Wi-Fi control, TShark capture, Zeek/Suricata analysis, administration, and SQLite intelligence components are **not deployed**.

## Deployment

1. Import `topherchris420/Luca` into Vercel.
2. Keep Root Directory set to the repository root containing `vercel.json`.
3. Select Vercel Services if asked for a framework.
4. Open `/` for the sample dashboard or `/api/health` to inspect the demo-only API.

Vercel Services documentation: https://vercel.com/docs/services

## Real monitoring

Use a separate, dedicated Linux host with physical Wi-Fi/network interfaces and explicit authorization. Harden its access controls and operating system first. **Never route Luca's capture, device-management, or administration APIs through the public Vercel deployment.**
