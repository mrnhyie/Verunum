# Verunum production deployment checklist

## Environment

Set `VERUNUM_ENV=production` and provide a random `JWT_SECRET` of at least 32 characters. On the first start of an empty database, also provide the bootstrap administrator and organisation variables documented in `.env.example`.

Do not use the demo credentials in production.

## TLS / reverse proxy

Terminate HTTPS at a reverse proxy and forward traffic to Verunum on its internal HTTP port 8080.

The public device endpoint is:

```text
wss://YOUR_DOMAIN/api/v1/devices/ws
```

The dashboard/API is served through the same HTTPS host.

Set `VERUNUM_WS_ORIGINS` to the browser origins that are allowed to open the device WebSocket. Hardware clients normally omit the Origin header and are allowed through the device protocol handshake.

## Database

Back up the SQLite database and keep the database file on persistent storage. Do not expose it through the web server.

## Device provisioning

1. Admin creates pending provisioning with MAC/name/location.
2. TAB5 connects to `/api/v1/devices/ws`.
3. Device sends `hello` with MAC and device name.
4. Server matches the MAC against pending provisioning.
5. Server creates the device and binds it to the pending organisation.
6. Server generates an API key and sends it once in `hello.ack`.
7. Device stores the key securely.
8. Future connections authenticate using the stored key.

## Security

- Do not put device API keys in firmware source code.
- Do not log API keys or fingerprint templates.
- Keep raw fingerprint templates on the device.
- Revoke a compromised device from the dashboard.
- Use WSS/TLS in production.
- Keep the JWT secret outside source control.
- Restrict access to the SQLite database and backup files.
