# Verunum TAB5 / R503 Hardware Deployment Guide

Use the accompanying PDF for the field installation and commissioning checklist.

## Firmware contract

1. Connect to `/api/v1/devices/ws` using the device API key.
2. Immediately send `{"type":"hello","payload":{"protocol_version":1}}`.
3. Wait for `hello.ack` before processing commands.
4. On `enroll.start`, capture the R503 fingerprint locally against the supplied `user_id` UUID.
5. Return `enroll.result` with the same `request_id`.
6. On fingerprint match, send `attendance` with the local user's UUID.
7. Queue attendance while offline and retry after `hello.ack`.
8. Reconnect with exponential backoff.

Biometric templates must never be sent to the Verunum backend.

## Security

- The platform stores only the device API-key hash.
- The provisioning API key is shown once.
- Do not hard-code production keys in firmware source code.
- Use `wss://` in production.
- Hardware clients normally omit the `Origin` header. Browser-origin connections are restricted by the server's WebSocket origin policy.
