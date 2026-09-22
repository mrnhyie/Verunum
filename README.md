# Verunum

Single-binary Go MVP for SparkLab Africa / Juldtech Solutions' smart biometric attendance and institutional identity platform. It serves the admin dashboard and device APIs from one server, with SQLite persistence.

## Run

```sh
go mod tidy
go run ./cmd/server -db verunum.db
```

Open `http://localhost:8080/login`.

For local development, the first run seeds the demo administrator `admin@demo.local` / `admin123`.

For production, set these environment variables before the first start:

```sh
export VERUNUM_ENV=production
export JWT_SECRET='use-a-random-secret-at-least-32-characters'
export VERUNUM_BOOTSTRAP_ADMIN_EMAIL='admin@your-domain.example'
export VERUNUM_BOOTSTRAP_ADMIN_PASSWORD='a-long-random-password'
export VERUNUM_BOOTSTRAP_ADMIN_NAME='Platform Administrator'
export VERUNUM_BOOTSTRAP_ORGANIZATION='Your Organisation'
```

Production refuses to start with a weak/missing JWT secret or missing bootstrap credentials. Run the service behind HTTPS/TLS and use WSS for devices.

## Production device provisioning

Verunum uses **zero-touch device provisioning**.

1. An authorised platform administrator creates a pending device provisioning for an organisation.
2. The administrator enters the terminal name, installation location and MAC address.
3. The physical terminal already knows the hosted WebSocket address.
4. The terminal connects to `/api/v1/devices/ws` and sends `hello` with its MAC address and device name.
5. Verunum matches the MAC against the pending provisioning.
6. If matched, Verunum creates the permanent device, binds it to the pending organisation, generates an API key and returns it once in `hello.ack`.
7. The terminal stores the API key securely and uses it for future authenticated connections and device REST requests.
8. The pending provisioning record is consumed.

The API key is **never hard-coded into firmware** and the backend stores only its hash.

See:

- `docs/hardware-websocket.md` — exact device protocol
- `docs/hardware-deployment-guide.md` — field installation guidance
- `docs/Verunum_End_to_End_User_and_Device_Flow.pdf` — dashboard-to-device functional contract

## WebSocket endpoint

Production:

```text
wss://YOUR_HOST/api/v1/devices/ws
```

Local development:

```text
ws://localhost:8080/api/v1/devices/ws
```

The first application frame is always `hello`.

### First-time provisioning

```json
{
  "type": "hello",
  "payload": {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "device_name": "Main Gate TAB5",
    "protocol_version": 1,
    "firmware_version": "1.0.0"
  }
}
```

Successful first-time provisioning returns:

```json
{
  "type": "hello.ack",
  "status": "provisioned",
  "payload": {
    "device_id": "dev_123",
    "api_key": "ONE_TIME_DEVICE_KEY"
  }
}
```

For later connections, the device supplies its stored API key and sends the same hello. The response has `status: "authenticated"` and does not return the key again.

## Person enrollment

The admin creates a person, selects an online terminal and starts fingerprint intake. The server sends `enroll.start`; the TAB5/R503 captures and stores the biometric template locally and returns `enroll.result`. Raw biometric templates never enter Verunum.

## Attendance

The terminal performs fingerprint matching locally and sends attendance events containing the user's UUID and a unique `event_id`. The device queues events while offline and retries the same event IDs after reconnecting. The backend uses event IDs for idempotency.

## Security

- Use WSS/TLS in production.
- Keep `JWT_SECRET` outside source control.
- Never log device API keys.
- Never hard-code device API keys into firmware.
- Store the device API key in protected device storage.
- The backend stores only API-key hashes.
- Raw fingerprint templates stay on the device.
- Revoke compromised devices from the dashboard.

## Verification note

The source is formatted with `gofmt`. The supplied environment currently has Go 1.23.2 while this project declares Go 1.26.0, and it cannot download the required toolchain/dependencies because external network access is unavailable. Therefore the full `go test ./...` suite could not be executed in this environment. Run it on the deployment/build machine with Go 1.26.x before production rollout.
