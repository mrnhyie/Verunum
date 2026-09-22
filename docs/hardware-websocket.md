# TAB5 / Verunum Terminal — WebSocket Integration

This is the protocol contract between the Verunum platform and the TAB5/R503 device.

**Core rule:** fingerprint templates remain on the terminal. Verunum receives person identity and attendance events, not raw biometric templates.

## 1. Architecture

```text
Organisation Admin
      |
      | HTTPS
      v
Verunum Dashboard
      |
      | REST / SSE
      v
Verunum Backend
      |
      | WebSocket / WSS
      v
TAB5 Terminal ---- UART ---- R503 fingerprint sensor
```

## 2. Device provisioning — automatic / zero-touch

The administrator first creates a **pending device provisioning** from the Verunum dashboard:

- organisation
- device name
- MAC address
- installation location

The physical terminal does **not** receive a manually entered API key.

The terminal already knows the hosted Verunum WebSocket URL. It connects to:

```text
wss://HOST/api/v1/devices/ws
```

For local development:

```text
ws://HOST:PORT/api/v1/devices/ws
```

The WebSocket upgrade itself does not require a pre-existing device credential. This is intentional: a brand-new terminal must be able to send its MAC address before it has an API key.

### First message: `hello`

The first application frame must be `hello`:

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

The backend takes the MAC address and checks `pending_device_enrollments`.

### If the MAC matches a pending provisioning

Verunum:

1. identifies the pending organisation;
2. creates the permanent device record;
3. binds the device to that organisation;
4. generates a unique API key;
5. stores only the API-key hash;
6. removes the pending provisioning record;
7. marks the device active;
8. returns the API key once in `hello.ack`.

Response:

```json
{
  "type": "hello.ack",
  "status": "provisioned",
  "payload": {
    "device_id": "dev_123",
    "api_key": "VERUNUM_DEVICE_KEY",
    "message": "Device successfully bound and activated."
  }
}
```

The device must securely store `api_key`. It must **not** hard-code the key into firmware.

### If the MAC is already provisioned

The device must send its stored API key either as `X-Device-Key`, `api_key`, or in the `hello.payload.api_key` field.

```json
{
  "type": "hello",
  "payload": {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "device_name": "Main Gate TAB5",
    "protocol_version": 1,
    "firmware_version": "1.0.0",
    "api_key": "STORED_DEVICE_KEY"
  }
}
```

The server verifies the MAC + API-key hash + non-revoked device record and responds:

```json
{
  "type": "hello.ack",
  "status": "authenticated",
  "payload": {
    "device_id": "dev_123",
    "message": "Connected successfully."
  }
}
```

## 3. Message envelope

```json
{
  "type": "hello | hello.ack | ping | pong | enroll.start | enroll.result | attendance | ack | error",
  "request_id": "string, optional",
  "payload": {}
}
```

Use `request_id` to correlate commands and responses. Use a unique `event_id` for every attendance event.

## 4. Fingerprint enrollment

Admin flow:

```text
Dashboard
  -> People
  -> Add person
  -> Create profile
  -> Select online TAB5
  -> Click to start fingerprint intake
  -> Verunum sends enroll.start
  -> TAB5 captures with R503
  -> Device stores template locally
  -> Device sends enroll.result
  -> Dashboard shows Enrolled
```

Server → device:

```json
{
  "type": "enroll.start",
  "request_id": "17",
  "payload": {
    "user_id": "USER-UUID",
    "finger_index": 1,
    "timeout_seconds": 30
  }
}
```

Device → server:

```json
{
  "type": "enroll.result",
  "request_id": "17",
  "payload": {
    "user_id": "USER-UUID",
    "finger_index": 1,
    "status": "enrolled",
    "error": ""
  }
}
```

Do not send the fingerprint template or raw biometric data to the backend.

## 5. Attendance

The R503 performs the match locally. The device maps the matched fingerprint to the stored user UUID and sends:

```json
{
  "type": "attendance",
  "event_id": "evt_20260920_000123",
  "payload": {
    "user_id": "USER-UUID",
    "event": "clock_in",
    "timestamp": "2026-09-20T08:04:12Z",
    "method": "fingerprint"
  }
}
```

The backend uses `event_id` for idempotency. If the same event is retried, it must not create a second attendance record.

## 6. Offline behavior

If the network is unavailable:

```text
Attendance
   |
   v
Local queue
   |
   | network restored
   v
Reconnect + authenticate
   |
   v
Send original event_id
   |
   v
Server ACK
   |
   v
Remove acknowledged event
```

Never generate a new event ID for a retry.

Reconnect using exponential backoff, for example 1s → 2s → 4s → 8s → 16s, capped around 30s.

If an `enroll.start` command was delivered but no `enroll.result` reached the backend before disconnect, the backend returns that command to `pending` and replays it after the next successful handshake.

## 7. Heartbeat / connection state

The server sends WebSocket ping frames periodically. The terminal must support normal WebSocket ping/pong behavior.

The dashboard derives device availability from the authenticated WebSocket connection and the device's `last_seen_at` / heartbeat timestamps.

## 8. Security requirements

- Production uses WSS/TLS.
- The API key is generated automatically during first-time provisioning.
- The API key is returned once to the device.
- Store the API key securely on the terminal.
- Never hard-code the API key in firmware.
- The backend stores the API-key hash, not plaintext.
- Never log the API key.
- Never transmit raw fingerprint templates.
- A revoked device cannot authenticate.
- MAC-only provisioning is allowed only when a matching pending provisioning exists.

## 9. Important implementation rule

The device developer should treat this document as the protocol contract. Do not invent alternate message names or JSON fields. If a new command is required, agree on the message type and payload with the backend developer before implementing it.
