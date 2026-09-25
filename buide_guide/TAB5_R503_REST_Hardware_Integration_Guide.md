# VERUNUM — TAB5 / R503 Hardware Developer Integration Guide

**Protocol:** REST over HTTP/HTTPS only
**Audience:** Hardware / firmware developer
**Purpose:** Implement the TAB5 fingerprint terminal so that it communicates with the Verunum backend exactly as the platform expects.

> **Important:** This guide describes the current REST-only hardware architecture. The previous WebSocket hardware contract is superseded for this version. **Do not implement a WebSocket device protocol for this build.**

---

## 1. System Goal

The TAB5 is the physical attendance terminal. It uses the R503 fingerprint sensor locally, communicates with Verunum using REST requests, receives commands by polling, reports enrollment results, submits attendance events, and queues attendance locally when the network is unavailable.

```
                 VERUNUM
                    │
          HTTPS / REST API
                    │
                    ▼
              ┌───────────┐
              │    TAB5   │
              │           │
              │ Firmware  │
              └─────┬─────┘
                    │ UART
                    ▼
                 R503
              Fingerprint
                Sensor
```

---

## 2. Base URL

| Environment | Base URL |
|---|---|
| Production | `https://YOUR-HOST/api/v1` |
| Initial EC2 testing | `http://YOUR_EC2_PUBLIC_IP:8080/api/v1` |

The hardware should keep the API base URL **configurable** rather than hard-coded into application logic. HTTPS must be used when the backend is exposed as a production service.

---

## 3. Device Lifecycle

```
ADMIN
  │
  ├─ creates organisation
  ├─ creates pending device provisioning (organisation + MAC + device name)
  │
  ▼
TAB5 calls POST /devices/hello
  │
  ▼
VERUNUM checks MAC against pending provisioning records
  │
  ├─ MATCH ──► create permanent device
  │            bind device to organisation
  │            consume pending provisioning
  │            generate API key (returned ONCE)
  │            store API-key hash
  │
  ▼
TAB5 receives API key, stores it in secure persistent storage
  │
  ▼
authenticated REST requests (X-Device-Key header)
```

**Critical provisioning rule:** the API key is returned **only** during successful provisioning. It must not be hard-coded into firmware source code.

---

## 4. API Authentication

After provisioning, every device-authenticated request must include the API key in the HTTP header:

```http
X-Device-Key: <api-key>
```

The backend stores a **hash** of the device API key and validates the supplied key. A revoked device is rejected with `401`.

The device ID used in URL paths is returned at provisioning time as `dev_<n>` (e.g. `dev_123`). Use it verbatim in paths — both `dev_123` and the bare number `123` are accepted.

---

## 5. First-Time Device Provisioning

**Step 1** — An organisation administrator creates a pending device provisioning record in the Verunum dashboard (organisation, MAC address, device name, optional location).

**Step 2** — The TAB5 sends its identity to the backend:

```http
POST /api/v1/devices/hello
Content-Type: application/json

{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "device_name": "Main Gate TAB5",
  "protocol_version": 1,
  "firmware_version": "1.0.0"
}
```

| Field | Required | Notes |
|---|---|---|
| `mac_address` | yes | Normalised by the backend (case/separator-insensitive). Must be a valid 48-bit MAC. |
| `device_name` | yes | Non-empty string. |
| `protocol_version` | yes | Must be `1`. |
| `firmware_version` | no | Free-form string, echoed back. |
| `api_key` | no | For already-provisioned devices; normally sent via `X-Device-Key` header instead. |

**Step 3** — The backend compares the MAC address against pending provisioning records.

**Step 4** — If matched, the backend creates the permanent device, binds it to the organisation, consumes the pending record and generates the device API key.

**Step 5** — The API key is returned once:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "status": "provisioned",
  "device_id": "dev_123",
  "organization_id": 1,
  "device_name": "Main Gate TAB5",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "api_key": "dev_sec_<one-time-secret>",
  "protocol_version": 1,
  "firmware_version": "1.0.0",
  "message": "Store this API key securely. It is returned only during provisioning."
}
```

**Error cases:**

| Status | Condition |
|---|---|
| `400` | Missing/invalid MAC, missing device name, unsupported protocol version. |
| `404` | Unknown MAC — no pending provisioning record exists for this MAC. |
| `409` | MAC already provisioned — the request did not include a valid API key. |
| `401` | API key presented but invalid, or device revoked. |

**Returning device authentication** — a provisioned device that presents a valid key gets:

```http
HTTP/1.1 200 OK

{
  "status": "authenticated",
  "device_id": "dev_123",
  "organization_id": 1,
  "protocol_version": 1,
  "message": "Connected successfully."
}
```

---

## 6. Heartbeat

The TAB5 periodically tells the backend that it is alive:

```http
POST /api/v1/devices/{device_id}/heartbeat
X-Device-Key: <api-key>
```

**Response:** `204 No Content` (no body).

- Recommended firmware interval: **every 30 seconds**.
- The dashboard considers a device online when its last heartbeat is **no older than ~90 seconds**.

---

## 7. Command Polling

REST is request/response based — the backend does **not** push commands to the TAB5. The TAB5 polls for pending commands:

```http
GET /api/v1/devices/{device_id}/commands
X-Device-Key: <api-key>
```

Example response:

```http
HTTP/1.1 200 OK

{
  "commands": [
    {
      "id": 41,
      "command_type": "enroll.start",
      "payload": {
        "request_id": "41",
        "user_id": "user-uuid",
        "finger_index": 1,
        "timeout_seconds": 30
      },
      "created_at": "2026-09-25T00:00:00Z"
    }
  ]
}
```

- Recommended polling interval: **every 2–5 seconds** during normal operation, with backoff when the network is unavailable.
- Pending commands remain on the backend until the device acknowledges them. This is what allows an offline device to receive a command after it comes back online.
- The `payload.request_id` field equals the command `id` as a string — use it to correlate the enrollment result (see §9).

---

## 8. Command Acknowledgement

```http
POST /api/v1/devices/{device_id}/commands/{command_id}/ack
X-Device-Key: <api-key>
Content-Type: application/json

{
  "status": "acked"
}
```

- `status` may be `"acked"` (operation completed/accepted) or `"delivered"` (received). Defaults to `"acked"` if omitted.
- **Response:** `204 No Content` on success; `404` if the command does not belong to this device.
- A command should only be acknowledged **after** the TAB5 has accepted or completed the requested operation — **not** merely because it was downloaded.

---

## 9. Fingerprint Enrollment

**Dashboard side:** the administrator chooses a person and a device and starts fingerprint enrollment:

```http
POST /api/v1/devices/{device_id}/enroll-request
Content-Type: application/json

{
  "user_id": "user-uuid",
  "finger_index": 1,
  "timeout_seconds": 30
}
```

(This is an admin-authenticated endpoint — the device never calls it.)

The backend creates an `enroll.start` command for that device. The TAB5 discovers the command through command polling (§7), then uses the R503 to perform the fingerprint operation **locally**.

**The TAB5 then reports the result:**

```http
POST /api/v1/devices/{device_id}/enrollment/result
X-Device-Key: <api-key>
Content-Type: application/json

{
  "command_id": 41,
  "request_id": "41",
  "user_id": "user-uuid",
  "finger_index": 1,
  "success": true
}
```

| Field | Required | Notes |
|---|---|---|
| `command_id` | yes | The `id` of the command being reported (preferred correlation key). |
| `request_id` | yes | The `payload.request_id` from the polled command (accepted as an alternative correlation key). |
| `user_id` | yes | The user UUID from the enroll command. |
| `finger_index` | no | Slot used on the device. |
| `success` | yes | `true` = enrolled, `false` = failed. |

**Biometric rule:** raw fingerprint templates are **never** sent to the Verunum backend under this contract. The biometric operation remains local to the TAB5/R503.

**Response:** `200 OK` — the command is acknowledged and the user's fingerprint status is updated on the dashboard.

---

## 10. Attendance

The TAB5 performs fingerprint matching locally. When a fingerprint is matched to a Verunum user, the terminal sends an attendance event:

```http
POST /api/v1/devices/{device_id}/attendance
X-Device-Key: <api-key>
Content-Type: application/json

{
  "user_id": 12,
  "event_id": "evt-unique-001",
  "event": "clock_in",
  "timestamp": "2026-09-25T08:15:00Z",
  "method": "fingerprint"
}
```

| Field | Required | Notes |
|---|---|---|
| `user_id` | yes | Verunum user ID (integer). |
| `event_id` | yes | Unique event identifier — **mandatory** for reliable synchronization (see §11). |
| `event` | yes | Event type, e.g. `clock_in`, `clock_out`. |
| `timestamp` | no | RFC 3339 UTC. Server time is used if omitted/invalid. |
| `method` | no | Defaults to `fingerprint`. |

> The device is identified by the `{device_id}` path segment and the `X-Device-Key` header — **do not send `device_id` in the body**.

**Response:**

```http
HTTP/1.1 201 Created

{
  "id": 501,
  "attendance_status": "on_time"
}
```

`attendance_status` is computed by the backend (`on_time` / `late` for `clock_in` based on the organisation's attendance rules).

---

## 11. Offline Attendance & Deduplication

```
NETWORK AVAILABLE                    NETWORK UNAVAILABLE
─────────────────────                  ─────────────────────
Fingerprint match                      Fingerprint match
  ▼                                      ▼
R503 local match                       R503 local match
  ▼                                      ▼
TAB5 identifies user                   TAB5 identifies user
  ▼                                      ▼
POST /attendance                       Store event locally
  ▼                                    ├─ preserve event_id
Backend stores event                   ├─ preserve timestamp
                                       │
                                       ▼
                                     Network returns
                                       │
                                       ▼
                                     Retry POST /attendance
                                     (SAME event_id)
                                       │
                                       ▼
                                     Backend deduplicates by event_id
                                       │
                                       ▼
                                     Remove local event
```

**`event_id` is mandatory for reliable synchronization.** If the same event is retried, the original `event_id` must be preserved so the backend can identify duplicates. A retried event returns the **original** record ID with `201 Created` — it is never stored twice.

For multiple queued events, use the batch endpoint:

```http
POST /api/v1/devices/{device_id}/attendance/batch
X-Device-Key: <api-key>
Content-Type: application/json

[
  {
    "user_id": 12,
    "event_id": "evt-001",
    "event": "clock_in",
    "timestamp": "2026-09-25T08:15:00Z",
    "method": "fingerprint"
  },
  {
    "user_id": 12,
    "event_id": "evt-002",
    "event": "clock_out",
    "timestamp": "2026-09-25T17:00:00Z",
    "method": "fingerprint"
  }
]
```

**Response:**

```http
HTTP/1.1 201 Created

{
  "received": 2,
  "created": 2,
  "deduplicated": 0
}
```

- `received` — number of events in the request.
- `created` — events newly stored.
- `deduplicated` — events whose `event_id` already existed (safe to delete from the local queue).

Invalid events (unknown user, missing fields) count toward `received` but not `created`; they can be retried after correction.

---

## 12. Complete Hardware Communication Flow

```
POWER ON
  │
  ├─ Load configuration
  │    ├─ API base URL
  │    └─ stored device credential (if provisioned)
  │
  ▼
Have API key?
  │
  ├─ NO ──► POST /devices/hello ──► MAC matched?
  │                                   │
  │                              NO ─┴─ YES
  │                               │       │
  │                         retry /   receive api_key
  │                         backoff     │
  │                               │   store key securely
  │                               │       │
  ├─ YES ◄────────────────────────┘
  │
  ▼
heartbeat every 30s
  │
  ├──► poll commands (every 2–5s) ──► enroll.start ──► R503 capture ──► POST enrollment/result ──► ack command
  │
  └──► fingerprint scan ──► local match ──► POST attendance ──► 201
```

---

## 13. API Endpoint Reference

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/devices/hello` | First-time MAC-based provisioning / re-authentication |
| `POST` | `/api/v1/devices/{device_id}/heartbeat` | Device liveness heartbeat |
| `GET` | `/api/v1/devices/{device_id}/commands` | Poll pending commands |
| `POST` | `/api/v1/devices/{device_id}/commands/{command_id}/ack` | Acknowledge command |
| `POST` | `/api/v1/devices/{device_id}/enrollment/result` | Return enrollment result |
| `POST` | `/api/v1/devices/{device_id}/attendance` | Submit one attendance event |
| `POST` | `/api/v1/devices/{device_id}/attendance/batch` | Synchronize queued attendance events |

**Admin-side endpoints (dashboard only, not called by firmware):**

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/platform/devices/pending` | Create pending provisioning record (pre-hello) |
| `POST` | `/api/v1/devices/{device_id}/enroll-request` | Create fingerprint enrollment command |

---

## 14. HTTP Status Handling

| Status | Meaning for firmware |
|---|---|
| `200` | Request succeeded and response body contains data. |
| `201` | Resource/event successfully created (provisioning, attendance). |
| `202` | Enrollment command accepted (admin endpoint). |
| `204` | Success with no response body (heartbeat, command ack). |
| `400` | Invalid request. Do not retry unchanged data. |
| `401` | Device authentication failed. Check stored API key. |
| `403` | Authenticated but not permitted for the requested operation. |
| `404` | Resource/device/command not found, or unknown MAC at hello. |
| `409` | Conflict — already-provisioned MAC at hello. |
| `422` | Target device offline (admin enrollment trigger). |
| `429` | Rate limited. Back off before retrying. |
| `5xx` | Server-side failure. Retry with backoff. |

---

## 15. Retry Rules

- Do not rapidly retry a failed request in a tight loop.
- Use increasing backoff when the server cannot be reached.
- **Never generate a new `event_id`** when retrying an already-created attendance event.
- Do not acknowledge a command merely because it was downloaded.
- If a command was downloaded but the device lost power before completion, recover safely according to the command's operation and re-poll — pending commands are re-delivered.
- After network recovery, heartbeat and command polling should resume automatically.

---

## 16. Security Requirements

- Do not hard-code a production API key into firmware source.
- The provisioning API key is delivered **once** — store it in secure persistent storage where the hardware permits.
- Send `X-Device-Key` on all authenticated device requests.
- Use HTTPS in production.
- Do not send raw fingerprint templates to the backend.
- Do not print the device API key in normal serial logs.
- Do not expose the API key in screenshots or diagnostic output sent to third parties.
- If a device credential is revoked, the device must stop treating itself as authenticated and follow the project's re-provisioning/recovery procedure.

---

## 17. Firmware State Machine

```
BOOT
  │
  ├─ no credential ──► PROVISIONING ──(success)──► READY
  │                        │
  │                        └─ 404/409 ──► retry with backoff
  │
  ├─ credential exists ──────────────────────────► READY

READY
  │
  ├─ heartbeat (every 30s)
  ├─ command poll (every 2–5s)
  ├─ fingerprint operation ──► attendance upload
  │
  └─ network failure ──► OFFLINE_QUEUE

OFFLINE_QUEUE
  │
  ├─ keep event_id
  ├─ keep timestamp
  ├─ retry after network recovery
  │
  ▼
READY
```

---

## 18. Hardware Developer Checklist

- [ ] Configure the Verunum API base URL.
- [ ] Read the device's MAC address reliably.
- [ ] Send `POST /api/v1/devices/hello` on first provisioning.
- [ ] Parse the provisioning response and securely persist `device_id` and `api_key`.
- [ ] Do not hard-code production credentials.
- [ ] Send `X-Device-Key` on authenticated requests.
- [ ] Implement heartbeat every 30 seconds.
- [ ] Implement command polling every 2–5 seconds with network-failure backoff.
- [ ] Implement `enroll.start` handling.
- [ ] Use R503 locally for fingerprint capture.
- [ ] Implement enrollment result reporting (`POST /enrollment/result`).
- [ ] Implement local fingerprint matching.
- [ ] Generate a unique attendance `event_id` per event.
- [ ] Preserve `event_id` when retrying.
- [ ] Implement offline attendance storage.
- [ ] Implement batch synchronization.
- [ ] Implement command acknowledgement.
- [ ] Implement HTTP status/error handling.
- [ ] Never transmit raw fingerprint templates.

---

## 19. End-to-End Hardware Acceptance Test

1. Admin creates an organisation.
2. Admin creates a pending device with the TAB5 MAC address.
3. TAB5 boots without an API key.
4. TAB5 `POST`s `/devices/hello`.
5. Backend matches the MAC.
6. Backend creates and binds the device.
7. Backend returns the API key once.
8. TAB5 securely stores the key.
9. TAB5 sends heartbeat (`204`).
10. TAB5 polls commands (empty list).
11. Admin starts enrollment.
12. TAB5 receives `enroll.start`.
13. R503 captures the fingerprint locally.
14. TAB5 `POST`s `enrollment/result`; command becomes `acked`.
15. User presents fingerprint.
16. TAB5 matches locally.
17. TAB5 `POST`s attendance with `event_id` (`201`, `attendance_status` returned).
18. Backend stores the attendance.
19. Disconnect network.
20. User presents fingerprint again.
21. TAB5 stores attendance locally (same `event_id`, original timestamp).
22. Restore network.
23. TAB5 retries the same `event_id`.
24. Backend returns the original record ID — stored once.
25. TAB5 continues heartbeat and command polling.

---

## 20. Final Rule for the Firmware Developer

The TAB5 is a **REST client**. It does not maintain a WebSocket connection to Verunum in this version. All device communication is ordinary HTTP/HTTPS request/response communication.

The backend is authoritative for device identity, organisation binding, provisioning, commands and attendance persistence. The TAB5/R503 is responsible for local fingerprint capture/matching and temporary offline attendance storage.

If an endpoint or JSON field in the implementation differs from this guide, treat the actual deployed REST contract as the source of truth and update this document before firmware integration proceeds.
