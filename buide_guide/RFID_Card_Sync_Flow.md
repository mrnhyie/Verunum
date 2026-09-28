# RFID Card Sync — Firmware Flow

**Audience:** Hardware / firmware developer
**Scope:** How the TAB5 learns that it must scan an RFID card, and how it confirms the card back to Verunum. This is the card equivalent of `enroll.start` fingerprint enrollment — full contract in the main guide, §7–§9a.

---

## The idea in one line

An RFID card is **not** considered bound to a terminal until the terminal itself reads the card UID and reports it back. Until then the card shows as **pending** on the dashboard, and a `card.enroll` command waits on the backend for that device.

---

## Flow

```
ADMIN registers card + picks terminal
        │
        ▼
VERUNUM queues command { command_type: "card.enroll" } for that device
   (card status = pending)
        │
        ▼
TAB5 polls GET /devices/{device_id}/commands
        │
      sees "card.enroll"
        │
        ▼
TAB5 scans / reads the RFID card locally
        │
        ▼
TAB5 POSTs /devices/{device_id}/card/result  { card_uid, success: true }
        │
        ▼
VERUNUM: card issued + bound to this terminal, command acked, dashboard updates
```

---

## 1. You receive the command

The existing command poll is unchanged. `card.enroll` arrives in the same `commands` array as `enroll.start`:

```http
GET /api/v1/devices/{device_id}/commands
X-Device-Key: <api-key>
```

```json
{
  "commands": [
    {
      "id": 42,
      "command_type": "card.enroll",
      "payload": {
        "request_id": "42",
        "card_id": 7,
        "card_uid": "04A2B3C4",
        "user_id": "user-uuid",
        "timeout_seconds": 30
      },
      "created_at": "2026-09-28T00:00:05Z"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `request_id` | The command `id` as a string — put it in your result. |
| `card_id` | Verunum card record ID. |
| `card_uid` | The UID registered in the dashboard. |
| `user_id` | Cardholder UUID; absent if the card is unassigned. |
| `timeout_seconds` | Window to complete the scan. |

## 2. Scan the card

Branch on `command_type`. Only on `card.enroll` should the terminal prompt for / read an RFID card at that moment (same idea as `enroll.start` triggering a fingerprint capture). Read the UID locally and store it in the local card roster.

## 3. Report the result

```http
POST /api/v1/devices/{device_id}/card/result
X-Device-Key: <api-key>
Content-Type: application/json

{
  "command_id": 42,
  "request_id": "42",
  "card_id": 7,
  "card_uid": "04A2B3C4",
  "success": true
}
```

- `success: true` → card becomes **issued**, bound to this terminal, command acked.
- `success: false` → card marked **failed**, stays unbound, command acked. Admin can re-send it.
- Send every field you know — the backend matches on `command_id` → `request_id` → `card_id` / `card_uid`.
- **Response:** `200 OK` body `{"ok": true, "status": "issued"}`.
- `404` = card not registered in this device's organisation ("unknown card"); do not retry.

## 4. Acknowledge

If your firmware acks commands via `POST /commands/{id}/ack`, only ack **after** the scan step has completed and the result has been reported. Do not ack `card.enroll` just because it was downloaded — that would drop the scan request.

If you report the result via `/card/result`, the backend acks the command for you (the result **is** the acknowledgement) — an extra explicit ack is harmless but not required.

---

## Rules of thumb

- One command = one card scan. If several `card.enroll` commands are pending, process each one and report each result with its own `command_id`/`request_id`.
- If the scan times out with no card presented, report `success: false` rather than leaving the command unacked, so the queue doesn't stall and the admin can retry.
- UID matching is case-insensitive on the backend, but report the UID exactly as read.
- No card secrets or biometric data are ever sent — only the UID string.
