# Implementation Plan: End-to-End Device Auto-Provisioning, Platform Management & Real-Time Biometric Enrollment Workflow

This plan details the implementation of the hardware-to-backend device auto-provisioning lifecycle, the dedicated platform organization profile management view, and the interactive real-time biometric enrollment flow with live SSE/WebSocket updates.

## User Review Required

> [!IMPORTANT]
> - **Schema Migration & Backward Compatibility:** Existing SQLite tables (`devices`, `rfid_cards`) will be upgraded safely using dynamic column addition (`mac_address`, `last_seen_at`, `api_key`, `card_uid`, `card_type`), and `pending_device_enrollments` will be created. Both integer and UUID/string identifiers for devices/orgs will be seamlessly handled.
> - **SSE & WebSocket Endpoints:** An SSE stream (`GET /api/v1/events` and `/api/v1/platform/events`) alongside WebSocket `/ws/device` will handle real-time events (`device.provisioned`, `user.enrollment_updated`) for instantaneous browser feedback without polling.

---

## Proposed Changes

### 1. Database Layer (`internal/db`)

#### [MODIFY] [schema.sql](file:///Users/nhyie/SparklabAfrica/Verunum/internal/db/schema.sql)
- Add `pending_device_enrollments` table schema:
  ```sql
  CREATE TABLE IF NOT EXISTS pending_device_enrollments (
      id VARCHAR(36) PRIMARY KEY,
      org_id VARCHAR(36) NOT NULL,
      mac_address VARCHAR(17) UNIQUE NOT NULL,
      device_name VARCHAR(100) NOT NULL,
      location VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  ```
- Ensure columns in `devices` (`mac_address`, `api_key`, `last_seen_at`) and `rfid_cards` (`card_uid`, `card_type`).

#### [MODIFY] [db.go](file:///Users/nhyie/SparklabAfrica/Verunum/internal/db/db.go)
- Add column migration checks via `ensureColumn` for:
  - `devices.mac_address TEXT`
  - `devices.api_key TEXT`
  - `devices.last_seen_at TEXT`
  - `rfid_cards.card_uid TEXT`
  - `rfid_cards.card_type TEXT DEFAULT 'standard'`
- Create table `pending_device_enrollments` if not exists.

---

### 2. WebSocket & Real-Time Event Hub (`internal/ws`)

#### [MODIFY] [protocol.go](file:///Users/nhyie/SparklabAfrica/Verunum/internal/ws/protocol.go)
- Add protocol payload definitions for:
  - `HelloAckPayload` (`device_id`, `api_key`, `message`, `status`)
  - `EnrollStartPayload` (`user_id`, `finger_index`, `timeout_seconds`)
  - `EnrollResultPayload` (`user_id`, `finger_index`, `template_hash`, `status`, `error`)
  - `SSEEvent` (`event`, `status`, `user_id`, `device_id`, `mac_address`, `org_id`, `payload`)

#### [MODIFY] [hub.go](file:///Users/nhyie/SparklabAfrica/Verunum/internal/ws/hub.go)
- Add Event Broker (`SSEBroker` / subscription manager) inside or alongside `Hub` to broadcast SSE events to connected web clients.
- Update connection upgrade logic for `GET /ws/device` (and `/api/v1/devices/ws`):
  1. Inspect `X-Device-MAC` header (or query parameter).
  2. If missing, return HTTP 400 Bad Request.
  3. Look up in `pending_device_enrollments`:
     - If matched: generate `dev_sec_<random>`, insert into `devices` table, remove from `pending_device_enrollments`, send `hello.ack` with status `"provisioned"`, and broadcast `device.provisioned` event via SSE/WS.
  4. If found in `devices`:
     - Validate, send `hello.ack` with status `"authenticated"`.
  5. If unrecognized MAC:
     - Reject upgrade with HTTP 403 / close frame `4001: Unregistered Hardware MAC`.
- Add `EnrollRequest(deviceID string/int, userID string, fingerIndex int)` to send `enroll.start` over WebSocket.
- Update `enrollResult` handling to store biometric template metadata / update user status and broadcast `user.enrollment_updated` SSE event to web clients.

---

### 3. Server Endpoints & API Routes (`cmd/server`)

#### [MODIFY] [main.go](file:///Users/nhyie/SparklabAfrica/Verunum/cmd/server/main.go)
- **Device Provisioning API:**
  - `POST /api/v1/platform/devices/pending`: validates `org_id`, `device_name`, `mac_address`, `location` and inserts into `pending_device_enrollments`.
  - `GET /api/v1/platform/events` and `GET /api/v1/events`: Server-Sent Events (SSE) stream endpoint for real-time frontend updates.
- **Biometric Enrollment API:**
  - `POST /api/v1/devices/:device_id/enroll-request`: checks device online status in `Hub`. Returns `422 Unprocessable Entity` if offline; sends `enroll.start` and returns `202 Accepted` if online.
- **Platform Routes & Organization Profile:**
  - Mount `/platform/device-provisioning` and `/admin/organizations/:orgId/devices/new`.
  - Mount `/platform/organisations/:org_id` and `/admin/organizations/:orgId` for the dedicated Organization Profile view.
  - Implement handler fetching:
    - Org info, category badge, creation date, status toggle, primary contact.
    - Provisioned Devices counter (online vs offline).
    - Enrolled users counter.
    - 30-Day activity metrics (scan volume).
    - Hardware inventory table with real-time status dots, MAC address, Last Seen, and action buttons (Revoke, Re-provision).

---

### 4. Web UI Templates & Frontend State Machines (`web/templates`, `web/static`)

#### [MODIFY] [provision_device_form.html](file:///Users/nhyie/SparklabAfrica/Verunum/web/templates/provision_device_form.html)
- Update form field labels:
  - Label: **"Device MAC address"**
  - Placeholder: `e.g. AA:BB:CC:DD:EE:FF`
  - Button: **"Request device provisioning"**
- Build Provisioning Waiting State Machine:
  - Submit via AJAX `POST /api/v1/platform/devices/pending`.
  - Swap form with waiting screen: centered spinner, *"Waiting for physical device (AA:BB:CC:DD:EE:FF) to connect..."*, 3-minute live countdown timer, and `[ Cancel ]` button.
  - Connect to SSE `/api/v1/platform/events` (or `/api/v1/events`).
  - On `device.provisioned`: show green checkmark banner *"Device successfully bound and provisioned!"* and redirect to `/platform/organisations/:org_id`.
  - On 3-minute timeout / cancel: show warning alert *"Provisioning timed out. Verify device is powered on and configured."* with `[ Retry ]` and `[ Return to Organisations ]`.

#### [NEW] [organization_profile.html](file:///Users/nhyie/SparklabAfrica/Verunum/web/templates/organization_profile.html)
- Organization Profile Page:
  - Header with Category Badge, Creation Date, Active Status toggle, Primary Contact card.
  - Metrics Cards: Provisioned Devices (Active vs Offline), Enrolled Users, 30-Day Activity Chart (SVG/CSS bar chart).
  - Hardware Inventory Table: Device Name, MAC Address, Online/Offline indicator dot, Last Seen timestamp, Actions (Revoke, Re-provision).

#### [MODIFY] [organizations.html](file:///Users/nhyie/SparklabAfrica/Verunum/web/templates/organizations.html)
- Link organization rows and the "Device" button to `/platform/organisations/:org_id` / `/platform/device-provisioning?org_id=:org_id`.

#### [MODIFY] [users.html](file:///Users/nhyie/SparklabAfrica/Verunum/web/templates/users.html) & [user_form.html](file:///Users/nhyie/SparklabAfrica/Verunum/web/templates/user_form.html)
- Update "Add User" modal / page:
  - Two-column responsive layout:
    - **Left Column:** First Name, Last Name, Email, Role, Assigned Device Select dropdown.
    - **Right Column:** Interactive Fingerprint Scanner Widget with dynamic visual states (`idle`, `waiting_for_click`, `scanning`, `success`, `error`).
    - Action button: `[ Click to Request Fingerprint ]`.
    - Real-time SSE listener for `user.enrollment_updated`.
    - Handles offline device (HTTP 422 red error message) and online device (HTTP 202 pulsing animation -> success state -> enables Save User).

#### [MODIFY] [app.css](file:///Users/nhyie/SparklabAfrica/Verunum/web/static/app.css)
- Add styles for:
  - Provisioning spinner, countdown timer, checkmark banner, and timeout alerts.
  - Organization profile widgets, 30-day activity chart, and status indicator dots.
  - Two-column Add User modal and pulsing biometric scanner animations.

---

## Verification Plan

### Automated Tests
- `go test ./...`: Run existing tests and new unit tests for:
  - Device pending enrollment insertion & duplicate handling.
  - Handshake logic: pending match -> provisioning ack + SSE event; recognized device -> auth ack; unknown MAC -> reject.
  - Biometric enrollment trigger & offline/online status check.

### Manual / Integration Verification
- **Device Provisioning Simulation:**
  - Submit provisioning request with MAC `AA:BB:CC:DD:EE:FF`.
  - Verify UI switches to 3-minute waiting state.
  - Simulate device connecting via WebSocket (`GET /ws/device` with `X-Device-MAC: AA:BB:CC:DD:EE:FF`).
  - Verify device receives `hello.ack` with `status: "provisioned"` and `api_key: "dev_sec_..."`.
  - Verify UI receives `device.provisioned` via SSE and redirects to Organization Profile.
- **Organization Profile Verification:**
  - Visit `/platform/organisations/:org_id`, check stats, chart, and hardware table with online/offline status.
- **Real-Time Fingerprint Enrollment Simulation:**
  - Open "Add User" modal, select online device, click `[ Click to Request Fingerprint ]`.
  - Verify `POST /api/v1/devices/:device_id/enroll-request` triggers `enroll.start` on WebSocket.
  - Simulate device sending `enroll.result` (`status: "success"`).
  - Verify backend emits `user.enrollment_updated` and UI transitions to green checkmark success state.
