PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'school',
    settings_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_access_codes (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    code_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS organization_onboarding (
    access_code_id INTEGER PRIMARY KEY REFERENCES organization_access_codes (id),
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    owner_user_id INTEGER NOT NULL REFERENCES users (id),
    claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    name TEXT NOT NULL,
    location TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    branch_id INTEGER REFERENCES branches (id),
    uuid TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    status TEXT NOT NULL DEFAULT 'active',
    fingerprint_status TEXT NOT NULL DEFAULT 'not_enrolled',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS users_org_email ON users (organization_id, email)
WHERE
    email IS NOT NULL;

CREATE TABLE IF NOT EXISTS pending_device_enrollments (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL,
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    device_name VARCHAR(100) NOT NULL,
    location VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    branch_id INTEGER REFERENCES branches (id),
    name TEXT NOT NULL,
    serial_number TEXT,
    mac_address TEXT UNIQUE,
    api_key TEXT,
    api_key_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline',
    last_heartbeat TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_access_codes (
    device_id INTEGER PRIMARY KEY REFERENCES devices (id),
    access_code_id INTEGER NOT NULL REFERENCES organization_access_codes (id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_enrollments (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    user_id INTEGER NOT NULL REFERENCES users (id),
    device_id INTEGER NOT NULL REFERENCES devices (id),
    slot_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    enrolled_at TEXT,
    UNIQUE (device_id, slot_id)
);

CREATE TABLE IF NOT EXISTS rfid_cards (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    user_id INTEGER REFERENCES users (id),
    uid TEXT NOT NULL,
    card_uid TEXT,
    card_type TEXT NOT NULL DEFAULT 'standard',
    issue_date TEXT NOT NULL,
    expiry_date TEXT,
    status TEXT NOT NULL DEFAULT 'issued',
    personalization_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, uid)
);

CREATE TABLE IF NOT EXISTS rfid_card_history (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    card_id INTEGER NOT NULL REFERENCES rfid_cards (id),
    action TEXT NOT NULL,
    previous_card_id INTEGER,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attendance_rules (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL UNIQUE REFERENCES organizations (id),
    working_hours TEXT NOT NULL DEFAULT '{"start":"08:00","end":"17:00"}',
    late_threshold_minutes INTEGER NOT NULL DEFAULT 15,
    early_departure_minutes INTEGER NOT NULL DEFAULT 15,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attendance_events (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    user_id INTEGER NOT NULL REFERENCES users (id),
    device_id INTEGER NOT NULL REFERENCES devices (id),
    event_id TEXT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    attendance_status TEXT NOT NULL DEFAULT 'on_time',
    sync_status TEXT NOT NULL DEFAULT 'synced',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, device_id, timestamp, event_type)
);
CREATE UNIQUE INDEX IF NOT EXISTS attendance_events_event_id_idx ON attendance_events(event_id) WHERE event_id IS NOT NULL AND event_id != '';

CREATE TABLE IF NOT EXISTS device_commands (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    device_id INTEGER NOT NULL REFERENCES devices (id),
    command_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TEXT,
    acked_at TEXT
);

CREATE TABLE IF NOT EXISTS sms_templates (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    name TEXT NOT NULL,
    body TEXT NOT NULL,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sms_logs (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    attendance_event_id INTEGER REFERENCES attendance_events (id),
    recipient_phone TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    job_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations (id),
    actor_user_id INTEGER REFERENCES users (id),
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    before_json TEXT,
    after_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);