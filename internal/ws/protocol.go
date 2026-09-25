package ws

import "encoding/json"

const ProtocolVersion = 1

const (
	TypeHello        = "hello"
	TypeHelloAck     = "hello.ack"
	TypePing         = "ping"
	TypePong         = "pong"
	TypeEnrollStart  = "enroll.start"
	TypeEnrollResult = "enroll.result"
	TypeAttendance   = "attendance"
	TypeAck          = "ack"
	TypeError        = "error"
)

// Envelope is the standard JSON shape for device API request/response bodies.
type Envelope struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Status    string          `json:"status,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type HelloPayload struct {
	MACAddress      string `json:"mac_address"`
	DeviceName      string `json:"device_name"`
	ProtocolVersion int    `json:"protocol_version"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	APIKey          string `json:"api_key,omitempty"`
}

type HelloAckPayload struct {
	DeviceID        string `json:"device_id"`
	APIKey          string `json:"api_key,omitempty"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	Message         string `json:"message"`
}

type EnrollStartPayload struct {
	RequestID      string `json:"request_id"`
	UserID         string `json:"user_id"`
	FingerIndex    int    `json:"finger_index,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// EnrollResultPayload is the report the TAB5 sends after a local R503
// enrollment operation. Raw templates never leave the device.
type EnrollResultPayload struct {
	CommandID   int    `json:"command_id,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	UserID      string `json:"user_id"`
	FingerIndex int    `json:"finger_index,omitempty"`
	Success     *bool  `json:"success,omitempty"`
	Status      string `json:"status,omitempty"`
	Error       string `json:"error,omitempty"`
}

type AttendancePayload struct {
	EventID   string `json:"event_id"`
	UserID    string `json:"user_id"`
	Event     string `json:"event"`
	Timestamp string `json:"timestamp,omitempty"`
	Method    string `json:"method,omitempty"`
}

type AckPayload struct {
	OK     bool   `json:"ok"`
	ID     int64  `json:"id,omitempty"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type SSEEvent struct {
	Event      string `json:"event"`
	Status     string `json:"status,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	OrgID      string `json:"org_id,omitempty"`
	Message    string `json:"message,omitempty"`
}

func MarshalEnvelope(typ, requestID, status string, payload any) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return json.Marshal(Envelope{Type: typ, RequestID: requestID, Status: status, Payload: raw})
}
