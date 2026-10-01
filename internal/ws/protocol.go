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
	TypeCardEnroll   = "card.enroll"
	TypeUserUpdate   = "user.update"
	TypeUserDelete   = "user.delete"
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

// CardEnrollPayload tells the terminal to add an RFID card UID to its local
// roster and bind it to the given user.
type CardEnrollPayload struct {
	RequestID      string `json:"request_id"`
	CardID         int    `json:"card_id"`
	CardUID        string `json:"card_uid"`
	UserID         string `json:"user_id,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// CardResultPayload is the report the TAB5 sends after accepting (or failing
// to accept) an RFID card UID from a card.enroll command.
type CardResultPayload struct {
	CommandID int    `json:"command_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	CardID    int    `json:"card_id,omitempty"`
	CardUID   string `json:"card_uid,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Success   *bool  `json:"success,omitempty"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
}

type AttendancePayload struct {
	EventID   string `json:"event_id"`
	UserID    string `json:"user_id"`
	Event     string `json:"event"`
	Timestamp string `json:"timestamp,omitempty"`
	Method    string `json:"method,omitempty"`
}

// UserUpdatePayload carries the authoritative user record so terminals can
// replace their local roster entry. CardUIDs is the complete current card
// list: replacing a lost card is expressed by re-sending the new set.
type UserUpdatePayload struct {
	RequestID string   `json:"request_id"`
	UserID    string   `json:"user_id"`
	FullName  string   `json:"full_name,omitempty"`
	Phone     string   `json:"phone,omitempty"`
	Role      string   `json:"role,omitempty"`
	Status    string   `json:"status,omitempty"`
	CardUIDs  []string `json:"card_uids,omitempty"`
}

// UserDeletePayload tells terminals to remove the user from their local
// roster. The platform soft-deletes: user status becomes inactive.
type UserDeletePayload struct {
	RequestID string `json:"request_id"`
	UserID    string `json:"user_id"`
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
	UserName   string `json:"user_name,omitempty"`
	CardUID    string `json:"card_uid,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	OrgID      string `json:"org_id,omitempty"`
	OrgName    string `json:"org_name,omitempty"`
	Method     string `json:"method,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	Message    string `json:"message,omitempty"`
	MessageID  int64  `json:"message_id,omitempty"`
	Sender     string `json:"sender,omitempty"`
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
