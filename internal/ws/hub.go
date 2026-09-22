package ws

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 20 * time.Second
	sendBuf    = 32
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     checkWebSocketOrigin,
}

func checkWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	// Hardware WebSocket clients normally do not send Origin.
	if origin == "" {
		return true
	}

	allowed := strings.TrimSpace(os.Getenv("VERUNUM_WS_ORIGINS"))
	if allowed != "" {
		for _, item := range strings.Split(allowed, ",") {
			if strings.TrimSpace(item) == origin {
				return true
			}
		}
		return false
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	// Default: same-origin browser WebSockets only.
	return strings.EqualFold(u.Host, r.Host)
}

type AttendFunc func(orgID, deviceID int, eventID, userUUID, event, timestamp, method string) (int64, string, error)

type client struct {
	hub           *Hub
	deviceID      int
	orgID         int
	conn          *websocket.Conn
	send          chan []byte
	awaitingHello bool
	helloStatus   string
	apiKey        string
	devIDStr      string
	stateMu       sync.Mutex
	replayPending bool
}

type Hub struct {
	db      *sql.DB
	ingest  AttendFunc
	mu      sync.RWMutex
	conns   map[int]*client
	sseMu   sync.RWMutex
	sseSubs map[chan SSEEvent]bool
}

func NewHub(db *sql.DB, ingest AttendFunc) *Hub {
	return &Hub{
		db:      db,
		ingest:  ingest,
		conns:   map[int]*client{},
		sseSubs: map[chan SSEEvent]bool{},
	}
}

func (h *Hub) SubscribeSSE() chan SSEEvent {
	ch := make(chan SSEEvent, 16)
	h.sseMu.Lock()
	h.sseSubs[ch] = true
	h.sseMu.Unlock()
	return ch
}

func (h *Hub) UnsubscribeSSE(ch chan SSEEvent) {
	h.sseMu.Lock()
	if _, ok := h.sseSubs[ch]; ok {
		delete(h.sseSubs, ch)
		close(ch)
	}
	h.sseMu.Unlock()
}

func (h *Hub) BroadcastSSE(evt SSEEvent) {
	h.sseMu.RLock()
	defer h.sseMu.RUnlock()
	for ch := range h.sseSubs {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (h *Hub) SSEHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

		ch := h.SubscribeSSE()
		defer h.UnsubscribeSSE(ch)

		// Send initial connected comment to flush headers
		_, _ = fmt.Fprintf(c.Writer, ": connected\n\n")
		c.Writer.Flush()

		notify := c.Request.Context().Done()
		for {
			select {
			case <-notify:
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, err := json.Marshal(evt)
				if err != nil {
					continue
				}
				c.Stream(func(w io.Writer) bool {
					_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, string(data))
					return err == nil
				})
			}
		}
	}
}

func (h *Hub) Connected(deviceID int) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[deviceID]
	return ok
}

func (h *Hub) ConnectedIDs(orgID int) map[int]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[int]bool{}
	for id, c := range h.conns {
		if c.orgID == orgID {
			out[id] = true
		}
	}
	return out
}

func (h *Hub) Gin() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The WebSocket endpoint intentionally accepts an unauthenticated upgrade so
	// a brand-new terminal can send its MAC in the first hello frame. Authentication
	// and automatic provisioning happen inside the protocol handshake.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}

	// A reconnecting device may also supply its stored key in the header/query.
	// It is still required to send hello so the protocol is deterministic.
	key := strings.TrimSpace(r.Header.Get("X-Device-Key"))
	if key == "" {
		key = strings.TrimSpace(r.URL.Query().Get("api_key"))
	}

	c := &client{
		hub: h, deviceID: 0, orgID: 0, conn: conn, send: make(chan []byte, sendBuf),
		awaitingHello: true, helloStatus: "", apiKey: "", devIDStr: "",
	}
	if key != "" {
		// Store only the supplied credential for validation during hello. Never log it.
		c.apiKey = key
	}
	go c.writePump()
	c.readPump()
}

func normalizeMAC(v string) (string, bool) {
	raw := strings.ToUpper(strings.TrimSpace(v))
	raw = strings.ReplaceAll(raw, ":", "")
	raw = strings.ReplaceAll(raw, "-", "")
	if len(raw) != 12 {
		return "", false
	}
	for _, ch := range raw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
			return "", false
		}
	}
	var b strings.Builder
	for i := 0; i < len(raw); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(':')
		}
		b.WriteString(raw[i : i+2])
	}
	return b.String(), true
}

func (h *Hub) bindHello(c *client, p HelloPayload, requestID string) ([]byte, error) {
	mac, ok := normalizeMAC(p.MACAddress)
	if !ok {
		return nil, fmt.Errorf("valid mac_address is required in hello")
	}
	if p.DeviceName == "" {
		return nil, fmt.Errorf("device_name is required in hello")
	}
	if p.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", p.ProtocolVersion)
	}

	// A key may be supplied in the hello payload, or in X-Device-Key/api_key
	// captured by ServeHTTP. The first-time provisioning path intentionally has no key.
	presentedKey := strings.TrimSpace(p.APIKey)
	if presentedKey == "" {
		presentedKey = strings.TrimSpace(c.apiKey)
	}

	// 1. Automatic first-time provisioning: MAC must match an admin-created pending record.
	var pendingID, orgIDStr, pendingName, location string
	err := h.db.QueryRow(`SELECT id, org_id, device_name, COALESCE(location,'')
		FROM pending_device_enrollments WHERE UPPER(mac_address)=?`, mac).
		Scan(&pendingID, &orgIDStr, &pendingName, &location)
	if err == nil && presentedKey == "" {
		orgID, _ := strconv.Atoi(orgIDStr)
		if orgID == 0 {
			_ = h.db.QueryRow("SELECT id FROM organizations WHERE id=? OR name=?", orgIDStr, orgIDStr).Scan(&orgID)
		}
		if orgID == 0 {
			return nil, fmt.Errorf("pending provisioning organization not found")
		}

		apiKey := "dev_sec_" + randomSecret(24)
		now := time.Now().UTC().Format(time.RFC3339)
		res, err := h.db.Exec(`INSERT INTO devices
			(organization_id, name, mac_address, api_key_hash, status, last_heartbeat, last_seen_at, created_at)
			VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`,
			orgID, strings.TrimSpace(p.DeviceName), mac, hashKey(apiKey), now, now, now)
		if err != nil {
			return nil, fmt.Errorf("provision device: %w", err)
		}
		deviceID, err := res.LastInsertId()
		if err != nil || deviceID == 0 {
			return nil, fmt.Errorf("provision device: missing device id")
		}
		if _, err := h.db.Exec("DELETE FROM pending_device_enrollments WHERE id=?", pendingID); err != nil {
			return nil, fmt.Errorf("complete pending provisioning: %w", err)
		}

		c.deviceID, c.orgID = int(deviceID), orgID
		c.devIDStr = fmt.Sprintf("dev_%d", deviceID)
		c.apiKey = apiKey
		c.helloStatus = "provisioned"
		h.registerConnection(c)

		h.BroadcastSSE(SSEEvent{
			Event: "device.provisioned", Status: "completed", OrgID: strconv.Itoa(orgID),
			DeviceID: c.devIDStr, DeviceName: p.DeviceName, MACAddress: mac,
			Message: "Device successfully bound and provisioned!",
		})

		ack, err := MarshalEnvelope(TypeHelloAck, requestID, "provisioned", HelloAckPayload{
			DeviceID: c.devIDStr, APIKey: apiKey, ProtocolVersion: ProtocolVersion, Message: "Device successfully bound and activated.",
		})
		if err != nil {
			return nil, err
		}
		c.awaitingHello = false
		return ack, nil
	}

	// 2. Existing device authentication. The stored API key is required.
	var deviceID, orgID int
	if err := h.db.QueryRow(`SELECT id, organization_id FROM devices
		WHERE UPPER(mac_address)=? AND api_key_hash=? AND status!='revoked'`, mac, hashKey(presentedKey)).Scan(&deviceID, &orgID); err != nil {
		return nil, fmt.Errorf("device authentication failed")
	}

	c.deviceID, c.orgID = deviceID, orgID
	c.devIDStr = fmt.Sprintf("dev_%d", deviceID)
	c.helloStatus = "authenticated"
	h.registerConnection(c)
	_, _ = h.db.Exec("UPDATE devices SET name=?,status='active',last_heartbeat=?,last_seen_at=? WHERE id=? AND organization_id=?", strings.TrimSpace(p.DeviceName), time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), deviceID, orgID)

	ack, err := MarshalEnvelope(TypeHelloAck, requestID, "authenticated", HelloAckPayload{
		DeviceID: c.devIDStr, ProtocolVersion: ProtocolVersion, Message: "Connected successfully.",
	})
	if err != nil {
		return nil, err
	}
	c.awaitingHello = false
	return ack, nil
}

func (h *Hub) registerConnection(c *client) {
	h.mu.Lock()
	old := h.conns[c.deviceID]
	h.conns[c.deviceID] = c
	h.mu.Unlock()
	if old != nil && old != c {
		_ = old.conn.Close()
	}
}

func (h *Hub) attach(deviceID, orgID int, conn *websocket.Conn, isNewProvision bool, devIDStr, apiKey string) {
	c := &client{
		hub: h, deviceID: deviceID, orgID: orgID, conn: conn, send: make(chan []byte, sendBuf),
		awaitingHello: true, helloStatus: "authenticated", apiKey: apiKey, devIDStr: devIDStr,
	}
	if isNewProvision {
		c.helloStatus = "provisioned"
	}
	h.registerConnection(c)
	go c.writePump()
	c.readPump()
}

func (h *Hub) drop(c *client) {
	h.mu.Lock()
	current, ok := h.conns[c.deviceID]
	h.mu.Unlock()

	if ok && current == c && c.deviceID > 0 {
		// Anything delivered but not ACKed is safe to replay after reconnect.
		// ACKed commands remain complete and are never duplicated.
		_, _ = h.db.Exec(`UPDATE device_commands
			SET status='pending', delivered_at=NULL
			WHERE organization_id=? AND device_id=? AND status='delivered'`, c.orgID, c.deviceID)
		_, _ = h.db.Exec("UPDATE devices SET status='offline' WHERE id=? AND organization_id=?", c.deviceID, c.orgID)
	}

	h.mu.Lock()
	if ok && current == c {
		if h.conns[c.deviceID] == c {
			delete(h.conns, c.deviceID)
		}
	}
	h.mu.Unlock()
}

func envTypeIsHello(data []byte) bool {
	var env Envelope
	if json.Unmarshal(data, &env) != nil {
		return false
	}
	return env.Type == TypeHello
}

func (c *client) readPump() {
	defer func() {
		c.hub.drop(c)
		c.conn.Close()
	}()
	c.conn.SetReadLimit(64 << 10)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		reply, err := c.hub.handle(c, data)
		if err != nil {
			reply, _ = marshalEnvelope(TypeError, "", ErrorPayload{Code: "bad_message", Message: err.Error()})
		}
		if len(reply) > 0 {
			if envTypeIsHello(data) {
				if c.deviceID > 0 && c.helloStatus != "" {
					c.stateMu.Lock()
					c.replayPending = true
					c.stateMu.Unlock()
				}
			}
			select {
			case c.send <- reply:
			default:
			}
		}
	}
}

func (c *client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
			c.stateMu.Lock()
			replay := c.replayPending
			if replay {
				c.replayPending = false
			}
			c.stateMu.Unlock()
			if replay {
				_ = c.hub.flushPending(c)
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = c.hub.db.Exec("UPDATE devices SET last_heartbeat=?,last_seen_at=? WHERE id=?", now, now, c.deviceID)
		}
	}
}

func (h *Hub) handle(c *client, data []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if c.awaitingHello {
		if env.Type != TypeHello {
			return nil, fmt.Errorf("first message must be hello")
		}
		var p HelloPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, fmt.Errorf("invalid hello payload: %w", err)
		}
		return h.bindHello(c, p, env.RequestID)
	}
	switch env.Type {
	case TypePing:
		return marshalEnvelope(TypePong, env.RequestID, nil)
	case TypePong:
		return nil, nil
	case TypeEnrollResult:
		return h.enrollResult(c, env)
	case TypeAttendance:
		return h.attendance(c, env)
	default:
		return marshalEnvelope(TypeError, env.RequestID, ErrorPayload{Code: "unknown_type", Message: "unsupported message type: " + env.Type})
	}
}

func (h *Hub) enrollResult(c *client, env Envelope) ([]byte, error) {
	var p EnrollResultPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, err
	}
	if p.UserID == "" {
		return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: false, Error: "user_id required"})
	}

	status := p.Status
	fp := "failed"
	switch status {
	case "success", "enrolled":
		fp = "enrolled"
		status = "enrolled"
	case "cancelled":
		fp = "not_enrolled"
	default:
		status = "failed"
		fp = "failed"
	}

	var userID int
	// Attempt lookup by uuid, or fallback to integer id if passed as string
	if err := h.db.QueryRow("SELECT id FROM users WHERE (uuid=? OR id=CAST(? AS INTEGER)) AND organization_id=?", p.UserID, p.UserID, c.orgID).Scan(&userID); err != nil {
		return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: false, Error: "unknown user_id"})
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = h.db.Exec("UPDATE users SET fingerprint_status=?,updated_at=? WHERE id=? AND organization_id=?", fp, now, userID, c.orgID)

	slotID := userID
	if p.FingerIndex > 0 {
		slotID = userID*10 + p.FingerIndex
	}

	_, _ = h.db.Exec(`INSERT INTO device_enrollments(organization_id,user_id,device_id,slot_id,status,enrolled_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(device_id,slot_id) DO UPDATE SET status=excluded.status, enrolled_at=excluded.enrolled_at, user_id=excluded.user_id`,
		c.orgID, userID, c.deviceID, slotID, status, now)

	if env.RequestID != "" {
		_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND id=CAST(? AS INTEGER)", now, c.orgID, c.deviceID, env.RequestID)
	}
	_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND status IN ('pending','delivered') AND command_type='enroll.start' AND payload_json LIKE ?", now, c.orgID, c.deviceID, "%"+p.UserID+"%")

	// Broadcast SSE event user.enrollment_updated to waiting browser UI
	h.BroadcastSSE(SSEEvent{
		Event:    "user.enrollment_updated",
		Status:   "completed",
		UserID:   p.UserID,
		DeviceID: fmt.Sprintf("dev_%d", c.deviceID),
	})

	return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: true, Status: fp})
}

func (h *Hub) attendance(c *client, env Envelope) ([]byte, error) {
	var p AttendancePayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, err
	}
	if p.EventID == "" || p.UserID == "" || p.Event == "" {
		return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: false, Error: "event_id, user_id and event required"})
	}
	if h.ingest == nil {
		return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: false, Error: "attendance ingest unavailable"})
	}
	id, status, err := h.ingest(c.orgID, c.deviceID, p.EventID, p.UserID, p.Event, p.Timestamp, p.Method)
	if err != nil {
		return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: false, Error: err.Error()})
	}
	return marshalEnvelope(TypeAck, env.RequestID, AckPayload{OK: true, ID: id, Status: status})
}

func (h *Hub) StartEnrollment(orgID, deviceID, userID int, userUUID string) (requestID string, delivered bool, err error) {
	return h.StartEnrollmentWithParams(orgID, deviceID, userID, userUUID, 1, 30)
}

func (h *Hub) StartEnrollmentWithParams(orgID, deviceID, userID int, userUUID string, fingerIndex, timeoutSeconds int) (requestID string, delivered bool, err error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	if fingerIndex <= 0 {
		fingerIndex = 1
	}

	payloadStruct := EnrollStartPayload{
		UserID:         userUUID,
		FingerIndex:    fingerIndex,
		TimeoutSeconds: timeoutSeconds,
	}
	payloadBytes, _ := json.Marshal(payloadStruct)

	r, err := h.db.Exec("INSERT INTO device_commands(organization_id,device_id,command_type,payload_json,status) VALUES(?,?,?,?,?)", orgID, deviceID, TypeEnrollStart, string(payloadBytes), "pending")
	if err != nil {
		return "", false, err
	}
	cmdID, _ := r.LastInsertId()
	requestID = strconv.FormatInt(cmdID, 10)
	now := time.Now().UTC().Format(time.RFC3339)

	_, _ = h.db.Exec("UPDATE users SET fingerprint_status='pending',updated_at=? WHERE id=? AND organization_id=?", now, userID, orgID)
	slotID := userID*10 + fingerIndex
	_, _ = h.db.Exec(`INSERT INTO device_enrollments(organization_id,user_id,device_id,slot_id,status)
		VALUES(?,?,?,?, 'pending')
		ON CONFLICT(device_id,slot_id) DO UPDATE SET status='pending', user_id=excluded.user_id, enrolled_at=NULL`,
		orgID, userID, deviceID, slotID)

	msg, err := MarshalEnvelope(TypeEnrollStart, requestID, "", payloadStruct)
	if err != nil {
		return requestID, false, err
	}
	_, _ = h.db.Exec("UPDATE device_commands SET status='delivered',delivered_at=? WHERE id=?", now, cmdID)
	delivered = h.send(deviceID, msg)
	if !delivered {
		_, _ = h.db.Exec("UPDATE device_commands SET status='pending',delivered_at=NULL WHERE id=?", cmdID)
	}
	return requestID, delivered, nil
}

func (h *Hub) send(deviceID int, msg []byte) bool {
	h.mu.RLock()
	c, ok := h.conns[deviceID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case c.send <- msg:
		return true
	default:
		return false
	}
}

func (h *Hub) flushPending(c *client) int {
	rows, err := h.db.Query("SELECT id,payload_json FROM device_commands WHERE organization_id=? AND device_id=? AND status='pending' AND command_type=? ORDER BY id", c.orgID, c.deviceID, TypeEnrollStart)
	if err != nil {
		return 0
	}
	
	type pendingCmd struct {
		id int64
		msg []byte
	}
	var cmds []pendingCmd

	for rows.Next() {
		var id int64
		var payload string
		if rows.Scan(&id, &payload) != nil {
			continue
		}
		var p EnrollStartPayload
		_ = json.Unmarshal([]byte(payload), &p)
		msg, err := MarshalEnvelope(TypeEnrollStart, strconv.FormatInt(id, 10), "", p)
		if err == nil {
			cmds = append(cmds, pendingCmd{id, msg})
		}
	}
	rows.Close()

	n := 0
	now := time.Now().UTC().Format(time.RFC3339)
	for _, cmd := range cmds {
		select {
		case c.send <- cmd.msg:
			_, _ = h.db.Exec("UPDATE device_commands SET status='delivered',delivered_at=? WHERE id=?", now, cmd.id)
			n++
		default:
		}
	}
	return n
}

func hashKey(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func randomSecret(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
