package ws

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type AttendFunc func(orgID, deviceID int, eventID, userUUID, event, timestamp, method string) (int64, string, error)

// Hub manages device state and SSE subscriptions. Devices communicate entirely
// over REST endpoints instead of persistent WebSocket connections.
type Hub struct {
	db      *sql.DB
	ingest  AttendFunc
	sseMu   sync.RWMutex
	sseSubs map[chan SSEEvent]bool
}

func NewHub(db *sql.DB, ingest AttendFunc) *Hub {
	return &Hub{
		db:      db,
		ingest:  ingest,
		sseSubs: map[chan SSEEvent]bool{},
	}
}

// ---------------------------------------------------------------------------
// SSE (Server-Sent Events) — unchanged, used by the browser dashboard
// ---------------------------------------------------------------------------

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
				// Write each event exactly once: gin's c.Stream re-invokes its
				// step function until it returns false, replaying forever.
				if _, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", evt.Event, string(data)); err != nil {
					return
				}
				c.Writer.Flush()
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Device connectivity — now based on heartbeat timestamps instead of WS conns
// ---------------------------------------------------------------------------

const heartbeatTimeout = 90 * time.Second

// Connected returns true if the device sent a heartbeat within the last 90s.
func (h *Hub) Connected(deviceID int) bool {
	var lastHeartbeat sql.NullString
	if err := h.db.QueryRow("SELECT last_heartbeat FROM devices WHERE id=? AND status NOT IN ('revoked','offline')", deviceID).Scan(&lastHeartbeat); err != nil {
		return false
	}
	if !lastHeartbeat.Valid || lastHeartbeat.String == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastHeartbeat.String)
	if err != nil {
		return false
	}
	return time.Since(t) < heartbeatTimeout
}

// ConnectedIDs returns the IDs of devices in an organization that have a recent heartbeat.
func (h *Hub) ConnectedIDs(orgID int) map[int]bool {
	cutoff := time.Now().UTC().Add(-heartbeatTimeout).Format(time.RFC3339)
	rows, err := h.db.Query("SELECT id FROM devices WHERE organization_id=? AND status NOT IN ('revoked','offline') AND last_heartbeat > ?", orgID, cutoff)
	if err != nil {
		return map[int]bool{}
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// REST Device Handshake — replaces WebSocket hello / hello.ack
// ---------------------------------------------------------------------------

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

// workSchedule returns the organization's clock-in/clock-out times so the
// terminal can render schedule info and make local decisions without a
// round-trip. Defaults mirror the settings page.
func (h *Hub) workSchedule(orgID int) gin.H {
	start, end := "08:00", "17:00"
	late := 15
	var hours string
	var threshold int
	if h.db.QueryRow("SELECT working_hours,late_threshold_minutes FROM attendance_rules WHERE organization_id=?", orgID).Scan(&hours, &threshold) == nil {
		var parsed struct {
			Start string `json:"start"`
			End   string `json:"end"`
		}
		if json.Unmarshal([]byte(hours), &parsed) == nil {
			if parsed.Start != "" {
				start = parsed.Start
			}
			if parsed.End != "" {
				end = parsed.End
			}
		}
		late = threshold
	}
	return gin.H{"clock_in": start, "clock_out": end, "late_threshold_minutes": late}
}

// HelloHandler handles POST /api/v1/devices/hello — the device handshake.
// New devices are auto-provisioned; returning devices are authenticated.
func (h *Hub) HelloHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var p HelloPayload
		if err := c.ShouldBindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "bad_request", Message: "invalid JSON: " + err.Error()}})
			return
		}

		mac, ok := normalizeMAC(p.MACAddress)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "bad_mac", Message: "valid mac_address is required"}})
			return
		}
		if p.DeviceName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "bad_name", Message: "device_name is required"}})
			return
		}
		if p.ProtocolVersion != ProtocolVersion {
			c.JSON(http.StatusBadRequest, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "bad_version", Message: fmt.Sprintf("unsupported protocol version: %d", p.ProtocolVersion)}})
			return
		}

		presentedKey := strings.TrimSpace(p.APIKey)
		if presentedKey == "" {
			presentedKey = strings.TrimSpace(c.GetHeader("X-Device-Key"))
		}

		// 1. Automatic first-time provisioning: MAC must match a pending record.
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
				c.JSON(http.StatusUnprocessableEntity, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "org_not_found", Message: "pending provisioning organization not found"}})
				return
			}

			apiKey := "dev_sec_" + randomSecret(24)
			now := time.Now().UTC().Format(time.RFC3339)
			res, err := h.db.Exec(`INSERT INTO devices
				(organization_id, name, mac_address, api_key_hash, status, last_heartbeat, last_seen_at, created_at)
				VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`,
				orgID, strings.TrimSpace(p.DeviceName), mac, hashKey(apiKey), now, now, now)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "provision_failed", Message: "provision device: " + err.Error()}})
				return
			}
			deviceID, err := res.LastInsertId()
			if err != nil || deviceID == 0 {
				c.JSON(http.StatusInternalServerError, gin.H{"type": TypeError, "payload": ErrorPayload{Code: "provision_failed", Message: "provision device: missing device id"}})
				return
			}
			if _, err := h.db.Exec("DELETE FROM pending_device_enrollments WHERE id=?", pendingID); err != nil {
				log.Printf("warning: failed to delete pending enrollment %s: %v", pendingID, err)
			}

			devIDStr := fmt.Sprintf("dev_%d", deviceID)

			h.BroadcastSSE(SSEEvent{
				Event: "device.provisioned", Status: "completed", OrgID: strconv.Itoa(orgID),
				DeviceID: devIDStr, DeviceName: p.DeviceName, MACAddress: mac,
				Message: "Device successfully bound and provisioned!",
			})

			c.JSON(http.StatusCreated, gin.H{
				"status":           "provisioned",
				"device_id":        devIDStr,
				"organization_id":  orgID,
				"device_name":      strings.TrimSpace(p.DeviceName),
				"mac_address":      mac,
				"api_key":          apiKey,
				"protocol_version": ProtocolVersion,
				"firmware_version": p.FirmwareVersion,
				"work_schedule":    h.workSchedule(orgID),
				"message":          "Store this API key securely. It is returned only during provisioning.",
			})
			return
		}

		// 2. Existing device authentication.
		if presentedKey == "" {
			var existing int
			if err := h.db.QueryRow("SELECT count(*) FROM devices WHERE UPPER(mac_address)=?", mac).Scan(&existing); err == nil && existing > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "device already provisioned; api_key required"})
				return
			}
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown device MAC; create a pending provisioning record first"})
			return
		}

		var deviceID, orgID int
		if err := h.db.QueryRow(`SELECT id, organization_id FROM devices
			WHERE UPPER(mac_address)=? AND api_key_hash=? AND status!='revoked'`, mac, hashKey(presentedKey)).Scan(&deviceID, &orgID); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "device authentication failed"})
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		_, _ = h.db.Exec("UPDATE devices SET name=?,status='active',last_heartbeat=?,last_seen_at=? WHERE id=? AND organization_id=?",
			strings.TrimSpace(p.DeviceName), now, now, deviceID, orgID)

		c.JSON(http.StatusOK, gin.H{
			"status":           "authenticated",
			"device_id":        fmt.Sprintf("dev_%d", deviceID),
			"organization_id":  orgID,
			"protocol_version": ProtocolVersion,
			"work_schedule":    h.workSchedule(orgID),
			"message":          "Connected successfully.",
		})
	}
}

// ---------------------------------------------------------------------------
// REST Enroll Result — replaces WebSocket enroll.result frame
// ---------------------------------------------------------------------------

// EnrollResultHandler handles POST /api/v1/devices/:id/enrollment/result
func (h *Hub) EnrollResultHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.MustGet("device_id").(int)
		orgID := c.MustGet("org_id").(int)

		var p EnrollResultPayload
		if err := c.ShouldBindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
		if p.UserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
			return
		}

		status := p.Status
		if p.Success != nil {
			if *p.Success {
				status = "enrolled"
			} else {
				status = "failed"
			}
		}
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
		if err := h.db.QueryRow("SELECT id FROM users WHERE (uuid=? OR id=CAST(? AS INTEGER)) AND organization_id=?", p.UserID, p.UserID, orgID).Scan(&userID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown user_id"})
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		_, _ = h.db.Exec("UPDATE users SET fingerprint_status=?,updated_at=? WHERE id=? AND organization_id=?", fp, now, userID, orgID)

		slotID := userID
		if p.FingerIndex > 0 {
			slotID = userID*10 + p.FingerIndex
		}

		_, _ = h.db.Exec(`INSERT INTO device_enrollments(organization_id,user_id,device_id,slot_id,status,enrolled_at)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(device_id,slot_id) DO UPDATE SET status=excluded.status, enrolled_at=excluded.enrolled_at, user_id=excluded.user_id`,
			orgID, userID, deviceID, slotID, status, now)

		// Ack the matching pending command: prefer explicit command_id, then
		// request_id, then fall back to the newest pending enroll.start for this user.
		if p.CommandID > 0 {
			_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND id=?", now, orgID, deviceID, p.CommandID)
		} else if p.RequestID != "" {
			_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND id=CAST(? AS INTEGER)", now, orgID, deviceID, p.RequestID)
		}
		_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND status IN ('pending','delivered') AND command_type='enroll.start' AND payload_json LIKE ?", now, orgID, deviceID, "%"+p.UserID+"%")

		// Broadcast SSE event. Status carries the real outcome so pages
		// don't show "enrolled" for failed/cancelled attempts.
		h.BroadcastSSE(SSEEvent{
			Event:    "user.enrollment_updated",
			Status:   fp,
			UserID:   p.UserID,
			DeviceID: fmt.Sprintf("dev_%d", deviceID),
		})

		c.JSON(http.StatusOK, AckPayload{OK: true, Status: fp})
	}
}

// ---------------------------------------------------------------------------
// Enrollment start — queues a command for the device to poll
// ---------------------------------------------------------------------------

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

	// The device correlates its enrollment result with this command via request_id.
	payloadBytes, _ = json.Marshal(EnrollStartPayload{
		RequestID:      requestID,
		UserID:         userUUID,
		FingerIndex:    fingerIndex,
		TimeoutSeconds: timeoutSeconds,
	})
	_, _ = h.db.Exec("UPDATE device_commands SET payload_json=? WHERE id=?", string(payloadBytes), cmdID)
	now := time.Now().UTC().Format(time.RFC3339)

	_, _ = h.db.Exec("UPDATE users SET fingerprint_status='pending',updated_at=? WHERE id=? AND organization_id=?", now, userID, orgID)
	slotID := userID*10 + fingerIndex
	_, _ = h.db.Exec(`INSERT INTO device_enrollments(organization_id,user_id,device_id,slot_id,status)
		VALUES(?,?,?,?, 'pending')
		ON CONFLICT(device_id,slot_id) DO UPDATE SET status='pending', user_id=excluded.user_id, enrolled_at=NULL`,
		orgID, userID, deviceID, slotID)

	// With REST polling, commands are always "pending" until the device fetches them.
	// The existing GET /api/v1/devices/:id/commands endpoint delivers them.
	// `delivered` is true when the device is known to be online (recent heartbeat).
	delivered = h.Connected(deviceID)
	return requestID, delivered, nil
}

// ---------------------------------------------------------------------------
// RFID card enrollment — same polling contract as fingerprint enrollment
// ---------------------------------------------------------------------------

// StartCardEnrollment queues a card.enroll command so the terminal can add the
// UID to its local roster. The card stays pending until the device confirms
// via the card result endpoint.
func (h *Hub) StartCardEnrollment(orgID, deviceID, cardID int, cardUID, userUUID string) (requestID string, delivered bool, err error) {
	payload, _ := json.Marshal(CardEnrollPayload{
		CardID:         cardID,
		CardUID:        cardUID,
		UserID:         userUUID,
		TimeoutSeconds: 30,
	})
	r, err := h.db.Exec("INSERT INTO device_commands(organization_id,device_id,command_type,payload_json,status) VALUES(?,?,?,?,?)", orgID, deviceID, TypeCardEnroll, string(payload), "pending")
	if err != nil {
		return "", false, err
	}
	cmdID, _ := r.LastInsertId()
	requestID = strconv.FormatInt(cmdID, 10)

	// The device correlates its card result with this command via request_id.
	payload, _ = json.Marshal(CardEnrollPayload{
		RequestID:      requestID,
		CardID:         cardID,
		CardUID:        cardUID,
		UserID:         userUUID,
		TimeoutSeconds: 30,
	})
	_, _ = h.db.Exec("UPDATE device_commands SET payload_json=? WHERE id=?", string(payload), cmdID)

	_, _ = h.db.Exec("UPDATE rfid_cards SET status='pending',personalization_status='pending' WHERE id=? AND organization_id=?", cardID, orgID)

	delivered = h.Connected(deviceID)
	return requestID, delivered, nil
}

func (h *Hub) lookupCard(orgID, cardID int, cardUID string) (id int, uid, userUUID string, err error) {
	const cols = `SELECT r.id, r.uid, COALESCE(u.uuid,'') FROM rfid_cards r LEFT JOIN users u ON u.id=r.user_id`
	if cardID > 0 {
		err = h.db.QueryRow(cols+" WHERE r.id=? AND r.organization_id=?", cardID, orgID).Scan(&id, &uid, &userUUID)
		return
	}
	err = h.db.QueryRow(cols+" WHERE r.organization_id=? AND (r.uid=? OR UPPER(r.uid)=UPPER(?)) ORDER BY r.id LIMIT 1", orgID, cardUID, cardUID).Scan(&id, &uid, &userUUID)
	return
}

// CardResultHandler handles POST /api/v1/devices/:id/card/result — the
// terminal's report that it accepted (or rejected) an RFID card UID. On
// success the card is bound to the reporting device.
func (h *Hub) CardResultHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.MustGet("device_id").(int)
		orgID := c.MustGet("org_id").(int)

		var p CardResultPayload
		if err := c.ShouldBindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}

		status := strings.ToLower(strings.TrimSpace(p.Status))
		if p.Success != nil {
			if *p.Success {
				status = "issued"
			} else {
				status = "failed"
			}
		}
		var cardStatus, personalization string
		switch status {
		case "success", "issued", "confirmed", "linked":
			cardStatus, personalization = "issued", "personalized"
		case "cancelled", "canceled":
			cardStatus, personalization = "cancelled", "pending"
		default:
			cardStatus, personalization = "failed", "failed"
		}

		// Identify the card by id, UID, or by the command it is answering.
		p.CardUID = strings.TrimSpace(p.CardUID)
		if p.CardID == 0 && p.CardUID == "" && p.RequestID != "" {
			var payloadJSON string
			if h.db.QueryRow("SELECT payload_json FROM device_commands WHERE organization_id=? AND device_id=? AND command_type=? AND id=CAST(? AS INTEGER)",
				orgID, deviceID, TypeCardEnroll, p.RequestID).Scan(&payloadJSON) == nil {
				var cp CardEnrollPayload
				if json.Unmarshal([]byte(payloadJSON), &cp) == nil {
					p.CardID, p.CardUID = cp.CardID, cp.CardUID
				}
			}
		}
		if p.CardID == 0 && p.CardUID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "card_id, card_uid or request_id required"})
			return
		}
		cardID, cardUID, userUUID, err := h.lookupCard(orgID, p.CardID, p.CardUID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown card"})
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		if cardStatus == "issued" {
			_, _ = h.db.Exec("UPDATE rfid_cards SET status=?,personalization_status=?,device_id=? WHERE id=? AND organization_id=?",
				cardStatus, personalization, deviceID, cardID, orgID)
		} else {
			_, _ = h.db.Exec("UPDATE rfid_cards SET status=?,personalization_status=? WHERE id=? AND organization_id=?",
				cardStatus, personalization, cardID, orgID)
		}

		// Ack the matching pending command: prefer explicit command_id, then
		// request_id, then fall back to the pending card.enroll for this card.
		if p.CommandID > 0 {
			_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND id=?", now, orgID, deviceID, p.CommandID)
		} else if p.RequestID != "" {
			_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND id=CAST(? AS INTEGER)", now, orgID, deviceID, p.RequestID)
		}
		_, _ = h.db.Exec("UPDATE device_commands SET status='acked',acked_at=? WHERE organization_id=? AND device_id=? AND status IN ('pending','delivered') AND command_type=? AND payload_json LIKE ?",
			now, orgID, deviceID, TypeCardEnroll, fmt.Sprintf("%%\"card_id\":%d%%", cardID))

		h.BroadcastSSE(SSEEvent{
			Event:    "card.enrollment_updated",
			Status:   cardStatus,
			CardUID:  cardUID,
			UserID:   userUUID,
			DeviceID: fmt.Sprintf("dev_%d", deviceID),
		})

		c.JSON(http.StatusOK, AckPayload{OK: true, Status: cardStatus})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// User roster sync — fan a user change out to every org terminal
// ---------------------------------------------------------------------------

// queueUserCommand inserts one command row per non-revoked device in the org.
// Offline devices keep the row pending and pick it up on their next poll, so
// roster changes converge even when a terminal is down at the time.
func (h *Hub) queueUserCommand(orgID int, commandType string, build func(requestID string) any) (int, error) {
	rows, err := h.db.Query("SELECT id FROM devices WHERE organization_id=? AND status!='revoked'", orgID)
	if err != nil {
		return 0, err
	}
	deviceIDs := []int{}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			deviceIDs = append(deviceIDs, id)
		}
	}
	rows.Close()
	queued := 0
	for _, deviceID := range deviceIDs {
		r, err := h.db.Exec("INSERT INTO device_commands(organization_id,device_id,command_type,payload_json,status) VALUES(?,?,?,?,?)",
			orgID, deviceID, commandType, "{}", "pending")
		if err != nil {
			continue
		}
		cmdID, _ := r.LastInsertId()
		requestID := strconv.FormatInt(cmdID, 10)
		payload, _ := json.Marshal(build(requestID))
		_, _ = h.db.Exec("UPDATE device_commands SET payload_json=? WHERE id=?", string(payload), cmdID)
		queued++
	}
	return queued, nil
}

// QueueUserUpdate broadcasts a user's authoritative record (name, phone,
// role, status, bound card UIDs) to all terminals.
func (h *Hub) QueueUserUpdate(orgID, userID int, userUUID string) (int, error) {
	if userUUID == "" {
		return 0, nil
	}
	var fullName, phone, role, status string
	if err := h.db.QueryRow("SELECT full_name,phone,role,status FROM users WHERE id=? AND organization_id=?", userID, orgID).Scan(&fullName, &phone, &role, &status); err != nil {
		return 0, err
	}
	cards := []string{}
	crows, err := h.db.Query("SELECT uid FROM rfid_cards WHERE organization_id=? AND user_id=? AND status='issued'", orgID, userID)
	if err == nil {
		for crows.Next() {
			var uid string
			if crows.Scan(&uid) == nil {
				cards = append(cards, uid)
			}
		}
		crows.Close()
	}
	return h.queueUserCommand(orgID, TypeUserUpdate, func(requestID string) any {
		return UserUpdatePayload{RequestID: requestID, UserID: userUUID, FullName: fullName, Phone: phone, Role: role, Status: status, CardUIDs: cards}
	})
}

// QueueUserDelete broadcasts removal of a user from all terminal rosters.
func (h *Hub) QueueUserDelete(orgID int, userUUID string) (int, error) {
	if userUUID == "" {
		return 0, nil
	}
	return h.queueUserCommand(orgID, TypeUserDelete, func(requestID string) any {
		return UserDeletePayload{RequestID: requestID, UserID: userUUID}
	})
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
