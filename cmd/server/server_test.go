package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	appdb "github.com/sparklabafrica/verunum/internal/db"
	"github.com/sparklabafrica/verunum/internal/ws"
)

func setupTestServer(t *testing.T) (*gin.Engine, *app, string) {
	gin.SetMode(gin.TestMode)
	databasePath := filepath.Join(t.TempDir(), "verunum-test.db")
	database, err := appdb.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	a := &app{db: database, secret: []byte("test-secret")}
	a.hub = ws.NewHub(database, a.insertEventByUUID)
	if err := a.seed(); err != nil {
		t.Fatal(err)
	}
	// Keep the test fixture deterministic even if the schema defaults change.
	if _, err := database.Exec("UPDATE users SET must_change_password=0 WHERE email=?", "admin@demo.local"); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.LoadHTMLGlob(filepath.Join("..", "..", "web", "templates", "*"))

	api := r.Group("/api/v1")
	api.POST("/devices/hello", a.hub.HelloHandler())
	api.GET("/events", a.hub.SSEHandler())
	adminAPI := api.Group("", a.adminAuth())
	adminAPI.POST("/platform/devices/pending", a.registerPendingDevice)
	adminAPI.POST("/devices/:id/enroll-request", a.enrollRequest)

	page := r.Group("", a.adminAuth())
	page.GET("/rfid-cards/new", a.newCardPage)
	page.POST("/rfid-cards", a.createCard)
	page.GET("/users", a.usersPage)
	page.POST("/users", a.createUser)
	page.GET("/users/:id/status", a.userStatus)
	page.GET("/roles", a.rolesPage)
	page.POST("/roles", a.createRole)
	page.POST("/roles/:id/delete", a.deleteRole)
	page.GET("/settings", a.settingsPage)
	page.POST("/settings", a.updateSettings)

	device := api.Group("/devices/:id", a.deviceAuth())
	device.POST("/heartbeat", a.heartbeat)
	device.GET("/commands", a.commands)
	device.POST("/commands/:cmdId/ack", a.ackCommand)
	device.POST("/enrollment/result", a.hub.EnrollResultHandler())
	device.POST("/card/result", a.hub.CardResultHandler())
	device.POST("/attendance", a.ingestAttendance)
	device.POST("/attendance/batch", a.ingestBatch)

	var adminUserID, adminOrgID int
	if err := a.db.QueryRow("SELECT id, organization_id FROM users WHERE email=?", "admin@demo.local").Scan(&adminUserID, &adminOrgID); err != nil {
		t.Fatal(err)
	}
	token := a.token(claims{UserID: adminUserID, OrgID: adminOrgID, Role: "super_admin", Expires: time.Now().Add(time.Hour).Unix()})
	return r, a, token
}

func jsonRequest(t *testing.T, r *gin.Engine, method, path, token, deviceKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if deviceKey != "" {
		req.Header.Set("X-Device-Key", deviceKey)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPendingDeviceAndAutoProvisioningFlow(t *testing.T) {
	r, a, token := setupTestServer(t)

	// 1. Admin submits a pending device provisioning record.
	w := jsonRequest(t, r, "POST", "/api/v1/platform/devices/pending", token, "", map[string]string{
		"org_id":      "1",
		"device_name": "Main Entrance Gate",
		"mac_address": "AA:BB:CC:DD:EE:FF",
		"location":    "Lobby",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for pending registration, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Unknown MAC is rejected with 404 before any pending record exists.
	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "11:22:33:44:55:66", "device_name": "Unknown", "protocol_version": 1,
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown MAC, got %d: %s", w.Code, w.Body.String())
	}

	// 3. TAB5 calls hello with the pending MAC and is auto-provisioned.
	sseCh := a.hub.SubscribeSSE()
	defer a.hub.UnsubscribeSSE(sseCh)

	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "AA:BB:CC:DD:EE:FF", "device_name": "Main Entrance Gate", "protocol_version": 1, "firmware_version": "1.0.0",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 provisioned, got %d: %s", w.Code, w.Body.String())
	}
	var ack map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack["status"] != "provisioned" || ack["mac_address"] != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("unexpected provisioning response: %v", ack)
	}
	apiKey, _ := ack["api_key"].(string)
	if !strings.HasPrefix(apiKey, "dev_sec_") {
		t.Fatalf("expected dev_sec_ API key, got %q", apiKey)
	}
	if ack["organization_id"].(float64) != 1 {
		t.Fatalf("expected organization_id 1, got %v", ack["organization_id"])
	}

	select {
	case evt := <-sseCh:
		if evt.Event != "device.provisioned" || evt.MACAddress != "AA:BB:CC:DD:EE:FF" {
			t.Fatalf("unexpected SSE event: %+v", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for device.provisioned SSE event")
	}

	// 4. Re-hello without a key is now a conflict (already provisioned).
	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "AA:BB:CC:DD:EE:FF", "device_name": "Main Entrance Gate", "protocol_version": 1,
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for already-provisioned MAC, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Authenticated hello with the stored key succeeds.
	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "AA:BB:CC:DD:EE:FF", "device_name": "Main Entrance Gate", "protocol_version": 1, "api_key": apiKey,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 authenticated hello, got %d: %s", w.Code, w.Body.String())
	}

	var devID int
	if err := a.db.QueryRow("SELECT id FROM devices WHERE mac_address='AA:BB:CC:DD:EE:FF'").Scan(&devID); err != nil {
		t.Fatal(err)
	}
	devPath := fmt.Sprintf("/api/v1/devices/dev_%d", devID)

	// 6. Heartbeat keeps the device online; commands poll returns the enroll command.
	w = jsonRequest(t, r, "POST", devPath+"/heartbeat", "", apiKey, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 heartbeat, got %d: %s", w.Code, w.Body.String())
	}
	if !a.hub.Connected(devID) {
		t.Fatal("expected device online after hello/heartbeat")
	}

	// 7. Enrollment request requires admin auth and an online device.
	enrollBody := map[string]any{"user_id": "admin@demo.local", "finger_index": 1, "timeout_seconds": 30}
	w = jsonRequest(t, r, "POST", devPath+"/enroll-request", "", "", enrollBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated enroll-request, got %d", w.Code)
	}
	w = jsonRequest(t, r, "POST", devPath+"/enroll-request", token, "", enrollBody)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 enroll-request, got %d: %s", w.Code, w.Body.String())
	}
	var enrollResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &enrollResp)
	requestID, _ := enrollResp["request_id"].(string)
	if requestID == "" {
		t.Fatalf("expected request_id in enroll-request response: %v", enrollResp)
	}

	w = jsonRequest(t, r, "GET", devPath+"/commands", "", apiKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 command poll, got %d: %s", w.Code, w.Body.String())
	}
	var poll struct {
		Commands []struct {
			ID          int    `json:"id"`
			CommandType string `json:"command_type"`
			Payload     struct {
				RequestID   string `json:"request_id"`
				UserID      string `json:"user_id"`
				FingerIndex int    `json:"finger_index"`
			} `json:"payload"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &poll); err != nil {
		t.Fatal(err)
	}
	if len(poll.Commands) != 1 || poll.Commands[0].CommandType != "enroll.start" {
		t.Fatalf("expected one enroll.start command, got %s", w.Body.String())
	}
	cmd := poll.Commands[0]
	if cmd.Payload.RequestID != requestID {
		t.Fatalf("command payload request_id %q does not match enroll-request %q", cmd.Payload.RequestID, requestID)
	}

	// 8. Device reports the enrollment result; the command is acknowledged.
	var adminUUID string
	_ = a.db.QueryRow("SELECT uuid FROM users WHERE email='admin@demo.local'").Scan(&adminUUID)
	w = jsonRequest(t, r, "POST", devPath+"/enrollment/result", "", apiKey, map[string]any{
		"command_id": cmd.ID, "request_id": requestID, "user_id": adminUUID, "finger_index": 1, "success": true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 enrollment result, got %d: %s", w.Code, w.Body.String())
	}
	var fpStatus, cmdStatus string
	_ = a.db.QueryRow("SELECT fingerprint_status FROM users WHERE email='admin@demo.local'").Scan(&fpStatus)
	if fpStatus != "enrolled" {
		t.Fatalf("expected fingerprint_status enrolled, got %q", fpStatus)
	}
	_ = a.db.QueryRow("SELECT status FROM device_commands WHERE id=?", cmd.ID).Scan(&cmdStatus)
	if cmdStatus != "acked" {
		t.Fatalf("expected command acked, got %q", cmdStatus)
	}

	// 9. Attendance ingest is idempotent on event_id.
	attBody := map[string]any{"user_id": 1, "event_id": "evt-unique-001", "event": "clock_in", "timestamp": time.Now().UTC().Format(time.RFC3339), "method": "fingerprint"}
	w = jsonRequest(t, r, "POST", devPath+"/attendance", "", apiKey, attBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 attendance, got %d: %s", w.Code, w.Body.String())
	}
	var attResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &attResp)
	firstID := attResp["id"]

	w = jsonRequest(t, r, "POST", devPath+"/attendance", "", apiKey, attBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 on retry, got %d: %s", w.Code, w.Body.String())
	}
	var retryResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &retryResp)
	if retryResp["id"] != firstID {
		t.Fatalf("expected duplicate event_id to return original id %v, got %v", firstID, retryResp["id"])
	}

	// 10. Batch sync of queued offline events.
	w = jsonRequest(t, r, "POST", devPath+"/attendance/batch", "", apiKey, []map[string]any{
		{"user_id": 1, "event_id": "evt-batch-001", "event": "clock_out", "timestamp": time.Now().UTC().Format(time.RFC3339), "method": "fingerprint"},
		{"user_id": 1, "event_id": "evt-batch-001", "event": "clock_out", "timestamp": time.Now().UTC().Format(time.RFC3339), "method": "fingerprint"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 batch, got %d: %s", w.Code, w.Body.String())
	}
	var batchResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &batchResp)
	if batchResp["created"].(float64) != 1 || batchResp["deduplicated"].(float64) != 1 {
		t.Fatalf("expected 1 created + 1 deduplicated, got %v", batchResp)
	}

	// 10b. Mixed batch mirroring real device traffic: garbage events (empty
	// user_id/event, unknown user) are skipped per-event instead of failing
	// the batch; numeric-string and UUID user_ids are accepted. Fixed
	// timestamps keep the events clear of the same-second UNIQUE key that the
	// now-based events above may share.
	w = jsonRequest(t, r, "POST", devPath+"/attendance/batch", "", apiKey, []map[string]any{
		{"user_id": "", "event_id": "00052B03-A6DC2463-4C12E612", "event": "", "timestamp": "2026-09-11 01:55:25", "method": "fingerprint"},
		{"user_id": "not-a-user", "event_id": "evt-garbage-1", "event": "clock_in", "timestamp": "2026-09-11T02:00:00Z"},
		{"user_id": "1", "event_id": "evt-str-001", "event": "clock_in", "timestamp": "2026-09-11T02:05:00Z"},
		{"user_id": adminUUID, "event_id": "evt-uuid-001", "event": "clock_out", "timestamp": "2026-09-11T02:35:00Z"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 mixed batch, got %d: %s", w.Code, w.Body.String())
	}
	var mixedResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &mixedResp)
	if mixedResp["created"].(float64) != 2 {
		t.Fatalf("expected 2 created in mixed batch, got %v", mixedResp)
	}

	// 11. Requests with a wrong device key are rejected.
	w = jsonRequest(t, r, "GET", devPath+"/commands", "", "wrong-key", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong device key, got %d", w.Code)
	}

	// 12. Enrollment request against an offline device returns 422.
	w = jsonRequest(t, r, "POST", "/api/v1/devices/9999/enroll-request", token, "", enrollBody)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for offline device, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHelloValidation(t *testing.T) {
	r, _, _ := setupTestServer(t)

	w := jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"device_name": "Missing MAC", "protocol_version": 1,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing MAC, got %d: %s", w.Code, w.Body.String())
	}

	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "not-a-mac", "device_name": "Bad MAC", "protocol_version": 1,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid MAC, got %d: %s", w.Code, w.Body.String())
	}

	w = jsonRequest(t, r, "POST", "/api/v1/devices/hello", "", "", map[string]any{
		"mac_address": "AA:BB:CC:DD:EE:FF", "device_name": "Bad Version", "protocol_version": 99,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported protocol version, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateCardQueuesDeviceSync(t *testing.T) {
	r, a, token := setupTestServer(t)

	var orgID, userID int
	var userUUID string
	if err := a.db.QueryRow("SELECT id, organization_id, uuid FROM users WHERE email='admin@demo.local'").Scan(&userID, &orgID, &userUUID); err != nil {
		t.Fatal(err)
	}
	devRes, err := a.db.Exec("INSERT INTO devices(organization_id,name,mac_address,api_key_hash,status,last_heartbeat) VALUES(?,?,?,?, 'active', ?)",
		orgID, "Main Gate", "AA:AA:AA:AA:AA:AA", hash("dev-secret"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	deviceID, _ := devRes.LastInsertId()

	// 1. A card aimed at the online terminal is registered as pending and a
	//    card.enroll command is queued for it.
	w := jsonRequest(t, r, "POST", "/rfid-cards", token, "", map[string]any{
		"uid": "04A2B3C4", "user_id": userID, "device_id": deviceID,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["status"] != "pending" || created["request_id"] == "" || created["delivered"] != true {
		t.Fatalf("expected pending card with delivered request_id, got %v", created)
	}
	var cardStatus, cmdType, cmdPayload string
	if err := a.db.QueryRow("SELECT status FROM rfid_cards WHERE uid='04A2B3C4'").Scan(&cardStatus); err != nil || cardStatus != "pending" {
		t.Fatalf("card status %q err=%v", cardStatus, err)
	}
	if err := a.db.QueryRow("SELECT command_type,payload_json FROM device_commands WHERE device_id=? AND status='pending'", deviceID).Scan(&cmdType, &cmdPayload); err != nil || cmdType != "card.enroll" {
		t.Fatalf("expected queued card.enroll command, got %q err=%v", cmdType, err)
	}
	if !strings.Contains(cmdPayload, "04A2B3C4") || !strings.Contains(cmdPayload, userUUID) {
		t.Fatalf("command payload missing card/user identifiers: %s", cmdPayload)
	}

	// 2. The terminal's next command poll delivers card.enroll in the array so
	//    firmware knows to scan a card now.
	w = jsonRequest(t, r, "GET", fmt.Sprintf("/api/v1/devices/%d/commands", deviceID), "", "dev-secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from command poll, got %d: %s", w.Code, w.Body.String())
	}
	var poll struct {
		Commands []struct {
			ID          int             `json:"id"`
			CommandType string          `json:"command_type"`
			Payload     json.RawMessage `json:"payload"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &poll); err != nil {
		t.Fatal(err)
	}
	if len(poll.Commands) != 1 || poll.Commands[0].CommandType != "card.enroll" {
		t.Fatalf("expected poll to deliver card.enroll, got %s", w.Body.String())
	}
	var polled struct {
		RequestID string `json:"request_id"`
		CardID    int    `json:"card_id"`
		CardUID   string `json:"card_uid"`
		UserID    string `json:"user_id"`
	}
	if err := json.Unmarshal(poll.Commands[0].Payload, &polled); err != nil {
		t.Fatal(err)
	}
	if polled.RequestID != strconv.Itoa(poll.Commands[0].ID) || polled.CardID == 0 || polled.CardUID != "04A2B3C4" || polled.UserID != userUUID {
		t.Fatalf("unexpected card.enroll payload: %s", poll.Commands[0].Payload)
	}

	// 3. The terminal reports the UID it accepted — the card is issued and
	//    bound to that terminal, and the command is acknowledged.
	w = jsonRequest(t, r, "POST", fmt.Sprintf("/api/v1/devices/%d/card/result", deviceID), "", "dev-secret", map[string]any{
		"card_uid": "04A2B3C4", "success": true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from card result, got %d: %s", w.Code, w.Body.String())
	}
	var boundDevice, pendingCmds int
	if err := a.db.QueryRow("SELECT coalesce(device_id,0) FROM rfid_cards WHERE uid='04A2B3C4'").Scan(&boundDevice); err != nil || boundDevice != int(deviceID) {
		t.Fatalf("expected card bound to device %d, got %d err=%v", deviceID, boundDevice, err)
	}
	if err := a.db.QueryRow("SELECT count(*) FROM device_commands WHERE status='pending'").Scan(&pendingCmds); err != nil || pendingCmds != 0 {
		t.Fatalf("expected no pending commands after ack, got %d err=%v", pendingCmds, err)
	}

	// 4. A card with no terminal target is issued immediately — no command.
	w = jsonRequest(t, r, "POST", "/rfid-cards", token, "", map[string]any{"uid": "STOCK-001"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var issued string
	if err := a.db.QueryRow("SELECT status FROM rfid_cards WHERE uid='STOCK-001'").Scan(&issued); err != nil || issued != "issued" {
		t.Fatalf("expected issued card without terminal, got %q err=%v", issued, err)
	}
	var cmdCount int
	if err := a.db.QueryRow("SELECT count(*) FROM device_commands").Scan(&cmdCount); err != nil || cmdCount != 1 {
		t.Fatalf("expected exactly one queued command overall, got %d err=%v", cmdCount, err)
	}
}

func TestReissueExistingCardUID(t *testing.T) {
	r, a, token := setupTestServer(t)

	var orgID, userID int
	if err := a.db.QueryRow("SELECT id, organization_id FROM users WHERE email='admin@demo.local'").Scan(&userID, &orgID); err != nil {
		t.Fatal(err)
	}
	res, err := a.db.Exec("INSERT INTO users(organization_id,uuid,full_name,role,status) VALUES(?,?,?,?,?)",
		orgID, "00000000-0000-4000-8000-00000000abcd", "Ama Mensah", "staff", "active")
	if err != nil {
		t.Fatal(err)
	}
	otherID, _ := res.LastInsertId()

	// 1. Register a card without a terminal — issued immediately.
	w := jsonRequest(t, r, "POST", "/rfid-cards", token, "", map[string]any{"uid": "STOCK-777", "user_id": userID})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Re-issuing the same UID (different casing) retargets the stored row
	//    instead of failing on the unique constraint.
	w = jsonRequest(t, r, "POST", "/rfid-cards", token, "", map[string]any{"uid": "stock-777", "user_id": otherID})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 on reissue, got %d: %s", w.Code, w.Body.String())
	}
	var count, holder int
	if err := a.db.QueryRow("SELECT count(*), coalesce(max(user_id),0) FROM rfid_cards WHERE organization_id=? AND upper(uid)='STOCK-777'", orgID).Scan(&count, &holder); err != nil || count != 1 || holder != int(otherID) {
		t.Fatalf("expected one card handed to %d, got count=%d holder=%d err=%v", otherID, count, holder, err)
	}

	// 3. Re-issuing unassigned releases the holder.
	w = jsonRequest(t, r, "POST", "/rfid-cards", token, "", map[string]any{"uid": "STOCK-777"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 releasing the card, got %d: %s", w.Code, w.Body.String())
	}
	var released sql.NullInt64
	if err := a.db.QueryRow("SELECT user_id FROM rfid_cards WHERE upper(uid)='STOCK-777'").Scan(&released); err != nil || released.Valid {
		t.Fatalf("expected NULL holder after release, got %v err=%v", released, err)
	}

	// 4. A browser form post with no UID comes back to the form with a banner —
	//    not a JSON blob, and never the raw driver error.
	form := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/rfid-cards", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	w = form("uid=&user_id=")
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/rfid-cards/new?error=uid_required" {
		t.Fatalf("unexpected redirect: %s", loc)
	}
	if strings.Contains(w.Body.String(), "constraint failed") {
		t.Fatalf("driver error leaked to the page: %s", w.Body.String())
	}

	// 5. A person from outside the organisation is rejected before the insert.
	w = form("uid=STOCK-999&user_id=99999")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=person_not_found") {
		t.Fatalf("expected person_not_found redirect, got %d %s", w.Code, loc)
	}

	// 6. The form renders the banner and keeps the UID the operator typed.
	req := httptest.NewRequest("GET", "/rfid-cards/new?error=uid_required&uid=STOCK-999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Enter the card UID") {
		t.Fatalf("expected the form to render the error banner, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `value="STOCK-999"`) {
		t.Fatalf("expected the form to preserve the submitted UID")
	}
}

func TestOrgRoleManagement(t *testing.T) {
	r, a, _ := setupTestServer(t)

	var adminUserID, orgID int
	if err := a.db.QueryRow("SELECT id, organization_id FROM users WHERE email='admin@demo.local'").Scan(&adminUserID, &orgID); err != nil {
		t.Fatal(err)
	}
	token := a.token(claims{UserID: adminUserID, OrgID: orgID, Role: "org_admin", Expires: time.Now().Add(time.Hour).Unix()})

	// 1. An org admin adds a custom role; the slug is derived from the name.
	w := jsonRequest(t, r, "POST", "/roles", token, "", map[string]any{"name": "Gate Marshall"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["slug"] != "gate_marshall" {
		t.Fatalf("expected slug gate_marshall, got %v", created["slug"])
	}
	roleID := int(created["id"].(float64))

	// 2. The same role (any casing/spacing) is rejected as a duplicate.
	w = jsonRequest(t, r, "POST", "/roles", token, "", map[string]any{"name": "gate  marshall"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate role, got %d: %s", w.Code, w.Body.String())
	}

	// 3. The new role can be assigned to a person.
	w = jsonRequest(t, r, "POST", "/users", token, "", map[string]any{"full_name": "Kofi Boateng", "role": "gate_marshall"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	// 4. The people page renders the friendly label and the RFID column.
	req := httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	htmlRec := httptest.NewRecorder()
	r.ServeHTTP(htmlRec, req)
	if htmlRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /users, got %d", htmlRec.Code)
	}
	body := htmlRec.Body.String()
	if !strings.Contains(body, "Gate Marshall") {
		t.Fatalf("expected /users to render the role label, got: %s", body[:min(len(body), 400)])
	}
	if !strings.Contains(body, "RFID card") || !strings.Contains(body, "card-pill") {
		t.Fatalf("expected /users to render the RFID card column")
	}

	// 4b. The roles page lists the custom role.
	req = httptest.NewRequest("GET", "/roles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	htmlRec = httptest.NewRecorder()
	r.ServeHTTP(htmlRec, req)
	if htmlRec.Code != http.StatusOK || !strings.Contains(htmlRec.Body.String(), "Gate Marshall") {
		t.Fatalf("expected /roles to render the custom role, got %d", htmlRec.Code)
	}

	// 5. A role still assigned to people cannot be deleted.
	w = jsonRequest(t, r, "POST", fmt.Sprintf("/roles/%d/delete", roleID), token, "", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 deleting an in-use role, got %d: %s", w.Code, w.Body.String())
	}

	// 6. An unused role deletes cleanly.
	w = jsonRequest(t, r, "POST", "/roles", token, "", map[string]any{"name": "Temp Role"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var tmp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tmp); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(t, r, "POST", fmt.Sprintf("/roles/%d/delete", int(tmp["id"].(float64))), token, "", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 deleting an unused role, got %d: %s", w.Code, w.Body.String())
	}

	// 7. The person's status endpoint carries the card counts the table uses.
	w = jsonRequest(t, r, "GET", fmt.Sprintf("/users/%d/status", adminUserID), token, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if _, ok := status["cards"]; !ok {
		t.Fatalf("expected cards count in status, got %v", status)
	}
	if _, ok := status["pending_cards"]; !ok {
		t.Fatalf("expected pending_cards count in status, got %v", status)
	}
}

func TestWorkHoursSettings(t *testing.T) {
	r, a, token := setupTestServer(t)

	// 1. The page renders the seeded defaults.
	w := jsonRequest(t, r, "GET", "/settings", token, "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `value="08:00"`) || !strings.Contains(w.Body.String(), `value="17:00"`) {
		t.Fatalf("expected settings page with defaults, got %d: %s", w.Code, w.Body.String()[:min(len(w.Body.String()), 300)])
	}

	// 2. A JSON update persists into attendance_rules.
	w = jsonRequest(t, r, "POST", "/settings", token, "", map[string]any{"start": "09:30", "end": "16:45", "late_threshold_minutes": 10, "early_departure_minutes": 20})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 settings update, got %d: %s", w.Code, w.Body.String())
	}
	var orgID int
	if err := a.db.QueryRow("SELECT organization_id FROM users WHERE email='admin@demo.local'").Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	var hours string
	var late, early int
	if err := a.db.QueryRow("SELECT working_hours, late_threshold_minutes, early_departure_minutes FROM attendance_rules WHERE organization_id=?", orgID).Scan(&hours, &late, &early); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hours, `"start":"09:30"`) || !strings.Contains(hours, `"end":"16:45"`) || late != 10 || early != 20 {
		t.Fatalf("unexpected rules row %q late=%d early=%d", hours, late, early)
	}

	// 3. The page reflects the new values.
	w = jsonRequest(t, r, "GET", "/settings", token, "", nil)
	if !strings.Contains(w.Body.String(), `value="09:30"`) || !strings.Contains(w.Body.String(), `value="16:45"`) {
		t.Fatalf("expected updated values on settings page, got %s", w.Body.String()[:min(len(w.Body.String()), 300)])
	}

	// 4. Invalid times are rejected for both JSON and form posts.
	w = jsonRequest(t, r, "POST", "/settings", token, "", map[string]any{"start": "25:00", "end": "17:00"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid time, got %d: %s", w.Code, w.Body.String())
	}
	form := url.Values{"start": {"07:45"}, "end": {"not-a-time"}, "late_threshold_minutes": {"15"}, "early_departure_minutes": {"15"}}
	req := httptest.NewRequest("POST", "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=invalid") {
		t.Fatalf("expected redirect with error=invalid, got %d -> %s", rec.Code, rec.Header().Get("Location"))
	}

	// 5. A valid form post redirects with the saved banner.
	form = url.Values{"start": {"07:45"}, "end": {"17:15"}, "late_threshold_minutes": {"20"}, "early_departure_minutes": {"10"}}
	req = httptest.NewRequest("POST", "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "saved=1") {
		t.Fatalf("expected redirect with saved=1, got %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDuplicateClockEventPrevention(t *testing.T) {
	r, a, token := setupTestServer(t)
	var orgID, userID int
	if err := a.db.QueryRow("SELECT organization_id, id FROM users WHERE email='admin@demo.local'").Scan(&orgID, &userID); err != nil {
		t.Fatal(err)
	}
	res, err := a.db.Exec("INSERT INTO devices(organization_id,name,api_key_hash,status) VALUES(?,?,?,'online')", orgID, "Terminal A", hash("dup-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	deviceID, _ := res.LastInsertId()
	devPath := fmt.Sprintf("/api/v1/devices/%d", deviceID)

	today := time.Now().UTC()
	at := func(h, m int) string {
		return time.Date(today.Year(), today.Month(), today.Day(), h, m, 0, 0, time.UTC).Format(time.RFC3339)
	}
	event := func(eventID, eventType, ts string) map[string]any {
		return map[string]any{"user_id": userID, "event_id": eventID, "event": eventType, "timestamp": ts, "method": "fingerprint"}
	}
	post := func(body any) *httptest.ResponseRecorder {
		return jsonRequest(t, r, "POST", devPath+"/attendance", "", "dup-test-key", body)
	}

	// 1. First clock-in of the day is accepted.
	w := post(event("evt-dup-1", "clock_in", at(8, 0)))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 clock_in, got %d: %s", w.Code, w.Body.String())
	}
	// 2. A second clock-in without an intervening clock-out is a 409.
	w = post(event("evt-dup-2", "clock_in", at(8, 5)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "already clocked in") {
		t.Fatalf("expected 409 already clocked in, got %d: %s", w.Code, w.Body.String())
	}
	// 3. The clock-out is accepted; a following clock-out is rejected.
	w = post(event("evt-dup-3", "clock_out", at(8, 30)))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 clock_out, got %d: %s", w.Code, w.Body.String())
	}
	w = post(event("evt-dup-4", "clock_out", at(8, 35)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not clocked in") {
		t.Fatalf("expected 409 not clocked in, got %d: %s", w.Code, w.Body.String())
	}
	// 4. A fresh clock-in after the clock-out is allowed again.
	w = post(event("evt-dup-5", "clock_in", at(9, 0)))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 second clock_in, got %d: %s", w.Code, w.Body.String())
	}

	// 5. A member with no events at all cannot clock out.
	w = jsonRequest(t, r, "POST", "/users", token, "", map[string]any{"full_name": "Fresh Person"})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating user, got %d: %s", w.Code, w.Body.String())
	}
	var freshID int
	if err := a.db.QueryRow("SELECT id FROM users WHERE full_name='Fresh Person'").Scan(&freshID); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(t, r, "POST", devPath+"/attendance", "", "dup-test-key", map[string]any{"user_id": freshID, "event_id": "evt-dup-6", "event": "clock_out", "timestamp": at(9, 10)})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not clocked in") {
		t.Fatalf("expected 409 orphan clock_out, got %d: %s", w.Code, w.Body.String())
	}

	// 6. A batch counts duplicates instead of failing the whole upload.
	w = jsonRequest(t, r, "POST", devPath+"/attendance/batch", "", "dup-test-key", []map[string]any{
		{"user_id": freshID, "event_id": "evt-dup-7", "event": "clock_in", "timestamp": at(9, 15)},
		{"user_id": freshID, "event_id": "evt-dup-8", "event": "clock_in", "timestamp": at(9, 16)},
		{"user_id": freshID, "event_id": "evt-dup-9", "event": "clock_out", "timestamp": at(9, 40)},
		{"user_id": freshID, "event_id": "evt-dup-10", "event": "clock_out", "timestamp": at(9, 41)},
		{"user_id": "", "event_id": "evt-dup-11", "event": "", "timestamp": at(9, 42)},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 batch, got %d: %s", w.Code, w.Body.String())
	}
	var batchResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &batchResp)
	if batchResp["created"].(float64) != 2 || batchResp["duplicates"].(float64) != 2 || batchResp["deduplicated"].(float64) != 1 {
		t.Fatalf("expected 2 created + 2 duplicates + 1 deduplicated, got %v", batchResp)
	}

	// 7. Lateness follows the work hours saved on the settings page. The
	// fresh person's latest event is the 09:40 clock-out, so a 09:45
	// clock-in is accepted and is late under a 09:30 start + 10 min grace.
	w = jsonRequest(t, r, "POST", "/settings", token, "", map[string]any{"start": "09:30", "end": "16:45", "late_threshold_minutes": 10, "early_departure_minutes": 20})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 settings update, got %d: %s", w.Code, w.Body.String())
	}
	w = jsonRequest(t, r, "POST", devPath+"/attendance", "", "dup-test-key", map[string]any{"user_id": freshID, "event_id": "evt-dup-12", "event": "clock_in", "timestamp": at(9, 45)})
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"attendance_status":"late"`) {
		t.Fatalf("expected late clock_in, got %d: %s", w.Code, w.Body.String())
	}
}
