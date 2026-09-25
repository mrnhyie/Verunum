package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

	api := r.Group("/api/v1")
	api.POST("/devices/hello", a.hub.HelloHandler())
	api.GET("/events", a.hub.SSEHandler())
	adminAPI := api.Group("", a.adminAuth())
	adminAPI.POST("/platform/devices/pending", a.registerPendingDevice)
	adminAPI.POST("/devices/:id/enroll-request", a.enrollRequest)

	device := api.Group("/devices/:id", a.deviceAuth())
	device.POST("/heartbeat", a.heartbeat)
	device.GET("/commands", a.commands)
	device.POST("/commands/:cmdId/ack", a.ackCommand)
	device.POST("/enrollment/result", a.hub.EnrollResultHandler())
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
