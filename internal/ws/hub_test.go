package ws

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	appdb "github.com/sparklabafrica/verunum/internal/db"
)

func setupTestDB(t *testing.T) *sql.DB {
	gin.SetMode(gin.TestMode)
	database, err := appdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func TestDeviceRESTEnrollAndAttendance(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(name,type) VALUES('Acme','school')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO attendance_rules(organization_id) VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO users(organization_id,full_name,role,uuid) VALUES(1,'Ama','viewer','11111111-1111-4111-8111-111111111111')"); err != nil {
		t.Fatal(err)
	}
	keyHash := hashKey("dev-secret")
	if _, err := database.Exec("INSERT INTO devices(organization_id,name,serial_number,mac_address,api_key_hash,status,last_heartbeat) VALUES(1,'Gate','TAB5-1','AA:AA:AA:AA:AA:AA',?,'active',?)", keyHash, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	var ingested struct{ user, event string }
	hub := NewHub(database, func(orgID, deviceID int, eventID, userUUID, event, timestamp, method string) (int64, string, error) {
		ingested.user = userUUID
		ingested.event = event
		return 42, "on_time", nil
	})

	r := gin.New()
	r.POST("/api/v1/devices/hello", hub.HelloHandler())

	// 1. Authenticate via hello — flat REST response, no envelope
	helloBody := `{"mac_address":"AA:AA:AA:AA:AA:AA","device_name":"Gate","protocol_version":1,"api_key":"dev-secret"}`
	req := httptest.NewRequest("POST", "/api/v1/devices/hello", strings.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var helloResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &helloResp); err != nil {
		t.Fatal(err)
	}
	if helloResp["status"] != "authenticated" || helloResp["device_id"] != "dev_1" {
		t.Fatalf("expected flat authenticated hello response, got %v", helloResp)
	}

	// 2. Start enrollment
	requestID, delivered, err := hub.StartEnrollment(1, 1, 1, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("start enroll: err=%v", err)
	}
	// Device has a recent heartbeat, so delivered should be true
	if !delivered {
		t.Fatal("expected delivered=true for device with recent heartbeat")
	}

	// 3. Verify command is pending and its payload carries the request_id
	var payloadJSON, cmdStatus string
	var cmdID int
	if err := database.QueryRow("SELECT id,payload_json,status FROM device_commands WHERE device_id=1").Scan(&cmdID, &payloadJSON, &cmdStatus); err != nil {
		t.Fatal(err)
	}
	if cmdStatus != "pending" {
		t.Fatalf("expected pending command, got %q", cmdStatus)
	}
	var polled EnrollStartPayload
	if err := json.Unmarshal([]byte(payloadJSON), &polled); err != nil {
		t.Fatal(err)
	}
	if strconv.Itoa(cmdID) != requestID || polled.RequestID != requestID {
		t.Fatalf("request_id not echoed in payload: cmdID=%d requestID=%s payload=%s", cmdID, requestID, payloadJSON)
	}

	// 4. Submit enroll result via REST with the PDF contract body
	enrollResultBody := `{"command_id":` + strconv.Itoa(cmdID) + `,"request_id":"` + requestID + `","user_id":"11111111-1111-4111-8111-111111111111","finger_index":1,"success":true}`
	enrollReq := httptest.NewRequest("POST", "/api/v1/devices/1/enrollment/result", strings.NewReader(enrollResultBody))
	enrollReq.Header.Set("Content-Type", "application/json")

	// Simulate deviceAuth middleware by setting context values
	enrollR := gin.New()
	enrollR.POST("/api/v1/devices/:id/enrollment/result", func(c *gin.Context) {
		c.Set("device_id", 1)
		c.Set("org_id", 1)
		hub.EnrollResultHandler()(c)
	})
	wEnroll := httptest.NewRecorder()
	enrollR.ServeHTTP(wEnroll, enrollReq)

	if wEnroll.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", wEnroll.Code, wEnroll.Body.String())
	}

	// 5. Verify fingerprint status updated and command acked
	var fp string
	if err := database.QueryRow("SELECT fingerprint_status FROM users WHERE id=1").Scan(&fp); err != nil || fp != "enrolled" {
		t.Fatalf("fingerprint status %q err=%v", fp, err)
	}
	var ackedCount int
	if err := database.QueryRow("SELECT count(*) FROM device_commands WHERE id=? AND status='acked'", cmdID).Scan(&ackedCount); err != nil || ackedCount != 1 {
		t.Fatalf("expected command acked, got count=%d err=%v", ackedCount, err)
	}
}

func TestDeviceAutoProvisioning(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(id, name, type) VALUES(10, 'Test Org', 'school')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO pending_device_enrollments(id, org_id, mac_address, device_name, location) VALUES('pend_1', '10', 'AA:BB:CC:DD:EE:FF', 'Main Gate', 'Lobby')"); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)
	sseCh := hub.SubscribeSSE()
	defer hub.UnsubscribeSSE(sseCh)

	r := gin.New()
	r.POST("/api/v1/devices/hello", hub.HelloHandler())

	// New device sends hello without API key — should be auto-provisioned
	helloBody := `{"mac_address":"AA:BB:CC:DD:EE:FF","device_name":"Main Gate","protocol_version":1}`
	req := httptest.NewRequest("POST", "/api/v1/devices/hello", strings.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "provisioned" || resp["device_id"] != "dev_1" {
		t.Fatalf("expected flat provisioned response, got %v", resp)
	}

	apiKey, ok := resp["api_key"].(string)
	if !ok || !strings.HasPrefix(apiKey, "dev_sec_") {
		t.Fatalf("expected dev_sec_ prefix for api key, got %v", resp["api_key"])
	}

	// Verify SSE broadcast was received
	select {
	case sseEvt := <-sseCh:
		if sseEvt.Event != "device.provisioned" || sseEvt.MACAddress != "AA:BB:CC:DD:EE:FF" {
			t.Fatalf("unexpected SSE event: %+v", sseEvt)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for SSE broadcast")
	}

	// Verify pending record removed and device inserted
	var pendingCount, devCount int
	var plaintextKey string
	_ = database.QueryRow("SELECT COALESCE(api_key,'') FROM devices WHERE mac_address='AA:BB:CC:DD:EE:FF'").Scan(&plaintextKey)
	if plaintextKey != "" {
		t.Fatalf("plaintext API key must not be stored")
	}
	_ = database.QueryRow("SELECT COUNT(*) FROM pending_device_enrollments WHERE mac_address='AA:BB:CC:DD:EE:FF'").Scan(&pendingCount)
	if pendingCount != 0 {
		t.Fatalf("expected pending record deleted, found %d", pendingCount)
	}
	_ = database.QueryRow("SELECT COUNT(*) FROM devices WHERE mac_address='AA:BB:CC:DD:EE:FF'").Scan(&devCount)
	if devCount != 1 {
		t.Fatalf("expected device inserted, found %d", devCount)
	}
}

func TestDeviceMustProvideValidMAC(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(id,name,type) VALUES(1,'Acme','school')"); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)
	r := gin.New()
	r.POST("/api/v1/devices/hello", hub.HelloHandler())

	// Missing MAC address
	helloBody := `{"device_name":"Missing MAC","protocol_version":1}`
	req := httptest.NewRequest("POST", "/api/v1/devices/hello", strings.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnregisteredMACHello(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(id,name,type) VALUES(1,'Acme','school')"); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)
	r := gin.New()
	r.POST("/api/v1/devices/hello", hub.HelloHandler())

	// Unregistered MAC without API key — PDF contract: 404
	helloBody := `{"mac_address":"11:22:33:44:55:66","device_name":"Unknown","protocol_version":1}`
	req := httptest.NewRequest("POST", "/api/v1/devices/hello", strings.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAlreadyProvisionedMACHelloWithoutKey(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(id,name,type) VALUES(1,'Acme','school')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO devices(organization_id,name,mac_address,api_key_hash,status) VALUES(1,'Gate','AA:AA:AA:AA:AA:AA',?,'active')", hashKey("dev-secret")); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)
	r := gin.New()
	r.POST("/api/v1/devices/hello", hub.HelloHandler())

	// PDF contract: already-provisioned MAC re-helloing without a key → 409
	helloBody := `{"mac_address":"AA:AA:AA:AA:AA:AA","device_name":"Gate","protocol_version":1}`
	req := httptest.NewRequest("POST", "/api/v1/devices/hello", strings.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHeartbeatBasedConnectivity(t *testing.T) {
	database := setupTestDB(t)
	if _, err := database.Exec("INSERT INTO organizations(name,type) VALUES('Acme','school')"); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)

	// Device with recent heartbeat
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = database.Exec("INSERT INTO devices(organization_id,name,mac_address,api_key_hash,status,last_heartbeat) VALUES(1,'Gate','AA:AA:AA:AA:AA:AA','hash','active',?)", now)
	if !hub.Connected(1) {
		t.Fatal("expected device 1 to be connected")
	}

	// Device with old heartbeat
	old := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	_, _ = database.Exec("INSERT INTO devices(organization_id,name,mac_address,api_key_hash,status,last_heartbeat) VALUES(1,'Gate2','BB:BB:BB:BB:BB:BB','hash','active',?)", old)
	if hub.Connected(2) {
		t.Fatal("expected device 2 to be disconnected")
	}

	// ConnectedIDs
	ids := hub.ConnectedIDs(1)
	if !ids[1] {
		t.Fatal("expected device 1 in connected IDs")
	}
	if ids[2] {
		t.Fatal("expected device 2 not in connected IDs")
	}
}
