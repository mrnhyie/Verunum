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
	"github.com/gorilla/websocket"
	appdb "github.com/sparklabafrica/verunum/internal/db"
	"github.com/sparklabafrica/verunum/internal/ws"
)

func setupTestServer(t *testing.T) (*gin.Engine, *app) {
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

	// Public and platform routes
	r.GET("/ws/device", a.hub.Gin())

	api := r.Group("/api/v1")
	api.GET("/events", a.hub.SSEHandler())
	api.GET("/platform/events", a.hub.SSEHandler())
	adminAPI := api.Group("", a.adminAuth())
	adminAPI.POST("/platform/devices/pending", a.registerPendingDevice)
	adminAPI.POST("/devices/:id/enroll-request", a.enrollRequest)

	platform := r.Group("/platform", a.adminAuth(), a.superAdmin())
	platform.GET("/organisations/:org_id", a.organizationProfilePage)

	return r, a
}

func TestPendingDeviceAndAutoProvisioningFlow(t *testing.T) {
	r, a := setupTestServer(t)

	// 1. Submit pending device registration
	payload := map[string]string{
		"org_id":      "1",
		"device_name": "Main Entrance Gate",
		"mac_address": "AA:BB:CC:DD:EE:FF",
		"location":    "Lobby",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/platform/devices/pending", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	var adminUserID, adminOrgID int
	if err := a.db.QueryRow("SELECT id, organization_id FROM users WHERE email=?", "admin@demo.local").Scan(&adminUserID, &adminOrgID); err != nil {
		t.Fatal(err)
	}
	claimsToken := a.token(claims{UserID: adminUserID, OrgID: adminOrgID, Role: "super_admin", Expires: time.Now().Add(time.Hour).Unix()})
	req.Header.Set("Authorization", "Bearer "+claimsToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Connect device via WebSocket. Initial provisioning is driven by hello.
	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/device"

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v (status %d)", err, resp.StatusCode)
	}
	defer conn.Close()

	// 3. Device sends hello, then reads hello.ack
	hello, _ := ws.MarshalEnvelope(ws.TypeHello, "", "", ws.HelloPayload{MACAddress: "AA:BB:CC:DD:EE:FF", DeviceName: "Gate", ProtocolVersion: ws.ProtocolVersion})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatalf("failed to send hello: %v", err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read WS message: %v", err)
	}

	var env ws.Envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}
	if env.Type != ws.TypeHelloAck || env.Status != "provisioned" {
		t.Fatalf("expected hello.ack with status provisioned, got %s", msg)
	}

	var helloAck ws.HelloAckPayload
	_ = json.Unmarshal(env.Payload, &helloAck)
	if !strings.HasPrefix(helloAck.APIKey, "dev_sec_") {
		t.Fatalf("expected dev_sec_ API key, got %s", helloAck.APIKey)
	}

	// 4. Test Biometric enrollment trigger (online device)
	var devID int
	_ = a.db.QueryRow("SELECT id FROM devices WHERE mac_address='AA:BB:CC:DD:EE:FF'").Scan(&devID)

	enrollBody, _ := json.Marshal(map[string]any{
		"user_id":      "admin@demo.local",
		"finger_index": 1,
	})

	// Enrollment is an admin action and must not be callable anonymously.
	unauthEnrollReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/devices/dev_%d/enroll-request", devID), bytes.NewReader(enrollBody))
	unauthEnrollReq.Header.Set("Content-Type", "application/json")
	wUnauth := httptest.NewRecorder()
	r.ServeHTTP(wUnauth, unauthEnrollReq)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated enrollment request, got %d: %s", wUnauth.Code, wUnauth.Body.String())
	}
	enrollReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/devices/dev_%d/enroll-request", devID), bytes.NewReader(enrollBody))
	enrollReq.Header.Set("Content-Type", "application/json")
	enrollReq.Header.Set("Authorization", "Bearer "+claimsToken)
	wEnroll := httptest.NewRecorder()
	r.ServeHTTP(wEnroll, enrollReq)

	if wEnroll.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for online device, got %d: %s", wEnroll.Code, wEnroll.Body.String())
	}

	// The online device must receive the enrollment command over WebSocket.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, commandMsg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("expected enroll.start command: %v", err)
	}
	var commandEnv ws.Envelope
	if err := json.Unmarshal(commandMsg, &commandEnv); err != nil || commandEnv.Type != ws.TypeEnrollStart {
		t.Fatalf("expected enroll.start, got %s", commandMsg)
	}

	// Closing before an ACK must return the command to pending so it can be replayed.
	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for a.hub.Connected(devID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.hub.Connected(devID) {
		t.Fatal("device connection did not close before reconnect test")
	}

	reconnectHeader := http.Header{}
	reconnectHeader.Set("X-Device-Key", helloAck.APIKey)
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, reconnectHeader)
	if err != nil {
		t.Fatalf("device reconnect failed: %v", err)
	}
	defer conn2.Close()

	reconnectHello, _ := ws.MarshalEnvelope(ws.TypeHello, "", "", ws.HelloPayload{
		MACAddress: "AA:BB:CC:DD:EE:FF", DeviceName: "Gate", ProtocolVersion: ws.ProtocolVersion, APIKey: helloAck.APIKey,
	})
	if err := conn2.WriteMessage(websocket.TextMessage, reconnectHello); err != nil {
		t.Fatalf("failed to send reconnect hello: %v", err)
	}
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, reconnectAck, err := conn2.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read reconnect hello.ack: %v", err)
	}
	var reconnectEnv ws.Envelope
	if err := json.Unmarshal(reconnectAck, &reconnectEnv); err != nil || reconnectEnv.Type != ws.TypeHelloAck || reconnectEnv.Status != "authenticated" {
		t.Fatalf("expected authenticated reconnect, got %s", reconnectAck)
	}
	_, replayedCommand, err := conn2.ReadMessage()
	if err != nil {
		t.Fatalf("expected pending enroll.start replay: %v", err)
	}
	var replayEnv ws.Envelope
	if err := json.Unmarshal(replayedCommand, &replayEnv); err != nil || replayEnv.Type != ws.TypeEnrollStart {
		t.Fatalf("expected replayed enroll.start, got %s", replayedCommand)
	}
	if replayEnv.RequestID != commandEnv.RequestID {
		t.Fatalf("replayed command request id changed: original=%s replay=%s", commandEnv.RequestID, replayEnv.RequestID)
	}

	// 5. Test Biometric enrollment trigger on offline device
	enrollReqOffline := httptest.NewRequest("POST", "/api/v1/devices/dev_9999/enroll-request", bytes.NewReader(enrollBody))
	enrollReqOffline.Header.Set("Content-Type", "application/json")
	enrollReqOffline.Header.Set("Authorization", "Bearer "+claimsToken)
	wOffline := httptest.NewRecorder()
	r.ServeHTTP(wOffline, enrollReqOffline)

	if wOffline.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity for offline device, got %d: %s", wOffline.Code, wOffline.Body.String())
	}
}

func TestUnregisteredMACHandshake(t *testing.T) {
	r, _ := setupTestServer(t)
	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/device"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("expected WebSocket upgrade to succeed before hello: %v", err)
	}
	defer conn.Close()

	hello, _ := ws.MarshalEnvelope(ws.TypeHello, "", "", ws.HelloPayload{
		MACAddress: "11:22:33:44:55:66", DeviceName: "Unknown", ProtocolVersion: ws.ProtocolVersion,
	})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var env ws.Envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != ws.TypeError {
		t.Fatalf("expected protocol error for unregistered MAC, got %s", msg)
	}
}

func TestMissingMACHandshake(t *testing.T) {
	r, _ := setupTestServer(t)
	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/device"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("expected WebSocket upgrade to succeed before hello: %v", err)
	}
	defer conn.Close()

	hello, _ := ws.MarshalEnvelope(ws.TypeHello, "", "", ws.HelloPayload{
		DeviceName: "Missing MAC", ProtocolVersion: ws.ProtocolVersion,
	})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var env ws.Envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != ws.TypeError {
		t.Fatalf("expected protocol error for missing MAC, got %s", msg)
	}
}
