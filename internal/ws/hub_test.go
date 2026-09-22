package ws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	appdb "github.com/sparklabafrica/verunum/internal/db"
)

func TestDeviceWebSocketEnrollAndAttendance(t *testing.T) {
	database, err := appdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
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
	if _, err := database.Exec("INSERT INTO devices(organization_id,name,serial_number,mac_address,api_key_hash) VALUES(1,'Gate','TAB5-1','AA:AA:AA:AA:AA:AA',?)", keyHash); err != nil {
		t.Fatal(err)
	}

	var ingested struct{ user, event string }
	hub := NewHub(database, func(orgID, deviceID int, eventID, userUUID, event, timestamp, method string) (int64, string, error) {
		ingested.user = userUUID
		ingested.event = event
		return 42, "on_time", nil
	})
	srv := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "?api_key=dev-secret"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello, _ := marshalEnvelope(TypeHello, "", HelloPayload{MACAddress: "AA:AA:AA:AA:AA:AA", DeviceName: "Gate", ProtocolVersion: ProtocolVersion, APIKey: "dev-secret"})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatal(err)
	}
	_, helloAck, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(helloAck, &env); err != nil || env.Type != TypeHelloAck || env.Status != "authenticated" {
		t.Fatalf("expected hello.ack authenticated, got %s %v", helloAck, err)
	}

	reqID, delivered, err := hub.StartEnrollment(1, 1, 1, "11111111-1111-4111-8111-111111111111")
	if err != nil || !delivered {
		t.Fatalf("start enroll: delivered=%v err=%v", delivered, err)
	}
	_, enroll, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(enroll, &env); err != nil || env.Type != TypeEnrollStart {
		t.Fatalf("expected enroll.start, got %s", enroll)
	}
	var start EnrollStartPayload
	_ = json.Unmarshal(env.Payload, &start)
	if start.UserID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("user id payload: %+v", start)
	}
	if env.RequestID != reqID {
		t.Fatalf("request id %s != %s", env.RequestID, reqID)
	}

	result, _ := marshalEnvelope(TypeEnrollResult, reqID, EnrollResultPayload{UserID: start.UserID, Status: "enrolled"})
	if err := conn.WriteMessage(websocket.TextMessage, result); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	_, ack, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ack, &env); err != nil || env.Type != TypeAck {
		t.Fatalf("expected ack, got %s", ack)
	}
	var fp string
	if err := database.QueryRow("SELECT fingerprint_status FROM users WHERE id=1").Scan(&fp); err != nil || fp != "enrolled" {
		t.Fatalf("fingerprint status %q err=%v", fp, err)
	}

	att, _ := marshalEnvelope(TypeAttendance, "att-1", AttendancePayload{EventID: "evt-1", UserID: start.UserID, Event: "clock_in", Method: "fingerprint"})
	if err := conn.WriteMessage(websocket.TextMessage, att); err != nil {
		t.Fatal(err)
	}
	_, ack, err = conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if ingested.user != start.UserID || ingested.event != "clock_in" {
		t.Fatalf("attendance ingest %+v", ingested)
	}
	if err := json.Unmarshal(ack, &env); err != nil || env.Type != TypeAck {
		t.Fatalf("expected attendance ack, got %s", ack)
	}
}

func TestDeviceAutoProvisioning(t *testing.T) {
	database, err := appdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec("INSERT INTO organizations(id, name, type) VALUES(10, 'Test Org', 'school')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO pending_device_enrollments(id, org_id, mac_address, device_name, location) VALUES('pend_1', '10', 'AA:BB:CC:DD:EE:FF', 'Main Gate', 'Lobby')"); err != nil {
		t.Fatal(err)
	}

	hub := NewHub(database, nil)
	sseCh := hub.SubscribeSSE()
	defer hub.UnsubscribeSSE(sseCh)

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer srv.Close()

	// Initial connection is intentionally unauthenticated; hello carries MAC + name.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v, resp status=%v", err, resp.StatusCode)
	}
	defer conn.Close()

	hello, _ := marshalEnvelope(TypeHello, "", HelloPayload{MACAddress: "AA:BB:CC:DD:EE:FF", DeviceName: "Main Gate", ProtocolVersion: ProtocolVersion})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read message error: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(msg, &env); err != nil || env.Type != TypeHelloAck || env.Status != "provisioned" {
		t.Fatalf("expected hello.ack provisioned, got %s", msg)
	}

	var payload HelloAckPayload
	_ = json.Unmarshal(env.Payload, &payload)
	if !strings.HasPrefix(payload.APIKey, "dev_sec_") {
		t.Fatalf("expected dev_sec_ prefix for api key, got %s", payload.APIKey)
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

func TestDeviceMustSendHelloFirst(t *testing.T) {
	database, err := appdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec("INSERT INTO organizations(id,name,type) VALUES(1,'Acme','school')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO devices(organization_id,name,mac_address,api_key_hash) VALUES(1,'Gate','AA:AA:AA:AA:AA:AA',?)", hashKey("secret")); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(database, nil)
	srv := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "?api_key=secret"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	bad, _ := marshalEnvelope(TypePing, "1", nil)
	if err := conn.WriteMessage(websocket.TextMessage, bad); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != TypeError {
		t.Fatalf("expected error, got %s", msg)
	}
}
