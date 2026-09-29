package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const clifeSMSEndpoint = "https://www.clife.shop/api/v1/send"

// loadDotEnv loads key=value pairs from a .env file in the working directory.
// Variables already set in the process environment take precedence, so a real
// export always wins over the file. Missing or malformed files are ignored.
func loadDotEnv(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k != "" && os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

// smsConfigured reports whether real delivery is possible. Without a key the
// worker keeps the historic stub behaviour (mark sent) so local flows and the
// test suite stay offline.
func smsConfigured() bool {
	key := strings.TrimSpace(os.Getenv("CLIFESMS_API_KEY"))
	return key != "" && !strings.Contains(strings.ToLower(key), "your") &&
		strings.TrimSpace(os.Getenv("CLIFESMS_SENDER_ID")) != ""
}

// sendClifeSMS posts one SMS through the ClifeSMS HTTP API
// (POST https://www.clife.shop/api/v1/send).
func sendClifeSMS(recipient, body string) error {
	form := url.Values{}
	form.Set("api_key", strings.TrimSpace(os.Getenv("CLIFESMS_API_KEY")))
	form.Set("sender_id", strings.TrimSpace(os.Getenv("CLIFESMS_SENDER_ID")))
	form.Set("recipient", recipient)
	form.Set("message", body)
	req, err := http.NewRequest(http.MethodPost, clifeSMSEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return &smsError{status: resp.StatusCode, body: string(respBody)}
	}
	return nil
}

type smsError struct {
	status int
	body   string
}

func (e *smsError) Error() string { return strings.TrimSpace(e.body) }

// queueSMS records an attendance notification for the user. Delivery happens
// in the background via smsWorker; nothing here blocks the ingest response.
func (a *app) queueSMS(org, eventID, userID int, event, status string) {
	var name, phone string
	if a.db.QueryRow("SELECT full_name,phone FROM users WHERE id=? AND organization_id=?", userID, org).Scan(&name, &phone) != nil || phone == "" {
		return
	}
	var ts string
	_ = a.db.QueryRow("SELECT timestamp FROM attendance_events WHERE id=? AND organization_id=?", eventID, org).Scan(&ts)
	_, _ = a.db.Exec("INSERT INTO sms_logs(organization_id,attendance_event_id,recipient_phone,body) VALUES(?,?,?,?)", org, eventID, phone, a.renderSMSBody(org, event, name, ts, status))
}

// renderSMSBody builds the message text. An org-specific sms_templates row for
// the event type wins; supported placeholders are {name}, {time}, {date} and
// {status}. The fallback copy mirrors a sensible default per event.
func (a *app) renderSMSBody(org int, event, name, timestamp, status string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		t = time.Now().UTC()
	}
	tpl := ""
	_ = a.db.QueryRow("SELECT body FROM sms_templates WHERE organization_id=? AND event_type=? ORDER BY id DESC LIMIT 1", org, event).Scan(&tpl)
	if tpl == "" {
		if event == "clock_out" {
			tpl = "Hi {name}, you clocked out at {time} on {date}. Have a great rest of your day."
		} else {
			tpl = "Hi {name}, you clocked in at {time} on {date}. Status: {status}."
		}
	}
	repl := strings.NewReplacer(
		"{name}", name,
		"{time}", t.Local().Format("15:04"),
		"{date}", t.Local().Format("Mon, 02 Jan 2006"),
		"{status}", status,
	)
	return repl.Replace(tpl)
}

// smsWorker drains the sms_logs queue every few seconds.
func (a *app) smsWorker() {
	if !smsConfigured() {
		log.Printf("sms: CLIFESMS_API_KEY not configured — queued messages are marked sent without delivery")
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.flushSMSQueue()
	}
}

func (a *app) flushSMSQueue() {
	rows, err := a.db.Query("SELECT id,recipient_phone,body FROM sms_logs WHERE status='queued' ORDER BY id LIMIT 10")
	if err != nil {
		return
	}
	type item struct {
		id    int64
		phone string
		body  string
	}
	items := []item{}
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.phone, &it.body) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, it := range items {
		if !smsConfigured() {
			_, _ = a.db.Exec("UPDATE sms_logs SET status='sent',sent_at=? WHERE id=?", now, it.id)
			continue
		}
		if err := sendClifeSMS(it.phone, it.body); err != nil {
			log.Printf("sms: delivery failed for log %d: %v", it.id, err)
			_, _ = a.db.Exec("UPDATE sms_logs SET status='failed' WHERE id=?", it.id)
			continue
		}
		_, _ = a.db.Exec("UPDATE sms_logs SET status='sent',sent_at=? WHERE id=?", now, it.id)
	}
}
