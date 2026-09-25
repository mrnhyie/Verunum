package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	appdb "github.com/sparklabafrica/verunum/internal/db"
	"github.com/sparklabafrica/verunum/internal/ws"
)

type app struct {
	db     *sql.DB
	secret []byte
	hub    *ws.Hub
}
type claims struct {
	UserID, OrgID int
	Role          string
	Expires       int64
}
type eventInput struct {
	UserID    int    `json:"user_id"`
	EventID   string `json:"event_id"`
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
}

func main() {
	// Setup flags without the broken addr flag
	file := flag.String("db", "verunum.db", "SQLite database path")
	flag.Parse()

	database, err := appdb.Open(*file)
	if err != nil {
		log.Fatal(err)
	}
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if strings.EqualFold(strings.TrimSpace(os.Getenv("VERUNUM_ENV")), "production") && len(jwtSecret) < 32 {
		log.Fatal("JWT_SECRET must be set to a random value of at least 32 characters in production")
	}
	if jwtSecret == "" {
		jwtSecret = "change-me-in-production"
	}
	a := &app{db: database, secret: []byte(jwtSecret)}
	a.hub = ws.NewHub(database, a.insertEventByUUID)
	if err := a.seed(); err != nil {
		log.Fatal(err)
	}
	go a.smsWorker()

	r := gin.Default()
	r.SetTrustedProxies(nil)
	r.LoadHTMLGlob("web/templates/*")
	r.Static("/static", "web/static")
	r.GET("/", func(c *gin.Context) { c.HTML(200, "index.html", gin.H{"Title": "Verunum Platform"}) })
	r.GET("/login", func(c *gin.Context) { c.HTML(200, "login.html", gin.H{"Error": ""}) })
	r.POST("/auth/login", a.login)
	r.POST("/auth/refresh", a.refresh)
	r.POST("/auth/logout", func(c *gin.Context) { c.SetCookie("verunum_token", "", -1, "/", "", false, true); c.Redirect(http.StatusFound, "/login") })

	admin := r.Group("", a.adminAuth())
	admin.GET("/dashboard", a.dashboard)
	admin.GET("/users", a.usersPage)
	admin.GET("/users/new", a.newUserPage)
	admin.GET("/users/:id/status", a.userStatus)
	admin.GET("/users/:id", a.userPage)
	admin.POST("/users/:id/enroll", a.startEnroll)
	admin.GET("/devices", a.devicesPage)
	admin.GET("/rfid-cards", a.cardsPage)
	admin.GET("/rfid-cards/new", a.newCardPage)
	admin.GET("/attendance", a.attendancePage)
	admin.GET("/reports/:period", a.report)
	admin.GET("/devices/status", a.devicesStatus)
	admin.POST("/users", a.createUser)
	admin.POST("/users/:id", a.updateUser)
	admin.PUT("/users/:id", a.updateUser)
	admin.POST("/users/:id/delete", a.deleteUser)
	admin.DELETE("/users/:id", a.deleteUser)
	admin.POST("/rfid-cards", a.createCard)
	admin.PUT("/rfid-cards/:id", a.updateCard)
	admin.POST("/attendance/:id/correct", a.correctAttendance)
	admin.POST("/sms/templates", a.createTemplate)
	admin.GET("/account/password", a.changePasswordPage)
	admin.POST("/account/password", a.changePassword)

	staff := r.Group("/admin", a.adminAuth(), a.superAdmin())
	staff.GET("/organizations", a.organizationsPage)
	staff.GET("/organizations/new", a.newOrganizationPage)
	staff.POST("/organizations", a.provisionOrganization)
	staff.GET("/organizations/:orgId", a.organizationProfilePage)
	staff.GET("/organizations/:orgId/edit", a.editOrganizationPage)
	staff.POST("/organizations/:orgId", a.updateOrganization)
	staff.POST("/organizations/:orgId/delete", a.deactivateOrganization)
	staff.GET("/organizations/:orgId/devices/new", a.platformProvisioningPage)
	staff.POST("/organizations/:orgId/devices", a.provisionDevice)
	staff.POST("/organizations/:orgId/devices/:deviceId/revoke", a.revokeDevice)
	staff.POST("/organizations/:orgId/devices/:deviceId/reprovision", a.reprovisionDevice)
	staff.POST("/organizations/:orgId/toggle-status", a.toggleOrgStatus)
	staff.POST("/organizations/:orgId/logo", a.uploadOrganizationLogo)

	platform := r.Group("/platform", a.adminAuth(), a.superAdmin())
	platform.GET("/device-provisioning", a.platformProvisioningPage)
	platform.GET("/organisations", a.organizationsPage)
	platform.GET("/organisations/:org_id", a.organizationProfilePage)
	platform.POST("/organisations/:org_id/devices/:device_id/revoke", a.revokeDevice)
	platform.POST("/organisations/:org_id/devices/:device_id/reprovision", a.reprovisionDevice)
	platform.POST("/organisations/:org_id/toggle-status", a.toggleOrgStatus)
	platform.POST("/organisations/:org_id/logo", a.uploadOrganizationLogo)

	// Device REST API endpoints (replaces former WebSocket handshake)
	api := r.Group("/api/v1")
	api.POST("/devices/hello", a.hub.HelloHandler())
	api.GET("/events", a.hub.SSEHandler())
	api.GET("/platform/events", a.hub.SSEHandler())
	adminAPI := r.Group("/api/v1", a.adminAuth())
	adminAPI.POST("/platform/devices/pending", a.registerPendingDevice)
	adminAPI.POST("/devices/:id/enroll-request", a.enrollRequest)

	device := api.Group("/devices/:id", a.deviceAuth())
	device.POST("/heartbeat", a.heartbeat)
	device.GET("/commands", a.commands)
	device.POST("/commands/:cmdId/ack", a.ackCommand)
	device.POST("/enrollment/result", a.hub.EnrollResultHandler())
	device.POST("/attendance", a.ingestAttendance)
	device.POST("/attendance/batch", a.ingestBatch)

	// FIXED: Replaced *addr with explicit string to prevent compile error
	log.Printf("Verunum running on 0.0.0.0:8080")

	// Exposes port 8080 directly to any network interface
	log.Fatal(r.Run("0.0.0.0:8080"))
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func randomKey() string    { b := make([]byte, 32); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func (a *app) seed() error {
	var n int
	if err := a.db.QueryRow("SELECT count(*) FROM organizations").Scan(&n); err != nil {
		return err
	}
	tx, _ := a.db.Begin()
	defer tx.Rollback()
	var org int64
	if n == 0 {
		production := strings.EqualFold(strings.TrimSpace(os.Getenv("VERUNUM_ENV")), "production")
		email := strings.TrimSpace(os.Getenv("VERUNUM_BOOTSTRAP_ADMIN_EMAIL"))
		password := os.Getenv("VERUNUM_BOOTSTRAP_ADMIN_PASSWORD")
		name := strings.TrimSpace(os.Getenv("VERUNUM_BOOTSTRAP_ADMIN_NAME"))
		orgName := strings.TrimSpace(os.Getenv("VERUNUM_BOOTSTRAP_ORGANIZATION"))
		if production {
			if email == "" || len(password) < 12 || orgName == "" {
				return fmt.Errorf("production bootstrap requires VERUNUM_BOOTSTRAP_ADMIN_EMAIL, VERUNUM_BOOTSTRAP_ADMIN_PASSWORD (12+ chars), and VERUNUM_BOOTSTRAP_ORGANIZATION")
			}
		} else {
			if email == "" {
				email = "admin@demo.local"
			}
			if password == "" {
				password = "admin123"
			}
			if name == "" {
				name = "Demo Administrator"
			}
			if orgName == "" {
				orgName = "SparkLab Demo Academy"
			}
		}
		r, err := tx.Exec("INSERT INTO organizations(name,type) VALUES(?,?)", orgName, "school")
		if err != nil {
			return err
		}
		org, _ = r.LastInsertId()
		br, _ := tx.Exec("INSERT INTO branches(organization_id,name,location) VALUES(?,?,?)", org, "Main Campus", "Accra")
		branch, _ := br.LastInsertId()
		if _, err := tx.Exec("INSERT INTO users(organization_id,branch_id,full_name,email,password_hash,role,uuid) VALUES(?,?,?,?,?,?,?)", org, branch, name, email, hash(password), "super_admin", uuid.NewString()); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO attendance_rules(organization_id) VALUES(?)", org); err != nil {
			return err
		}
		if !production {
			if _, err := tx.Exec("INSERT OR IGNORE INTO organization_access_codes(organization_id,code_hash) VALUES(?,?)", org, hash("VERUNUM-DEMO-01")); err != nil {
				return err
			}
		}
	} else if err := tx.QueryRow("SELECT id FROM organizations ORDER BY id LIMIT 1").Scan(&org); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *app) token(x claims) string {
	p, _ := json.Marshal(x)
	body := base64.RawURLEncoding.EncodeToString(p)
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (a *app) parseToken(t string) (claims, error) {
	var x claims
	p := strings.Split(t, ".")
	if len(p) != 2 {
		return x, fmt.Errorf("invalid token")
	}
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(p[0]))
	s, _ := base64.RawURLEncoding.DecodeString(p[1])
	if !hmac.Equal(s, m.Sum(nil)) {
		return x, fmt.Errorf("invalid signature")
	}
	raw, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return x, e
	}
	e = json.Unmarshal(raw, &x)
	if e != nil || x.Expires < time.Now().Unix() {
		return x, fmt.Errorf("expired token")
	}
	return x, nil
}
func (a *app) login(c *gin.Context) {
	var in struct {
		Email    string `form:"email" json:"email"`
		Password string `form:"password" json:"password"`
	}
	if err := c.ShouldBind(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}
	var id, org int
	var role, pw string
	var mustChange int
	err := a.db.QueryRow("SELECT u.id,u.organization_id,u.role,u.password_hash,u.must_change_password FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.email=? AND u.status='active' AND o.status='active'", in.Email).Scan(&id, &org, &role, &pw, &mustChange)
	if err != nil || !hmac.Equal([]byte(pw), []byte(hash(in.Password))) {
		if strings.Contains(c.GetHeader("Accept"), "text/html") {
			c.HTML(401, "login.html", gin.H{"Error": "Invalid email or password"})
		} else {
			c.JSON(401, gin.H{"error": "invalid credentials"})
		}
		return
	}
	t := a.token(claims{id, org, role, time.Now().Add(8 * time.Hour).Unix()})
	c.SetCookie("verunum_token", t, 8*3600, "/", "", false, true)
	if strings.Contains(c.GetHeader("Accept"), "text/html") {
		if mustChange == 1 {
			c.Redirect(http.StatusFound, "/account/password")
			return
		}
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.JSON(200, gin.H{"token": t, "expires_in": 28800, "must_change_password": mustChange == 1})
}
func (a *app) register(c *gin.Context) {
	var in struct {
		AccessCode           string `form:"access_code" json:"access_code"`
		OrganizationName     string `form:"organization_name" json:"organization_name"`
		OrganizationType     string `form:"organization_type" json:"organization_type"`
		OrganizationPhone    string `form:"organization_phone" json:"organization_phone"`
		OrganizationLocation string `form:"organization_location" json:"organization_location"`
		FullName             string `form:"full_name" json:"full_name"`
		Email                string `form:"email" json:"email"`
		Password             string `form:"password" json:"password"`
		ConfirmPassword      string `form:"confirm_password" json:"confirm_password"`
	}
	if err := c.ShouldBind(&in); err != nil || strings.TrimSpace(in.OrganizationName) == "" || !validOrganizationType(in.OrganizationType) || strings.TrimSpace(in.FullName) == "" || strings.TrimSpace(in.Email) == "" || len(in.Password) < 8 || in.Password != in.ConfirmPassword {
		a.registerError(c, "Enter your organisation details, company code, and matching 8+ character password.")
		return
	}
	var codeID, org int
	err := a.db.QueryRow("SELECT id,organization_id FROM organization_access_codes WHERE code_hash=? AND status='active'", hash(strings.ToUpper(strings.TrimSpace(in.AccessCode)))).Scan(&codeID, &org)
	if err != nil {
		a.registerError(c, "That company code is not valid or has been revoked.")
		return
	}
	var exists int
	_ = a.db.QueryRow("SELECT count(*) FROM users WHERE lower(email)=lower(?)", strings.TrimSpace(in.Email)).Scan(&exists)
	if exists > 0 {
		a.registerError(c, "An account already uses this email address. Please sign in.")
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		a.registerError(c, "We could not create the account. Please try again.")
		return
	}
	defer tx.Rollback()
	var claimed int
	if err := tx.QueryRow("SELECT count(*) FROM organization_onboarding WHERE access_code_id=?", codeID).Scan(&claimed); err != nil || claimed > 0 {
		a.registerError(c, "This company code has already been used to activate an organisation account.")
		return
	}
	profile, _ := json.Marshal(map[string]string{"phone": strings.TrimSpace(in.OrganizationPhone), "location": strings.TrimSpace(in.OrganizationLocation)})
	if _, err := tx.Exec("UPDATE organizations SET name=?,type=?,settings_json=? WHERE id=?", strings.TrimSpace(in.OrganizationName), in.OrganizationType, string(profile), org); err != nil {
		a.registerError(c, "We could not save the organisation details. Please try again.")
		return
	}
	r, err := tx.Exec("INSERT INTO users(organization_id,full_name,email,password_hash,role,uuid) VALUES(?,?,?,?,?,?)", org, strings.TrimSpace(in.FullName), strings.TrimSpace(in.Email), hash(in.Password), "org_admin", uuid.NewString())
	if err != nil {
		a.registerError(c, "We could not create the account. Please try again.")
		return
	}
	id, _ := r.LastInsertId()
	if _, err := tx.Exec("INSERT INTO organization_onboarding(access_code_id,organization_id,owner_user_id) VALUES(?,?,?)", codeID, org, id); err != nil {
		a.registerError(c, "This company code has already been used to activate an organisation account.")
		return
	}
	_, _ = tx.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id,after_json) VALUES(?,?,?,?,?,?)", org, id, "register", "organization", org, fmt.Sprintf(`{"access_code_id":%d,"type":%q}`, codeID, in.OrganizationType))
	if err := tx.Commit(); err != nil {
		a.registerError(c, "We could not create the account. Please try again.")
		return
	}
	t := a.token(claims{int(id), org, "org_admin", time.Now().Add(8 * time.Hour).Unix()})
	c.SetCookie("verunum_token", t, 8*3600, "/", "", false, true)
	if strings.Contains(c.GetHeader("Accept"), "text/html") {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.JSON(201, gin.H{"token": t, "organization_id": org})
}
func validOrganizationType(v string) bool {
	switch v {
	case "school", "church", "company", "home", "other":
		return true
	}
	return false
}
func (a *app) registerError(c *gin.Context, msg string) {
	if strings.Contains(c.GetHeader("Accept"), "text/html") || strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded") {
		c.HTML(400, "register.html", gin.H{"Error": msg})
		return
	}
	c.JSON(400, gin.H{"error": msg})
}
func (a *app) refresh(c *gin.Context) {
	x, ok := c.Get("claims")
	if !ok {
		c.JSON(401, gin.H{"error": "authentication required"})
		return
	}
	v := x.(claims)
	c.JSON(200, gin.H{"token": a.token(claims{v.UserID, v.OrgID, v.Role, time.Now().Add(8 * time.Hour).Unix()})})
}
func (a *app) adminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if t == "" {
			t, _ = c.Cookie("verunum_token")
		}
		x, e := a.parseToken(t)
		if e != nil {
			if strings.Contains(c.GetHeader("Accept"), "text/html") {
				c.Redirect(302, "/login")
			} else {
				c.JSON(401, gin.H{"error": "authentication required"})
			}
			c.Abort()
			return
		}
		var mustChange int
		if err := a.db.QueryRow("SELECT must_change_password FROM users WHERE id=? AND organization_id=?", x.UserID, x.OrgID).Scan(&mustChange); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load account state"})
			c.Abort()
			return
		}
		if mustChange == 1 && c.Request.URL.Path != "/account/password" {
			if strings.Contains(c.GetHeader("Accept"), "text/html") {
				c.Redirect(http.StatusFound, "/account/password")
			} else {
				c.JSON(http.StatusForbidden, gin.H{"error": "password change required", "must_change_password": true})
			}
			c.Abort()
			return
		}
		c.Set("claims", x)
		c.Next()
	}
}
func (a *app) superAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.MustGet("claims").(claims).Role != "super_admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "platform staff access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
func (a *app) org(c *gin.Context) int      { return c.MustGet("claims").(claims).OrgID }
func deviceID(c *gin.Context) (int, error) {
	return strconv.Atoi(strings.TrimPrefix(c.Param("id"), "dev_"))
}
func (a *app) deviceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-Device-Key")
		id, e := deviceID(c)
		var org int
		if e != nil || key == "" || a.db.QueryRow("SELECT organization_id FROM devices WHERE id=? AND api_key_hash=? AND status!='revoked'", id, hash(key)).Scan(&org) != nil {
			c.JSON(401, gin.H{"error": "device authentication failed"})
			c.Abort()
			return
		}
		c.Set("device_id", id)
		c.Set("org_id", org)
		c.Next()
	}
}

func (a *app) registerDevice(c *gin.Context) {
	var in struct {
		BranchID     int    `json:"branch_id"`
		AccessCode   string `json:"access_code"`
		Name         string `json:"name"`
		SerialNumber string `json:"serial_number"`
	}
	if c.ShouldBindJSON(&in) != nil || in.AccessCode == "" || in.Name == "" || in.SerialNumber == "" {
		c.JSON(400, gin.H{"error": "access_code, name and serial_number required"})
		return
	}
	var codeID, org int
	if err := a.db.QueryRow("SELECT id,organization_id FROM organization_access_codes WHERE code_hash=? AND status='active'", hash(strings.ToUpper(strings.TrimSpace(in.AccessCode)))).Scan(&codeID, &org); err != nil {
		c.JSON(403, gin.H{"error": "invalid company access code"})
		return
	}
	key := randomKey()
	var branchID any
	if in.BranchID > 0 {
		branchID = in.BranchID
	}
	r, e := a.db.Exec("INSERT INTO devices(organization_id,branch_id,name,serial_number,api_key_hash,status) VALUES(?,?,?,?,?,'offline')", org, branchID, in.Name, in.SerialNumber, hash(key))
	if e != nil {
		c.JSON(409, gin.H{"error": "device registration failed: " + e.Error()})
		return
	}
	id, _ := r.LastInsertId()
	_, _ = a.db.Exec("INSERT INTO device_access_codes(device_id,access_code_id) VALUES(?,?)", id, codeID)
	c.JSON(201, gin.H{"id": id, "organization_id": org, "api_key": key, "warning": "Store this API key securely; it is shown only once."})
}
func (a *app) heartbeat(c *gin.Context) {
	id := c.MustGet("device_id").(int)
	_, e := a.db.Exec("UPDATE devices SET status='online',last_heartbeat=? WHERE id=? AND organization_id=?", time.Now().UTC().Format(time.RFC3339), id, c.MustGet("org_id").(int))
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.Status(204)
}
func (a *app) commands(c *gin.Context) {
	id, org := c.MustGet("device_id").(int), c.MustGet("org_id").(int)
	rows, e := a.db.Query("SELECT id,command_type,payload_json,created_at FROM device_commands WHERE organization_id=? AND device_id=? AND status='pending' ORDER BY id", org, id)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int
		var typ, payload, created string
		rows.Scan(&id, &typ, &payload, &created)
		out = append(out, gin.H{"id": id, "command_type": typ, "payload": json.RawMessage(payload), "created_at": created})
	}
	c.JSON(200, gin.H{"commands": out})
}
func (a *app) ackCommand(c *gin.Context) {
	cmd, _ := strconv.Atoi(c.Param("cmdId"))
	id, org := c.MustGet("device_id").(int), c.MustGet("org_id").(int)
	var in struct {
		Status string `json:"status"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Status == "" {
		in.Status = "acked"
	}
	if in.Status != "delivered" && in.Status != "acked" {
		c.JSON(400, gin.H{"error": "status must be delivered or acked"})
		return
	}
	q := "UPDATE device_commands SET status=?, delivered_at=CASE WHEN ?='delivered' THEN ? ELSE delivered_at END, acked_at=CASE WHEN ?='acked' THEN ? ELSE acked_at END WHERE id=? AND device_id=? AND organization_id=?"
	r, e := a.db.Exec(q, in.Status, in.Status, time.Now().UTC().Format(time.RFC3339), in.Status, time.Now().UTC().Format(time.RFC3339), cmd, id, org)
	n, _ := r.RowsAffected()
	if e != nil || n == 0 {
		c.JSON(404, gin.H{"error": "command not found"})
		return
	}
	c.Status(204)
}
func (a *app) ingestAttendance(c *gin.Context) {
	var in eventInput
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(400, gin.H{"error": "invalid event"})
		return
	}
	id, status, _, e := a.insertEvent(c.MustGet("org_id").(int), c.MustGet("device_id").(int), in)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id, "attendance_status": status})
}
func (a *app) ingestBatch(c *gin.Context) {
	var in []eventInput
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(400, gin.H{"error": "expected event array"})
		return
	}
	org := c.MustGet("org_id").(int)
	device := c.MustGet("device_id").(int)
	created := 0
	for _, e := range in {
		if id, _, isNew, err := a.insertEvent(org, device, e); err == nil && id > 0 && isNew {
			created++
		}
	}
	c.JSON(201, gin.H{"received": len(in), "created": created, "deduplicated": len(in) - created})
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

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func (a *app) insertEvent(org, deviceID int, in eventInput) (int64, string, bool, error) {
	if in.UserID == 0 || in.Event == "" {
		return 0, "", false, fmt.Errorf("user_id and event required")
	}
	t, err := time.Parse(time.RFC3339, in.Timestamp)
	if err != nil {
		t = time.Now().UTC()
	}
	if in.Method == "" {
		in.Method = "fingerprint"
	}
	var ok int
	if err = a.db.QueryRow("SELECT count(*) FROM users WHERE id=? AND organization_id=? AND status='active'", in.UserID, org).Scan(&ok); err != nil || ok == 0 {
		return 0, "", false, fmt.Errorf("user not found in device organization")
	}
	status := a.eventStatus(org, in.Event, t)
	if in.EventID != "" {
		var existingID int64
		if err := a.db.QueryRow("SELECT id FROM attendance_events WHERE event_id=? AND organization_id=?", in.EventID, org).Scan(&existingID); err == nil {
			return existingID, status, false, nil
		}
	}
	r, err := a.db.Exec("INSERT OR IGNORE INTO attendance_events(organization_id,user_id,device_id,event_id,event_type,timestamp,verification_method,attendance_status) VALUES(?,?,?,?,?,?,?,?)", org, in.UserID, deviceID, nullIfEmpty(in.EventID), in.Event, t.UTC().Format(time.RFC3339), in.Method, status)
	if err != nil {
		return 0, "", false, err
	}
	id, _ := r.LastInsertId()
	created := id > 0
	if !created {
		if in.EventID != "" {
			_ = a.db.QueryRow("SELECT id FROM attendance_events WHERE event_id=? AND organization_id=?", in.EventID, org).Scan(&id)
		}
		if id == 0 {
			_ = a.db.QueryRow("SELECT id FROM attendance_events WHERE organization_id=? AND user_id=? AND device_id=? AND timestamp=? AND event_type=?", org, in.UserID, deviceID, t.UTC().Format(time.RFC3339), in.Event).Scan(&id)
		}
	}
	if id > 0 {
		a.queueSMS(org, int(id), in.UserID, in.Event)
	}
	return id, status, created, nil
}
func (a *app) eventStatus(org int, event string, t time.Time) string {
	if event != "clock_in" {
		return "on_time"
	}
	var hours string
	var threshold int
	if a.db.QueryRow("SELECT working_hours,late_threshold_minutes FROM attendance_rules WHERE organization_id=?", org).Scan(&hours, &threshold) != nil {
		return "on_time"
	}
	var h struct {
		Start string `json:"start"`
	}
	_ = json.Unmarshal([]byte(hours), &h)
	p := strings.Split(h.Start, ":")
	if len(p) != 2 {
		return "on_time"
	}
	hh, _ := strconv.Atoi(p[0])
	mm, _ := strconv.Atoi(p[1])
	start := time.Date(t.Year(), t.Month(), t.Day(), hh, mm, 0, 0, t.Location()).Add(time.Duration(threshold) * time.Minute)
	if t.After(start) {
		return "late"
	}
	return "on_time"
}
func (a *app) dashboard(c *gin.Context) {
	claim := c.MustGet("claims").(claims)
	if claim.Role == "super_admin" {
		var organizations, devices, pending int
		a.db.QueryRow("SELECT count(*) FROM organizations").Scan(&organizations)
		a.db.QueryRow("SELECT count(*) FROM devices").Scan(&devices)
		a.db.QueryRow("SELECT count(*) FROM users WHERE must_change_password=1").Scan(&pending)
		rows, _ := a.db.Query("SELECT o.name,o.type,coalesce((SELECT full_name FROM users u WHERE u.organization_id=o.id AND u.role='org_admin' ORDER BY id LIMIT 1),'Not assigned'),(SELECT count(*) FROM devices d WHERE d.organization_id=o.id) FROM organizations o ORDER BY o.id DESC LIMIT 10")
		defer rows.Close()
		organizationsList := []gin.H{}
		for rows.Next() {
			var name, typ, admin string
			var count int
			rows.Scan(&name, &typ, &admin, &count)
			organizationsList = append(organizationsList, gin.H{"Name": name, "Type": typ, "Admin": admin, "Devices": count})
		}
		c.HTML(200, "dashboard.html", gin.H{"Title": "Platform dashboard", "IsStaff": true, "Organizations": organizations, "Devices": devices, "Pending": pending, "OrganizationList": organizationsList})
		return
	}
	org := a.org(c)
	today := time.Now().Format("2006-01-02")
	var present, late, online int
	a.db.QueryRow("SELECT count(DISTINCT user_id) FROM attendance_events WHERE organization_id=? AND timestamp LIKE ?", org, today+"%").Scan(&present)
	a.db.QueryRow("SELECT count(*) FROM attendance_events WHERE organization_id=? AND timestamp LIKE ? AND attendance_status='late'", org, today+"%").Scan(&late)
	a.db.QueryRow("SELECT count(*) FROM devices WHERE organization_id=? AND status='online'", org).Scan(&online)
	rows, _ := a.db.Query("SELECT u.full_name,e.event_type,e.timestamp,e.attendance_status FROM attendance_events e JOIN users u ON u.id=e.user_id WHERE e.organization_id=? ORDER BY e.id DESC LIMIT 10", org)
	defer rows.Close()
	events := []gin.H{}
	for rows.Next() {
		var n, ev, t, s string
		rows.Scan(&n, &ev, &t, &s)
		events = append(events, gin.H{"Name": n, "Event": ev, "Time": t, "Status": s})
	}
	c.HTML(200, "dashboard.html", gin.H{"Title": "Dashboard", "Present": present, "Late": late, "Online": online, "Events": events})
}
func (a *app) usersPage(c *gin.Context) {
	if c.MustGet("claims").(claims).Role == "super_admin" {
		c.Redirect(http.StatusFound, "/admin/organizations")
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	query := "SELECT id,full_name,email,phone,role,fingerprint_status,status FROM users WHERE organization_id=?"
	args := []any{a.org(c)}
	if q != "" {
		query += " AND (lower(full_name) LIKE ? OR lower(coalesce(email,'')) LIKE ?)"
		args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%")
	}
	query += " ORDER BY full_name"
	rows, _ := a.db.Query(query, args...)
	defer rows.Close()
	users := []gin.H{}
	for rows.Next() {
		var id int
		var n, e, p, r, f, s string
		rows.Scan(&id, &n, &e, &p, &r, &f, &s)
		users = append(users, gin.H{"ID": id, "Name": n, "Email": e, "Phone": p, "Role": r, "Fingerprint": f, "Status": s})
	}
	c.HTML(200, "users.html", gin.H{"Title": "Users", "Users": users, "Query": q, "Devices": a.orgDeviceList(c)})
}
func (a *app) newUserPage(c *gin.Context) {
	c.HTML(200, "user_form.html", gin.H{"Title": "Add person", "Devices": a.orgDeviceList(c), "Person": nil})
}
func (a *app) userPage(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.Status(404)
		return
	}
	var name, email, phone, role, fp, status, publicID string
	if a.db.QueryRow("SELECT full_name,coalesce(email,''),coalesce(phone,''),role,fingerprint_status,status,uuid FROM users WHERE id=? AND organization_id=?", id, a.org(c)).Scan(&name, &email, &phone, &role, &fp, &status, &publicID) != nil {
		c.Status(404)
		return
	}
	c.HTML(200, "user_form.html", gin.H{"Title": "Add fingerprint", "Devices": a.orgDeviceList(c), "Person": gin.H{"ID": id, "Name": name, "Email": email, "Phone": phone, "Role": role, "Fingerprint": fp, "Status": status, "UUID": publicID}})
}
func (a *app) orgDeviceList(c *gin.Context) []gin.H {
	rows, err := a.db.Query("SELECT id,name,status FROM devices WHERE organization_id=? ORDER BY name", a.org(c))
	if err != nil {
		return nil
	}
	defer rows.Close()
	online := a.hub.ConnectedIDs(a.org(c))
	items := []gin.H{}
	for rows.Next() {
		var id int
		var name, status string
		rows.Scan(&id, &name, &status)
		isOnline := online[id]
		if isOnline {
			status = "online"
		}
		items = append(items, gin.H{"ID": id, "Name": name, "Status": status, "Connected": isOnline})
	}
	return items
}
func (a *app) devicesPage(c *gin.Context) {
	if c.MustGet("claims").(claims).Role == "super_admin" {
		c.Redirect(http.StatusFound, "/admin/organizations")
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	query := "SELECT id,name,serial_number,status,coalesce(last_heartbeat,''),(SELECT count(*) FROM device_commands dc WHERE dc.device_id=devices.id AND dc.organization_id=devices.organization_id AND dc.status='pending') FROM devices WHERE organization_id=?"
	args := []any{a.org(c)}
	if q != "" {
		query += " AND (lower(name) LIKE ? OR lower(serial_number) LIKE ?)"
		args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%")
	}
	rows, _ := a.db.Query(query, args...)
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, p int
		var n, s, st, h string
		rows.Scan(&id, &n, &s, &st, &h, &p)
		if a.hub.Connected(id) {
			st = "online"
		}
		items = append(items, gin.H{"ID": id, "Name": n, "Serial": s, "Status": st, "Heartbeat": h, "Pending": p, "Online": a.hub.Connected(id)})
	}
	c.HTML(200, "devices.html", gin.H{"Title": "Devices", "Devices": items, "Query": q})
}
func (a *app) newDevicePage(c *gin.Context) {
	c.HTML(200, "device_form.html", gin.H{"Title": "Register device"})
}
func (a *app) cardsPage(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	query := "SELECT r.id,r.uid,coalesce(u.full_name,''),r.status,r.personalization_status,r.issue_date,coalesce(r.expiry_date,'') FROM rfid_cards r LEFT JOIN users u ON u.id=r.user_id WHERE r.organization_id=?"
	args := []any{a.org(c)}
	if q != "" {
		query += " AND (lower(r.uid) LIKE ? OR lower(coalesce(u.full_name,'')) LIKE ?)"
		args = append(args, "%"+strings.ToLower(q)+"%", "%"+strings.ToLower(q)+"%")
	}
	rows, _ := a.db.Query(query, args...)
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id int
		var uid, n, s, p, i, e string
		rows.Scan(&id, &uid, &n, &s, &p, &i, &e)
		items = append(items, gin.H{"ID": id, "UID": uid, "Name": n, "Status": s, "Personalization": p, "Issued": i, "Expiry": e})
	}
	c.HTML(200, "cards.html", gin.H{"Title": "RFID Cards", "Cards": items, "Query": q})
}
func (a *app) newCardPage(c *gin.Context) {
	rows, _ := a.db.Query("SELECT id,full_name FROM users WHERE organization_id=? AND status='active' ORDER BY full_name", a.org(c))
	defer rows.Close()
	users := []gin.H{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		users = append(users, gin.H{"ID": id, "Name": name})
	}
	c.HTML(200, "card_form.html", gin.H{"Title": "Issue RFID card", "Users": users})
}
func (a *app) attendancePage(c *gin.Context) {
	org := a.org(c)
	selected := c.Query("date")
	if selected == "" {
		selected = time.Now().Format("2006-01-02")
	}
	if _, err := time.Parse("2006-01-02", selected); err != nil {
		selected = time.Now().Format("2006-01-02")
	}
	q := "SELECT e.id,u.full_name,d.name,e.event_type,e.timestamp,e.verification_method,e.attendance_status FROM attendance_events e JOIN users u ON u.id=e.user_id JOIN devices d ON d.id=e.device_id WHERE e.organization_id=? AND e.timestamp LIKE ?"
	args := []any{org, selected + "%"}
	if userID := c.Query("user_id"); userID != "" {
		q += " AND e.user_id=?"
		args = append(args, userID)
	}
	if term := strings.TrimSpace(c.Query("q")); term != "" {
		q += " AND lower(u.full_name) LIKE ?"
		args = append(args, "%"+strings.ToLower(term)+"%")
	}
	q += " ORDER BY e.timestamp DESC LIMIT 250"
	rows, _ := a.db.Query(q, args...)
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id int
		var u, d, e, t, m, s string
		rows.Scan(&id, &u, &d, &e, &t, &m, &s)
		items = append(items, gin.H{"ID": id, "User": u, "Device": d, "Event": e, "Time": t, "Method": m, "Status": s})
	}
	absent := []gin.H{}
	absentRows, _ := a.db.Query("SELECT id,full_name,coalesce(email,'') FROM users u WHERE organization_id=? AND status='active' AND NOT EXISTS (SELECT 1 FROM attendance_events e WHERE e.organization_id=u.organization_id AND e.user_id=u.id AND e.timestamp LIKE ?) ORDER BY full_name", org, selected+"%")
	defer absentRows.Close()
	for absentRows.Next() {
		var id int
		var name, email string
		absentRows.Scan(&id, &name, &email)
		absent = append(absent, gin.H{"ID": id, "Name": name, "Email": email})
	}
	base, _ := time.Parse("2006-01-02", selected)
	days := []gin.H{}
	for i := -3; i <= 3; i++ {
		d := base.AddDate(0, 0, i)
		var count int
		_ = a.db.QueryRow("SELECT count(DISTINCT user_id) FROM attendance_events WHERE organization_id=? AND timestamp LIKE ?", org, d.Format("2006-01-02")+"%").Scan(&count)
		days = append(days, gin.H{"Date": d.Format("2006-01-02"), "Label": d.Format("Mon, 02 Jan"), "Count": count, "Selected": d.Format("2006-01-02") == selected})
	}
	view := c.Query("view")
	if view == "absent" {
		items = []gin.H{}
	}
	c.HTML(200, "attendance.html", gin.H{"Title": "Attendance", "Events": items, "Absent": absent, "AbsentCount": len(absent), "Days": days, "SelectedDate": selected, "View": view, "Query": c.Query("q")})
}
func (a *app) devicesStatus(c *gin.Context) {
	rows, _ := a.db.Query("SELECT id,name,status,last_heartbeat FROM devices WHERE organization_id=?", a.org(c))
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int
		var n, s string
		var h sql.NullString
		rows.Scan(&id, &n, &s, &h)
		out = append(out, gin.H{"id": id, "name": n, "status": s, "last_heartbeat": h.String, "online": a.hub.Connected(id)})
	}
	c.JSON(200, gin.H{"devices": out})
}
func (a *app) report(c *gin.Context) {
	period := c.Param("period")
	if period != "daily" && period != "weekly" && period != "monthly" {
		c.JSON(400, gin.H{"error": "period must be daily, weekly or monthly"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=attendance-"+period+".csv")
	c.Data(200, "text/csv", []byte("user,event,timestamp,status\n"))
}
func (a *app) changePasswordPage(c *gin.Context) {
	c.HTML(http.StatusOK, "change_password.html", gin.H{"Error": ""})
}
func (a *app) changePassword(c *gin.Context) {
	var in struct {
		Password        string `form:"password" json:"password"`
		ConfirmPassword string `form:"confirm_password" json:"confirm_password"`
	}
	if c.ShouldBind(&in) != nil || len(in.Password) < 8 || in.Password != in.ConfirmPassword {
		c.HTML(http.StatusBadRequest, "change_password.html", gin.H{"Error": "Use a matching password with at least 8 characters."})
		return
	}
	x := c.MustGet("claims").(claims)
	_, err := a.db.Exec("UPDATE users SET password_hash=?,must_change_password=0,updated_at=? WHERE id=? AND organization_id=?", hash(in.Password), time.Now().UTC().Format(time.RFC3339), x.UserID, x.OrgID)
	if err != nil {
		c.HTML(500, "change_password.html", gin.H{"Error": "We could not update your password. Please try again."})
		return
	}
	_, _ = a.db.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id) VALUES(?,?,?,?,?)", x.OrgID, x.UserID, "change_password", "user", x.UserID)
	c.Redirect(http.StatusFound, "/dashboard")
}
func (a *app) provisionOrganization(c *gin.Context) {
	var in struct {
		Name       string `form:"name" json:"name"`
		Type       string `form:"type" json:"type"`
		Phone      string `form:"phone" json:"phone"`
		Location   string `form:"location" json:"location"`
		AdminName  string `form:"admin_name" json:"admin_name"`
		AdminEmail string `form:"admin_email" json:"admin_email"`
	}
	if c.ShouldBind(&in) != nil || strings.TrimSpace(in.Name) == "" || !validOrganizationType(in.Type) || strings.TrimSpace(in.AdminName) == "" || strings.TrimSpace(in.AdminEmail) == "" {
		a.provisionError(c, "name, valid type, admin_name and admin_email are required")
		return
	}
	var exists int
	_ = a.db.QueryRow("SELECT count(*) FROM users WHERE lower(email)=lower(?)", strings.TrimSpace(in.AdminEmail)).Scan(&exists)
	if exists > 0 {
		a.provisionError(c, "an account already uses this email address")
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		a.provisionError(c, "could not begin provisioning")
		return
	}
	defer tx.Rollback()
	settings, _ := json.Marshal(map[string]string{"phone": strings.TrimSpace(in.Phone), "location": strings.TrimSpace(in.Location)})
	r, err := tx.Exec("INSERT INTO organizations(name,type,settings_json) VALUES(?,?,?)", strings.TrimSpace(in.Name), in.Type, string(settings))
	if err != nil {
		a.provisionError(c, "could not create organization")
		return
	}
	org, _ := r.LastInsertId()
	temporaryPassword := randomPassword()
	r, err = tx.Exec("INSERT INTO users(organization_id,full_name,email,password_hash,role,must_change_password,uuid) VALUES(?,?,?,?,?,1,?)", org, strings.TrimSpace(in.AdminName), strings.TrimSpace(in.AdminEmail), hash(temporaryPassword), "org_admin", uuid.NewString())
	if err != nil {
		a.provisionError(c, "could not create admin account")
		return
	}
	userID, _ := r.LastInsertId()
	if _, err = tx.Exec("INSERT INTO attendance_rules(organization_id) VALUES(?)", org); err != nil {
		a.provisionError(c, "could not configure organization")
		return
	}
	staff := c.MustGet("claims").(claims)
	_, _ = tx.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id,after_json) VALUES(?,?,?,?,?,?)", org, staff.UserID, "provision", "organization", org, fmt.Sprintf(`{"initial_admin_id":%d}`, userID))
	if err = tx.Commit(); err != nil {
		a.provisionError(c, "could not finish provisioning")
		return
	}
	if wantsHTML(c) {
		c.HTML(201, "provisioned.html", gin.H{"Title": "Organisation provisioned", "OrganizationID": org, "AdminName": in.AdminName, "AdminEmail": in.AdminEmail, "TemporaryPassword": temporaryPassword})
		return
	}
	c.JSON(201, gin.H{"organization_id": org, "initial_admin_id": userID, "initial_password": temporaryPassword, "must_change_password": true, "warning": "Provide the temporary password to the customer securely. It is shown only once."})
}
func (a *app) provisionDevice(c *gin.Context) {
	orgID, err := strconv.Atoi(c.Param("orgId"))
	if err != nil || orgID < 1 {
		c.JSON(400, gin.H{"error": "invalid organization id"})
		return
	}
	var in struct {
		Name         string `form:"name" json:"name"`
		SerialNumber string `form:"serial_number" json:"serial_number"`
		MACAddress   string `form:"mac_address" json:"mac_address"`
		Location     string `form:"location" json:"location"`
	}
	if c.ShouldBind(&in) != nil || strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.MACAddress) == "" {
		c.JSON(400, gin.H{"error": "name and mac_address are required"})
		return
	}
	var found int
	if a.db.QueryRow("SELECT count(*) FROM organizations WHERE id=?", orgID).Scan(&found) != nil || found == 0 {
		c.JSON(404, gin.H{"error": "organization not found"})
		return
	}
	mac := strings.ToUpper(strings.TrimSpace(in.MACAddress))
	_, err = a.db.Exec(`INSERT INTO pending_device_enrollments(id,org_id,mac_address,device_name,location)
		VALUES(?,?,?,?,?)
		ON CONFLICT(mac_address) DO UPDATE SET org_id=excluded.org_id, device_name=excluded.device_name, location=excluded.location, created_at=CURRENT_TIMESTAMP`,
		uuid.NewString(), strconv.Itoa(orgID), mac, strings.TrimSpace(in.Name), strings.TrimSpace(in.Location))
	if err != nil {
		c.JSON(409, gin.H{"error": "device provisioning request failed: " + err.Error()})
		return
	}
	staff := c.MustGet("claims").(claims)
	_, _ = a.db.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id,after_json) VALUES(?,?,?,?,?,?)", orgID, staff.UserID, "provision_request", "device", nil, fmt.Sprintf(`{"name":%q,"mac_address":%q}`, strings.TrimSpace(in.Name), mac))
	if wantsHTML(c) {
		c.HTML(201, "device_provisioned.html", gin.H{"Title": "Device provisioning requested", "OrganizationID": orgID, "DeviceName": in.Name})
		return
	}
	c.JSON(201, gin.H{"status": "pending", "organization_id": orgID, "device_name": strings.TrimSpace(in.Name), "mac_address": mac, "message": "Power on the terminal. It will be provisioned automatically when it connects with this MAC."})
}
func wantsHTML(c *gin.Context) bool {
	return strings.Contains(c.GetHeader("Accept"), "text/html") || strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded")
}
func (a *app) provisionError(c *gin.Context, message string) {
	if wantsHTML(c) {
		c.HTML(http.StatusBadRequest, "organization_form.html", gin.H{"Title": "Provision organisation", "Error": message})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": message})
}
func (a *app) organizationsPage(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	query := "SELECT o.id,o.name,o.type,o.status,coalesce((SELECT full_name FROM users u WHERE u.organization_id=o.id AND u.role='org_admin' ORDER BY id LIMIT 1),''),(SELECT count(*) FROM devices d WHERE d.organization_id=o.id) FROM organizations o"
	args := []any{}
	if q != "" {
		query += " WHERE lower(o.name) LIKE ?"
		args = append(args, "%"+strings.ToLower(q)+"%")
	}
	query += " ORDER BY o.id DESC"
	rows, err := a.db.Query(query, args...)
	if err != nil {
		c.HTML(500, "organizations.html", gin.H{"Title": "Organisations", "Error": "Could not load organisations."})
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, devices int
		var name, typ, status, admin string
		rows.Scan(&id, &name, &typ, &status, &admin, &devices)
		items = append(items, gin.H{"ID": id, "Name": name, "Type": typ, "Status": status, "Admin": admin, "Devices": devices})
	}
	c.HTML(200, "organizations.html", gin.H{"Title": "Organisations", "Organizations": items, "Query": q})
}
func (a *app) newOrganizationPage(c *gin.Context) {
	c.HTML(200, "organization_form.html", gin.H{"Title": "Provision organisation", "Error": ""})
}
func (a *app) editOrganizationPage(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("orgId"))
	if err != nil {
		c.Status(404)
		return
	}
	var name, typ, settings, status string
	if a.db.QueryRow("SELECT name,type,settings_json,status FROM organizations WHERE id=?", id).Scan(&name, &typ, &settings, &status) != nil {
		c.Status(404)
		return
	}
	var profile map[string]string
	_ = json.Unmarshal([]byte(settings), &profile)
	c.HTML(200, "organization_edit.html", gin.H{"Title": "Edit organisation", "ID": id, "Name": name, "Type": typ, "Phone": profile["phone"], "Location": profile["location"], "Status": status})
}
func (a *app) updateOrganization(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("orgId"))
	if err != nil {
		c.Status(404)
		return
	}
	var in struct {
		Name     string `form:"name"`
		Type     string `form:"type"`
		Phone    string `form:"phone"`
		Location string `form:"location"`
		Status   string `form:"status"`
	}
	if c.ShouldBind(&in) != nil || strings.TrimSpace(in.Name) == "" || !validOrganizationType(in.Type) || (in.Status != "active" && in.Status != "inactive") {
		c.HTML(400, "organization_edit.html", gin.H{"Title": "Edit organisation", "ID": id, "Error": "Enter a name, valid type, and status."})
		return
	}
	settings, _ := json.Marshal(map[string]string{"phone": strings.TrimSpace(in.Phone), "location": strings.TrimSpace(in.Location)})
	r, err := a.db.Exec("UPDATE organizations SET name=?,type=?,settings_json=?,status=? WHERE id=?", strings.TrimSpace(in.Name), in.Type, string(settings), in.Status, id)
	n, _ := r.RowsAffected()
	if err != nil || n == 0 {
		c.Status(404)
		return
	}
	staff := c.MustGet("claims").(claims)
	_, _ = a.db.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id) VALUES(?,?,?,?,?)", id, staff.UserID, "update", "organization", id)
	c.Redirect(http.StatusFound, "/admin/organizations")
}
func (a *app) deactivateOrganization(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("orgId"))
	if err != nil {
		c.Status(404)
		return
	}
	r, err := a.db.Exec("UPDATE organizations SET status='inactive' WHERE id=?", id)
	n, _ := r.RowsAffected()
	if err != nil || n == 0 {
		c.Status(404)
		return
	}
	staff := c.MustGet("claims").(claims)
	_, _ = a.db.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id) VALUES(?,?,?,?,?)", id, staff.UserID, "deactivate", "organization", id)
	c.Redirect(http.StatusFound, "/admin/organizations")
}
func (a *app) platformProvisioningPage(c *gin.Context) {
	orgIDParam := c.Query("org_id")
	if orgIDParam == "" {
		orgIDParam = c.Param("orgId")
		if orgIDParam == "" {
			orgIDParam = c.Param("org_id")
		}
	}
	var orgID int
	var orgName string
	if orgIDParam != "" {
		orgID, _ = strconv.Atoi(orgIDParam)
		_ = a.db.QueryRow("SELECT name FROM organizations WHERE id=?", orgID).Scan(&orgName)
	}

	rows, err := a.db.Query("SELECT id, name FROM organizations WHERE status='active' ORDER BY id ASC")
	var orgs []gin.H
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var oID int
			var oName string
			_ = rows.Scan(&oID, &oName)
			orgs = append(orgs, gin.H{"ID": oID, "Name": oName, "Selected": oID == orgID})
			if orgID == 0 {
				orgID = oID
				orgName = oName
			}
		}
	}

	c.HTML(200, "provision_device_form.html", gin.H{
		"Title":            "Device provisioning",
		"OrganizationID":   orgID,
		"OrganizationName": orgName,
		"Organizations":    orgs,
		"Error":            "",
	})
}

func (a *app) registerPendingDevice(c *gin.Context) {
	var in struct {
		OrgID      any    `json:"org_id"`
		DeviceName string `json:"device_name"`
		MACAddress string `json:"mac_address"`
		Location   string `json:"location"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "invalid json payload: " + err.Error()})
		return
	}
	claims := c.MustGet("claims").(claims)
	orgIDStr := strings.TrimSpace(fmt.Sprintf("%v", in.OrgID))
	if claims.Role != "super_admin" {
		orgIDStr = strconv.Itoa(claims.OrgID)
	}
	mac, ok := normalizeMAC(in.MACAddress)
	devName := strings.TrimSpace(in.DeviceName)
	loc := strings.TrimSpace(in.Location)

	if !ok || devName == "" || orgIDStr == "" || orgIDStr == "<nil>" {
		c.JSON(400, gin.H{"error": "valid org_id, device_name, and MAC address are required"})
		return
	}

	id := uuid.NewString()
	_, err := a.db.Exec(`INSERT INTO pending_device_enrollments (id, org_id, mac_address, device_name, location)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(mac_address) DO UPDATE SET
			org_id=excluded.org_id,
			device_name=excluded.device_name,
			location=excluded.location,
			created_at=CURRENT_TIMESTAMP`,
		id, orgIDStr, mac, devName, loc)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to register pending device: " + err.Error()})
		return
	}

	c.JSON(201, gin.H{
		"status":      "pending",
		"id":          id,
		"org_id":      orgIDStr,
		"mac_address": mac,
		"device_name": devName,
		"location":    loc,
	})
}

func (a *app) enrollRequest(c *gin.Context) {
	devParam := c.Param("id")
	devParam = strings.TrimPrefix(devParam, "dev_")
	deviceID, err := strconv.Atoi(devParam)
	if err != nil || deviceID <= 0 {
		c.JSON(400, gin.H{"error": "invalid device_id"})
		return
	}

	var in struct {
		UserID         string `json:"user_id"`
		FingerIndex    int    `json:"finger_index"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := c.ShouldBindJSON(&in); err != nil || in.UserID == "" {
		c.JSON(400, gin.H{"error": "user_id is required"})
		return
	}

	if !a.hub.Connected(deviceID) {
		c.JSON(422, gin.H{"error": "Target device is offline"})
		return
	}

	var userID, orgID int
	var userUUID string
	if err := a.db.QueryRow("SELECT id, organization_id, uuid FROM users WHERE uuid=? OR id=CAST(? AS INTEGER) OR email=?", in.UserID, in.UserID, in.UserID).Scan(&userID, &orgID, &userUUID); err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	fingerIndex := in.FingerIndex
	if fingerIndex <= 0 {
		fingerIndex = 1
	}

	reqID, delivered, err := a.hub.StartEnrollmentWithParams(orgID, deviceID, userID, userUUID, fingerIndex, in.TimeoutSeconds)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(202, gin.H{
		"status":     "scanning",
		"request_id": reqID,
		"user_id":    userUUID,
		"device_id":  fmt.Sprintf("dev_%d", deviceID),
		"delivered":  delivered,
	})
}

func (a *app) organizationProfilePage(c *gin.Context) {
	orgParam := c.Param("org_id")
	if orgParam == "" {
		orgParam = c.Param("orgId")
	}
	orgID, err := strconv.Atoi(orgParam)
	if err != nil || orgID <= 0 {
		c.Status(404)
		return
	}

	var org struct {
		ID        int
		Name      string
		Type      string
		Status    string
		CreatedAt string
		Settings  string
	}
	if err := a.db.QueryRow("SELECT id, name, type, status, created_at, settings_json FROM organizations WHERE id=?", orgID).Scan(&org.ID, &org.Name, &org.Type, &org.Status, &org.CreatedAt, &org.Settings); err != nil {
		c.Status(404)
		return
	}

	var adminContact struct {
		Name  string
		Email string
		Phone string
	}
	_ = a.db.QueryRow("SELECT full_name, COALESCE(email,''), COALESCE(phone,'') FROM users WHERE organization_id=? AND role IN ('super_admin', 'org_admin') ORDER BY id LIMIT 1", orgID).Scan(&adminContact.Name, &adminContact.Email, &adminContact.Phone)
	if adminContact.Name == "" {
		_ = a.db.QueryRow("SELECT full_name, COALESCE(email,''), COALESCE(phone,'') FROM users WHERE organization_id=? ORDER BY id LIMIT 1", orgID).Scan(&adminContact.Name, &adminContact.Email, &adminContact.Phone)
	}

	var totalUsers int
	_ = a.db.QueryRow("SELECT count(*) FROM users WHERE organization_id=?", orgID).Scan(&totalUsers)

	rows, err := a.db.Query("SELECT id, name, COALESCE(mac_address, serial_number, ''), status, COALESCE(last_seen_at, last_heartbeat, ''), created_at FROM devices WHERE organization_id=? ORDER BY id DESC", orgID)
	var devicesList []gin.H
	var activeDevices, offlineDevices int
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dID int
			var dName, dMAC, dStatus, dLastSeen, dCreated string
			_ = rows.Scan(&dID, &dName, &dMAC, &dStatus, &dLastSeen, &dCreated)
			isOnline := a.hub.Connected(dID)
			if isOnline {
				activeDevices++
				dStatus = "online"
			} else {
				offlineDevices++
				if dStatus == "online" || dStatus == "active" {
					dStatus = "offline"
				}
			}
			devicesList = append(devicesList, gin.H{
				"ID":       dID,
				"DevID":    fmt.Sprintf("dev_%d", dID),
				"Name":     dName,
				"MAC":      dMAC,
				"Status":   dStatus,
				"IsOnline": isOnline,
				"LastSeen": dLastSeen,
				"Created":  dCreated,
			})
		}
	}

	type dayStat struct {
		Date  string `json:"date"`
		Label string `json:"label"`
		Count int    `json:"count"`
		Pct   int    `json:"pct"`
	}
	var activityHistory []dayStat
	dailyMap := map[string]int{}
	histRows, err := a.db.Query("SELECT substr(timestamp, 1, 10) as d, count(*) FROM attendance_events WHERE organization_id=? AND timestamp >= datetime('now', '-30 days') GROUP BY d", orgID)
	if err == nil {
		defer histRows.Close()
		for histRows.Next() {
			var d string
			var count int
			_ = histRows.Scan(&d, &count)
			dailyMap[d] = count
		}
	}
	now := time.Now()
	maxCount := 1
	var totalScans30Days int
	for i := 29; i >= 0; i-- {
		t := now.AddDate(0, 0, -i)
		ds := t.Format("2006-01-02")
		cnt := dailyMap[ds]
		totalScans30Days += cnt
		if cnt > maxCount {
			maxCount = cnt
		}
	}
	for i := 29; i >= 0; i-- {
		t := now.AddDate(0, 0, -i)
		ds := t.Format("2006-01-02")
		label := t.Format("Jan 02")
		cnt := dailyMap[ds]
		pct := (cnt * 100) / maxCount
		if cnt > 0 && pct < 8 {
			pct = 8
		}
		activityHistory = append(activityHistory, dayStat{
			Date:  ds,
			Label: label,
			Count: cnt,
			Pct:   pct,
		})
	}

	var profile map[string]string
	_ = json.Unmarshal([]byte(org.Settings), &profile)
	c.HTML(200, "organization_profile.html", gin.H{
		"Title":            org.Name + " · Platform Profile",
		"Org":              org,
		"Admin":            adminContact,
		"TotalUsers":       totalUsers,
		"TotalDevices":     len(devicesList),
		"ActiveDevices":    activeDevices,
		"OfflineDevices":   offlineDevices,
		"Devices":          devicesList,
		"Activity":         activityHistory,
		"TotalScans30Days": totalScans30Days,
		"MaxActivity":      maxCount,
		"OrgLogo":          profile["logo"],
		"OrgLocation":      profile["location"],
	})
}

func (a *app) uploadOrganizationLogo(c *gin.Context) {
	orgParam := c.Param("org_id")
	if orgParam == "" {
		orgParam = c.Param("orgId")
	}
	orgID, err := strconv.Atoi(orgParam)
	if err != nil || orgID <= 0 {
		c.Status(http.StatusNotFound)
		return
	}

	file, err := c.FormFile("logo")
	if err != nil || file.Size <= 0 || file.Size > 2*1024*1024 {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
		return
	}
	contentType := file.Header.Get("Content-Type")
	allowed := map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true, "image/svg+xml": true}
	if !allowed[contentType] {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
		return
	}

	ext := filepath.Ext(file.Filename)
	if ext == "" {
		ext = ".img"
	}
	path := fmt.Sprintf("web/static/uploads/org_%d%s", orgID, strings.ToLower(ext))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil || c.SaveUploadedFile(file, path) != nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
		return
	}

	var settings string
	if err := a.db.QueryRow("SELECT settings_json FROM organizations WHERE id=?", orgID).Scan(&settings); err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	profile := map[string]string{}
	_ = json.Unmarshal([]byte(settings), &profile)
	profile["logo"] = "/static/uploads/" + filepath.Base(path)
	encoded, _ := json.Marshal(profile)
	_, _ = a.db.Exec("UPDATE organizations SET settings_json=? WHERE id=?", string(encoded), orgID)
	c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
}

func (a *app) revokeDevice(c *gin.Context) {
	orgID, _ := strconv.Atoi(c.Param("org_id"))
	if orgID == 0 {
		orgID, _ = strconv.Atoi(c.Param("orgId"))
	}
	devID, _ := strconv.Atoi(c.Param("device_id"))
	if devID == 0 {
		devID, _ = strconv.Atoi(c.Param("deviceId"))
	}
	_, _ = a.db.Exec("UPDATE devices SET status='revoked', api_key='', api_key_hash='' WHERE id=? AND organization_id=?", devID, orgID)
	if wantsHTML(c) {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
		return
	}
	c.JSON(200, gin.H{"status": "revoked", "device_id": devID})
}

func (a *app) reprovisionDevice(c *gin.Context) {
	orgID, _ := strconv.Atoi(c.Param("org_id"))
	if orgID == 0 {
		orgID, _ = strconv.Atoi(c.Param("orgId"))
	}
	devID, _ := strconv.Atoi(c.Param("device_id"))
	if devID == 0 {
		devID, _ = strconv.Atoi(c.Param("deviceId"))
	}

	var dName, dMAC, dLoc string
	if err := a.db.QueryRow("SELECT name, COALESCE(mac_address, serial_number, ''), '' FROM devices WHERE id=? AND organization_id=?", devID, orgID).Scan(&dName, &dMAC, &dLoc); err == nil && dMAC != "" {
		_, _ = a.db.Exec("INSERT INTO pending_device_enrollments (id, org_id, mac_address, device_name, location) VALUES (?, ?, ?, ?, ?) ON CONFLICT(mac_address) DO UPDATE SET org_id=excluded.org_id, device_name=excluded.device_name", uuid.NewString(), strconv.Itoa(orgID), dMAC, dName, dLoc)
		_, _ = a.db.Exec("DELETE FROM devices WHERE id=? AND organization_id=?", devID, orgID)
	}

	if wantsHTML(c) {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/device-provisioning?org_id=%d", orgID))
		return
	}
	c.JSON(200, gin.H{"status": "reprovision_queued", "device_id": devID})
}

func (a *app) toggleOrgStatus(c *gin.Context) {
	orgID, _ := strconv.Atoi(c.Param("org_id"))
	if orgID == 0 {
		orgID, _ = strconv.Atoi(c.Param("orgId"))
	}
	var cur string
	_ = a.db.QueryRow("SELECT status FROM organizations WHERE id=?", orgID).Scan(&cur)
	next := "active"
	if cur == "active" {
		next = "inactive"
	}
	_, _ = a.db.Exec("UPDATE organizations SET status=? WHERE id=?", next, orgID)
	if wantsHTML(c) {
		c.Redirect(http.StatusFound, fmt.Sprintf("/platform/organisations/%d", orgID))
		return
	}
	c.JSON(200, gin.H{"status": next, "org_id": orgID})
}
func randomPassword() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 14)
	raw := make([]byte, len(b))
	_, _ = rand.Read(raw)
	for i := range b {
		b[i] = chars[int(raw[i])%len(chars)]
	}
	return string(b)
}
func (a *app) createUser(c *gin.Context) {
	var in struct {
		FullName string `form:"full_name" json:"full_name"`
		Email    string `form:"email" json:"email"`
		Phone    string `form:"phone" json:"phone"`
		Role     string `form:"role" json:"role"`
		BranchID int    `form:"branch_id" json:"branch_id"`
	}
	if c.ShouldBind(&in) != nil || in.FullName == "" {
		c.JSON(400, gin.H{"error": "full_name required"})
		return
	}
	if in.Role == "" {
		in.Role = "viewer"
	}
	var branchID any
	if in.BranchID > 0 {
		branchID = in.BranchID
	}
	publicID := uuid.NewString()
	r, e := a.db.Exec("INSERT INTO users(organization_id,branch_id,full_name,email,phone,role,uuid) VALUES(?,?,?,?,?,?,?)", a.org(c), branchID, in.FullName, in.Email, in.Phone, in.Role, publicID)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	id, _ := r.LastInsertId()
	a.audit(c, "create", "user", id, "", in)
	if strings.Contains(c.GetHeader("Accept"), "text/html") || strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded") {
		c.Redirect(http.StatusFound, fmt.Sprintf("/users/%d", id))
		return
	}
	c.JSON(201, gin.H{"id": id, "uuid": publicID, "fingerprint_status": "not_enrolled"})
}
func (a *app) updateUser(c *gin.Context) {
	if c.Query("_method") == "DELETE" {
		a.deleteUser(c)
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	var in struct {
		FullName          string `form:"full_name" json:"full_name"`
		Phone             string `form:"phone" json:"phone"`
		Role              string `form:"role" json:"role"`
		Status            string `form:"status" json:"status"`
		FingerprintStatus string `form:"fingerprint_status" json:"fingerprint_status"`
	}
	if c.ShouldBind(&in) != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	r, _ := a.db.Exec("UPDATE users SET full_name=?,phone=?,role=?,status=?,fingerprint_status=?,updated_at=? WHERE id=? AND organization_id=?", in.FullName, in.Phone, in.Role, in.Status, in.FingerprintStatus, time.Now().UTC().Format(time.RFC3339), id, a.org(c))
	n, _ := r.RowsAffected()
	if n == 0 {
		c.Status(404)
		return
	}
	a.audit(c, "update", "user", int64(id), "", in)
	if wantsHTML(c) {
		c.Redirect(http.StatusFound, "/users")
		return
	}
	c.Status(204)
}
func (a *app) deleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	r, _ := a.db.Exec("UPDATE users SET status='inactive' WHERE id=? AND organization_id=?", id, a.org(c))
	n, _ := r.RowsAffected()
	if n == 0 {
		c.Status(404)
		return
	}
	a.audit(c, "deactivate", "user", int64(id), "", nil)
	c.Status(204)
}
func (a *app) createDevice(c *gin.Context) {
	var in struct {
		Name   string `form:"name" json:"name"`
		Serial string `form:"serial" json:"serial"`
	}
	if c.ShouldBind(&in) != nil || in.Name == "" || in.Serial == "" {
		c.JSON(400, gin.H{"error": "name and serial required"})
		return
	}
	key := randomKey()
	r, e := a.db.Exec("INSERT INTO devices(organization_id,name,serial_number,api_key_hash) VALUES(?,?,?,?)", a.org(c), in.Name, in.Serial, hash(key))
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	id, _ := r.LastInsertId()
	a.audit(c, "create", "device", id, "", in)
	if strings.Contains(c.GetHeader("Accept"), "text/html") || strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded") {
		c.Redirect(http.StatusFound, "/devices")
		return
	}
	c.JSON(201, gin.H{"id": id, "api_key": key})
}
func (a *app) createCard(c *gin.Context) {
	var in struct {
		UserID     int    `form:"user_id" json:"user_id"`
		UID        string `form:"uid" json:"uid"`
		ExpiryDate string `form:"expiry_date" json:"expiry_date"`
	}
	if c.ShouldBind(&in) != nil || in.UID == "" {
		c.JSON(400, gin.H{"error": "uid required"})
		return
	}
	r, e := a.db.Exec("INSERT INTO rfid_cards(organization_id,user_id,uid,issue_date,expiry_date) VALUES(?,?,?,?,?)", a.org(c), in.UserID, in.UID, time.Now().Format("2006-01-02"), in.ExpiryDate)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	id, _ := r.LastInsertId()
	a.audit(c, "issue", "rfid_card", id, "", in)
	if strings.Contains(c.GetHeader("Accept"), "text/html") || strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded") {
		c.Redirect(http.StatusFound, "/rfid-cards")
		return
	}
	c.JSON(201, gin.H{"id": id})
}
func (a *app) updateCard(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var in struct{ Status, PersonalizationStatus string }
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	r, _ := a.db.Exec("UPDATE rfid_cards SET status=?,personalization_status=? WHERE id=? AND organization_id=?", in.Status, in.PersonalizationStatus, id, a.org(c))
	n, _ := r.RowsAffected()
	if n == 0 {
		c.Status(404)
		return
	}
	a.audit(c, "update", "rfid_card", int64(id), "", in)
	c.Status(204)
}
func (a *app) correctAttendance(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var in struct{ Status, Reason string }
	if c.ShouldBindJSON(&in) != nil || in.Status == "" {
		c.JSON(400, gin.H{"error": "status required"})
		return
	}
	r, _ := a.db.Exec("UPDATE attendance_events SET attendance_status=? WHERE id=? AND organization_id=?", in.Status, id, a.org(c))
	n, _ := r.RowsAffected()
	if n == 0 {
		c.Status(404)
		return
	}
	a.audit(c, "correct", "attendance_event", int64(id), "", in)
	c.Status(204)
}
func (a *app) createTemplate(c *gin.Context) {
	var in struct{ Name, Body, EventType string }
	if c.ShouldBindJSON(&in) != nil || in.Name == "" || in.Body == "" {
		c.JSON(400, gin.H{"error": "name and body required"})
		return
	}
	r, e := a.db.Exec("INSERT INTO sms_templates(organization_id,name,body,event_type) VALUES(?,?,?,?)", a.org(c), in.Name, in.Body, in.EventType)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	id, _ := r.LastInsertId()
	a.audit(c, "create", "sms_template", id, "", in)
	c.JSON(201, gin.H{"id": id})
}
func (a *app) audit(c *gin.Context, action, typ string, id int64, before string, after any) {
	x := c.MustGet("claims").(claims)
	b, _ := json.Marshal(after)
	_, _ = a.db.Exec("INSERT INTO audit_logs(organization_id,actor_user_id,action,entity_type,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?,?)", x.OrgID, x.UserID, action, typ, id, before, string(b))
}
func (a *app) queueSMS(org, eventID, userID int, event string) {
	var phone string
	if a.db.QueryRow("SELECT phone FROM users WHERE id=? AND organization_id=?", userID, org).Scan(&phone) != nil || phone == "" {
		return
	}
	body := "Attendance update: " + event
	_, _ = a.db.Exec("INSERT INTO sms_logs(organization_id,attendance_event_id,recipient_phone,body) VALUES(?,?,?,?)", org, eventID, phone, body)
}
func (a *app) smsWorker() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_, _ = a.db.Exec("UPDATE sms_logs SET status='sent',sent_at=? WHERE id IN (SELECT id FROM sms_logs WHERE status='queued' ORDER BY id LIMIT 20)", time.Now().UTC().Format(time.RFC3339))
	}
}

func (a *app) insertEventByUUID(orgID, deviceID int, eventID, userUUID, event, timestamp, method string) (int64, string, error) {
	var userID int
	if err := a.db.QueryRow("SELECT id FROM users WHERE uuid=? AND organization_id=? AND status='active'", userUUID, orgID).Scan(&userID); err != nil {
		return 0, "", fmt.Errorf("user not found in device organization")
	}
	id, status, _, err := a.insertEvent(orgID, deviceID, eventInput{UserID: userID, EventID: eventID, Event: event, Timestamp: timestamp, Method: method})
	return id, status, err
}

func (a *app) userStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "person not found"})
		return
	}
	var name, publicID, fp, status string
	if a.db.QueryRow("SELECT full_name,uuid,fingerprint_status,status FROM users WHERE id=? AND organization_id=?", id, a.org(c)).Scan(&name, &publicID, &fp, &status) != nil {
		c.JSON(404, gin.H{"error": "person not found"})
		return
	}
	c.JSON(200, gin.H{"id": id, "uuid": publicID, "full_name": name, "fingerprint_status": fp, "status": status})
}

func (a *app) startEnroll(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid person id"})
		return
	}
	org := a.org(c)
	var in struct {
		DeviceID int `form:"device_id" json:"device_id"`
	}
	_ = c.ShouldBind(&in)
	var publicID string
	if a.db.QueryRow("SELECT uuid FROM users WHERE id=? AND organization_id=?", id, org).Scan(&publicID) != nil {
		c.JSON(404, gin.H{"error": "person not found"})
		return
	}
	if in.DeviceID == 0 {
		for deviceID := range a.hub.ConnectedIDs(org) {
			if in.DeviceID != 0 {
				c.JSON(400, gin.H{"error": "select a device"})
				return
			}
			in.DeviceID = deviceID
		}
	}
	if in.DeviceID == 0 {
		c.JSON(400, gin.H{"error": "no online terminal. Power on a TAB5 and connect it, then try again."})
		return
	}
	var found int
	if a.db.QueryRow("SELECT count(*) FROM devices WHERE id=? AND organization_id=?", in.DeviceID, org).Scan(&found) != nil || found == 0 {
		c.JSON(404, gin.H{"error": "device not found"})
		return
	}
	requestID, delivered, err := a.hub.StartEnrollment(org, in.DeviceID, id, publicID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.audit(c, "enroll.start", "user", int64(id), "", gin.H{"device_id": in.DeviceID, "request_id": requestID})
	c.JSON(200, gin.H{"request_id": requestID, "user_id": publicID, "device_id": in.DeviceID, "delivered": delivered, "fingerprint_status": "pending"})
}
