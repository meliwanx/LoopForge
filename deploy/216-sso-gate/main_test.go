package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOrigin   = "http://120.26.208.161:5270"
	testSecret   = "test-system-secret-0123456789"
	testIdentity = "test-identity-secret-0123456789abcdef"
)

type fakeSSO struct {
	mu      sync.Mutex
	tickets map[string]string // ticket -> job
	revoked map[string]bool
	srv     *httptest.Server
}

func newFakeSSO(t *testing.T) *fakeSSO {
	f := &fakeSSO{tickets: map[string]string{}, revoked: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts := r.Header.Get("X-System-Signature-Timestamp")
		mac := hmac.New(sha256.New, []byte(testSecret))
		mac.Write([]byte(ts))
		if r.Header.Get("X-System-Code") != "loopforge" || r.Header.Get("X-System-Signature") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/sso/verify":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			job, ok := f.tickets[body["ticket"]]
			delete(f.tickets, body["ticket"])
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
				"user": map[string]any{"user_id": 7, "job_number": job, "status": 1}, "sso_session_id": "sid-" + job}})
		case "/api/sso/session-status":
			var body struct {
				IDs []string `json:"session_ids"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			var revoked []string
			f.mu.Lock()
			for _, id := range body.IDs {
				if f.revoked[id] {
					revoked = append(revoked, id)
				}
			}
			f.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"revoked": revoked}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type seen struct {
	host, cookie, staff, staffID, secret, xff, path string
}

func setup(t *testing.T, allowed string) (*gate, *fakeSSO, *seen) {
	t.Helper()
	sso := newFakeSSO(t)
	got := &seen{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = seen{host: r.Host, cookie: r.Header.Get("Cookie"), staff: r.Header.Get("Staffname"), staffID: r.Header.Get("Staffid"),
			secret: r.Header.Get("X-AgentFlow-Gateway-Secret"), xff: r.Header.Get("X-Forwarded-For"), path: r.URL.RequestURI()}
		io.WriteString(w, "upstream ok")
	}))
	t.Cleanup(up.Close)
	file := filepath.Join(t.TempDir(), "allowed_jobs")
	os.WriteFile(file, []byte(allowed), 0o600)
	g, err := newGate(config{PublicOrigin: testOrigin, Upstream: up.URL, SSOBaseURL: sso.srv.URL, SystemCode: "loopforge",
		SystemSecret: []byte(testSecret), IdentitySecret: testIdentity, AllowedFile: file,
		SessionTTL: time.Hour, SessionMax: 24 * time.Hour, StateTTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	g.httpClient = sso.srv.Client()
	g.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return g, sso, got
}

func do(g *gate, method, target string, cookies []*http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, testOrigin+target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func cookieFrom(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

// login runs the whole SSO round trip for job and returns the gate session cookie (nil when refused).
func login(t *testing.T, g *gate, sso *fakeSSO, job, next string) (*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	w := do(g, "GET", loginPath+"?next="+url.QueryEscape(next), nil, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	if loc.Path != "/api/sso/federated-login" || q.Get("redirect_system") != "loopforge" || q.Get("redirect_uri") != testOrigin+callbackPath {
		t.Fatalf("bad SSO redirect %s", loc)
	}
	state := cookieFrom(w, stateCookie)
	sso.mu.Lock()
	sso.tickets["T-"+job] = job
	sso.mu.Unlock()
	w = do(g, "GET", callbackPath+"?ticket=T-"+job+"&state="+q.Get("callback_state"), []*http.Cookie{state}, nil)
	return cookieFrom(w, sessionCookie), w
}

func TestAnonymous(t *testing.T) {
	g, _, got := setup(t, "29556\n")
	w := do(g, "GET", "/projects?x=1", nil, map[string]string{"Sec-Fetch-Mode": "navigate"})
	if w.Code != http.StatusFound || w.Header().Get("Location") != loginPath+"?next="+url.QueryEscape("/projects?x=1") {
		t.Fatalf("navigation: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = do(g, "POST", "/api/auth/register", nil, map[string]string{"Staffname": "admin"})
	if w.Code != http.StatusUnauthorized || got.path != "" {
		t.Fatalf("anonymous API must not reach upstream: %d %q", w.Code, got.path)
	}
	w = do(g, "GET", "/", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("non-navigation GET: %d", w.Code)
	}
}

func TestHostMustMatch(t *testing.T) {
	g, _, _ := setup(t, "29556\n")
	r := httptest.NewRequest("GET", "http://evil.example/", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("got %d", w.Code)
	}
}

func TestLoginForwardsIdentityAndStripsForgery(t *testing.T) {
	g, sso, got := setup(t, "# team\n29556\n")
	sess, w := login(t, g, sso, "29556", "/projects?a=1")
	if sess == nil || w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/projects?a=1" {
		t.Fatalf("login failed: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = do(g, "POST", "/api/assistant/generations", []*http.Cookie{sess, {Name: "agentflow_user", Value: "lf"}}, map[string]string{
		"Staffname": "admin", "X-Staff-Name": "admin", "Staffid": "1", "X-AgentFlow-Gateway-Secret": "forged",
		"X-Forwarded-For": "1.2.3.4", "Origin": testOrigin})
	if w.Code != 200 {
		t.Fatalf("proxy: %d", w.Code)
	}
	if got.staff != "29556" || got.staffID != "29556" || got.secret != testIdentity || got.xff != "" {
		t.Fatalf("identity headers wrong: %+v", got)
	}
	if got.host != "120.26.208.161:5270" {
		t.Fatalf("Host must be preserved for LoopForge's Origin check, got %q", got.host)
	}
	if got.cookie != "agentflow_user=lf" {
		t.Fatalf("gate cookie must not reach LoopForge, got %q", got.cookie)
	}
}

func TestNotAllowlisted(t *testing.T) {
	g, sso, got := setup(t, "29556\n")
	sess, w := login(t, g, sso, "10001", "/")
	if sess != nil || w.Code != http.StatusForbidden || got.path != "" {
		t.Fatalf("expected 403 without session: %d", w.Code)
	}
}

func TestAllowlistRemovalRevokesSession(t *testing.T) {
	g, sso, _ := setup(t, "29556\n")
	sess, _ := login(t, g, sso, "29556", "/")
	os.WriteFile(g.allow.path, []byte("10001\n"), 0o600)
	future := time.Now().Add(2 * time.Hour)
	os.Chtimes(g.allow.path, future, future)
	g.allow.checked = time.Time{}
	if w := do(g, "GET", "/api/x", []*http.Cookie{sess}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("removed job must lose access, got %d", w.Code)
	}
}

func TestMissingAllowlistFailsClosed(t *testing.T) {
	g, sso, _ := setup(t, "29556\n")
	os.Remove(g.allow.path)
	if sess, w := login(t, g, sso, "29556", "/"); sess != nil || w.Code != http.StatusForbidden {
		t.Fatalf("expected deny, got %d", w.Code)
	}
}

func TestStateIsSingleUseAndBound(t *testing.T) {
	g, sso, _ := setup(t, "29556\n")
	w := do(g, "GET", loginPath, nil, nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	state := loc.Query().Get("callback_state")
	sso.tickets["T1"] = "29556"
	// no state cookie (login started in another browser)
	if w := do(g, "GET", callbackPath+"?ticket=T1&state="+state, nil, nil); w.Code != 400 {
		t.Fatalf("missing state cookie: %d", w.Code)
	}
	// the bound browser can still finish; a replay of the same state cannot
	sc := &http.Cookie{Name: stateCookie, Value: state}
	if w := do(g, "GET", callbackPath+"?ticket=T1&state="+state, []*http.Cookie{sc}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("bound callback: %d", w.Code)
	}
	sso.tickets["T2"] = "29556"
	if w := do(g, "GET", callbackPath+"?ticket=T2&state="+state, []*http.Cookie{sc}, nil); w.Code != 400 {
		t.Fatalf("state reuse must fail: %d", w.Code)
	}
}

func TestBadTicketRejected(t *testing.T) {
	g, _, _ := setup(t, "29556\n")
	w := do(g, "GET", loginPath, nil, nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	state := cookieFrom(w, stateCookie)
	w = do(g, "GET", callbackPath+"?ticket=nope&state="+loc.Query().Get("callback_state"), []*http.Cookie{state}, nil)
	if w.Code != 401 || cookieFrom(w, sessionCookie) != nil {
		t.Fatalf("bad ticket: %d", w.Code)
	}
}

func TestSSOLogoutElsewhereRevokes(t *testing.T) {
	g, sso, _ := setup(t, "29556\n")
	sess, _ := login(t, g, sso, "29556", "/")
	sso.revoked["sid-29556"] = true
	base := time.Now()
	g.now = func() time.Time { return base.Add(2 * time.Minute) }
	if w := do(g, "GET", "/api/x", []*http.Cookie{sess}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked SSO session must be logged out, got %d", w.Code)
	}
}

func TestLogout(t *testing.T) {
	g, sso, _ := setup(t, "29556\n")
	sess, _ := login(t, g, sso, "29556", "/")
	if w := do(g, "POST", logoutPath, []*http.Cookie{sess}, map[string]string{"Origin": "http://evil.example"}); w.Code != 403 {
		t.Fatalf("cross-origin logout: %d", w.Code)
	}
	w := do(g, "POST", logoutPath, []*http.Cookie{sess}, map[string]string{"Origin": testOrigin})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/api/sso/logout?redirect_path=%2F&redirect_system=loopforge") {
		t.Fatalf("logout: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do(g, "GET", "/api/x", []*http.Cookie{sess}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("session must be gone: %d", w.Code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/a?b=1": "/a?b=1", "//evil.com": "/", "https://evil.com": "/", "/\\evil": "/",
		"/_gate/login": "/", "/sso-callback?ticket=x": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIdentityHeaderMatching(t *testing.T) {
	for _, h := range []string{"Staffname", "STAFF_NAME", "x-staff-id", "X-Agentflow-Gateway-Secret", "X-Real-IP", "Forwarded"} {
		if !identityHeader(h) {
			t.Errorf("%s should be stripped", h)
		}
	}
	if identityHeader("Content-Type") {
		t.Error("Content-Type must pass")
	}
}
