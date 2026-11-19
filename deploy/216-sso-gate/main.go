// LoopForge 的企业 SSO 网关（216）。
//
// 跑在 platform 容器的网络命名空间里（compose network_mode: service:platform），
// 所以转发到 127.0.0.1:8080 时 LoopForge 看到的是回环地址，才会信任身份头。
// 未登录的页面请求跳企业 SSO；验票后按工号白名单放行，转发时带上
// Staffname/Staffid（工号）和与 LoopForge 共享的网关密钥。
// 浏览器自带的身份头、代理头一律删掉，不能伪造身份。
//
// 协议与 business-monitor/tools/sso-gate（Gatus 门禁）一致：
// federated-login → /sso-callback?ticket&state → 签名 POST /api/sso/verify；
// 每分钟调 /api/sso/session-status 跟随 SSO 单点登出。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "lf_gate"
	stateCookie   = "lf_gate_state"
	loginPath     = "/_gate/login"
	logoutPath    = "/_gate/logout"
	callbackPath  = "/sso-callback"
	maxEntries    = 10000

	ssoSessionCheckInterval = time.Minute
	allowlistCheckInterval  = 5 * time.Second
)

type config struct {
	PublicOrigin   string
	ListenAddr     string
	Upstream       string
	SSOBaseURL     string
	SystemCode     string
	SystemSecret   []byte
	IdentitySecret string
	AllowedFile    string
	SessionTTL     time.Duration // 滑动续期
	SessionMax     time.Duration // 自登录起的绝对上限
	StateTTL       time.Duration
}

type loginState struct {
	expires time.Time
	next    string
}

type session struct {
	job          string
	created      time.Time
	expires      time.Time
	ssoSID       string
	ssoCheckedAt time.Time
}

type allowlist struct {
	mu        sync.Mutex
	path      string
	checked   time.Time
	modTime   time.Time
	size      int64
	jobs      map[string]bool
	allowAll  bool
	loadError bool
}

// allowed 读白名单文件（每行一个工号，# 开头为注释，单独一行 * 表示所有 SSO 用户）。
// 文件改了自动生效，不用重启；读失败时拒绝所有人（fail closed）。
func (a *allowlist) allowed(job string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.checked) >= allowlistCheckInterval {
		a.checked = now
		a.reloadLocked()
	}
	if a.loadError || job == "" {
		return false
	}
	return a.allowAll || a.jobs[job]
}

func (a *allowlist) reloadLocked() {
	info, err := os.Stat(a.path)
	if err != nil {
		if !a.loadError {
			log.Printf("allowlist unreadable, denying everyone: %v", err)
		}
		a.loadError = true
		return
	}
	if !a.loadError && a.jobs != nil && info.ModTime().Equal(a.modTime) && info.Size() == a.size {
		return
	}
	f, err := os.Open(a.path)
	if err != nil {
		a.loadError = true
		return
	}
	defer f.Close()
	jobs := map[string]bool{}
	all := false
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "":
		case line == "*":
			all = true
		case safeASCII(line, 1, 64):
			jobs[line] = true
		}
	}
	if scanner.Err() != nil {
		a.loadError = true
		return
	}
	a.jobs, a.allowAll, a.loadError = jobs, all, false
	a.modTime, a.size = info.ModTime(), info.Size()
	log.Printf("allowlist loaded: %d job numbers, allow_all=%v", len(jobs), all)
}

type gate struct {
	cfg        config
	publicURL  *url.URL
	ssoURL     *url.URL
	upstream   *url.URL
	proxy      *httputil.ReverseProxy
	httpClient *http.Client
	allow      *allowlist
	now        func() time.Time

	mu       sync.Mutex
	states   map[string]loginState
	sessions map[string]session
}

func newGate(c config) (*gate, error) {
	pub, err := url.Parse(c.PublicOrigin)
	if err != nil || (pub.Scheme != "http" && pub.Scheme != "https") || pub.Host == "" || (pub.Path != "" && pub.Path != "/") || pub.RawQuery != "" {
		return nil, errors.New("GATE_PUBLIC_ORIGIN must be scheme://host[:port]")
	}
	pub.Path = ""
	sso, err := url.Parse(c.SSOBaseURL)
	if err != nil || sso.Scheme != "https" || sso.Host == "" {
		return nil, errors.New("SSO_BASE_URL must be an https origin")
	}
	up, err := url.Parse(c.Upstream)
	if err != nil || up.Scheme != "http" || up.Host == "" {
		return nil, errors.New("GATE_UPSTREAM must be http://host:port")
	}
	if c.SystemCode == "" || len(c.SystemSecret) < 16 {
		return nil, errors.New("SYSTEM_CODE and SYSTEM_SECRET (>=16 bytes) are required")
	}
	if len(c.IdentitySecret) < 24 {
		return nil, errors.New("GATE_IDENTITY_SECRET (>=24 chars) is required")
	}
	if c.AllowedFile == "" {
		return nil, errors.New("GATE_ALLOWED_JOBS_FILE is required")
	}
	if c.SessionTTL <= 0 || c.SessionMax < c.SessionTTL || c.StateTTL <= 0 {
		return nil, errors.New("invalid session/state TTL")
	}
	g := &gate{
		cfg: c, publicURL: pub, ssoURL: sso, upstream: up,
		httpClient: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		allow:      &allowlist{path: c.AllowedFile},
		now:        time.Now,
		states:     map[string]loginState{},
		sessions:   map[string]session{},
	}
	g.proxy = &httputil.ReverseProxy{
		// 不用 SetURL：它会把 Host 改成上游地址，而 LoopForge 要求 Origin 与 Host 一致。
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = up.Scheme
			pr.Out.URL.Host = up.Host
			pr.Out.Host = pr.In.Host
		},
		FlushInterval: -1, // SSE / 流式回复立即下发
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream error: %s %s: %v", r.Method, r.URL.Path, err)
			plainError(w, http.StatusBadGateway, "LoopForge 暂时不可用，请稍后重试")
		},
	}
	return g, nil
}

func safeASCII(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func cookieValue(r *http.Request, name string) string {
	var found string
	for _, c := range r.Cookies() {
		if c.Name == name {
			if found != "" {
				return "" // 重复同名 cookie 视为无效
			}
			found = c.Value
		}
	}
	return found
}

func (g *gate) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: g.publicURL.Scheme == "https", SameSite: http.SameSiteLaxMode})
}

func (g *gate) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: g.publicURL.Scheme == "https", SameSite: http.SameSiteLaxMode})
}

func plainError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, message+"\n")
}

func (g *gate) pruneLocked(now time.Time) {
	for k, v := range g.states {
		if !now.Before(v.expires) {
			delete(g.states, k)
		}
	}
	for k, v := range g.sessions {
		if !now.Before(v.expires) {
			delete(g.sessions, k)
		}
	}
}

func (g *gate) sign(req *http.Request) {
	ts := strconv.FormatInt(g.now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, g.cfg.SystemSecret)
	_, _ = mac.Write([]byte(ts))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-System-Code", g.cfg.SystemCode)
	req.Header.Set("X-System-Signature-Timestamp", ts)
	req.Header.Set("X-System-Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func (g *gate) ssoEndpoint(path string) string {
	u := url.URL{Scheme: g.ssoURL.Scheme, Host: g.ssoURL.Host, Path: path}
	return u.String()
}

func (g *gate) authenticated(r *http.Request) (string, session, bool) {
	token := cookieValue(r, sessionCookie)
	if token == "" {
		return "", session{}, false
	}
	now := g.now()
	g.mu.Lock()
	s, ok := g.sessions[token]
	if ok && (!now.Before(s.expires) || !now.Before(s.created.Add(g.cfg.SessionMax))) {
		delete(g.sessions, token)
		ok = false
	}
	g.mu.Unlock()
	if !ok || !g.allow.allowed(s.job, now) {
		return "", session{}, false
	}
	needCheck := s.ssoSID != "" && now.Sub(s.ssoCheckedAt) >= ssoSessionCheckInterval
	revoked := needCheck && g.ssoSessionRevoked(r.Context(), s.ssoSID)

	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok = g.sessions[token]
	if !ok || revoked {
		delete(g.sessions, token)
		return "", session{}, false
	}
	if needCheck {
		s.ssoCheckedAt = now
	}
	s.expires = now.Add(g.cfg.SessionTTL)
	g.sessions[token] = s
	return token, s, true
}

// SSO 单点登出：每个会话最多每分钟问一次 SSO；SSO 不通时放行，避免 SSO 故障把所有人踢下线。
func (g *gate) ssoSessionRevoked(ctx context.Context, sid string) bool {
	body, _ := json.Marshal(map[string][]string{"session_ids": {sid}})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.ssoEndpoint("/api/sso/session-status"), bytes.NewReader(body))
	if err != nil {
		return false
	}
	g.sign(req)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Printf("SSO session status check failed, allowing: %v", err)
		return false
	}
	defer resp.Body.Close()
	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			Revoked []string `json:"revoked"`
		} `json:"data"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&parsed) != nil || !parsed.Success {
		log.Printf("SSO session status check failed, allowing: HTTP %d", resp.StatusCode)
		return false
	}
	for _, id := range parsed.Data.Revoked {
		if id == sid {
			return true
		}
	}
	return false
}

func isPageNavigation(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// safeNext 只接受站内相对路径，防止登录后被带去外站。
func safeNext(raw string) string {
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\x00") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/_gate/") || u.Path == callbackPath {
		return "/"
	}
	return raw
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != g.publicURL.Host {
		plainError(w, http.StatusMisdirectedRequest, "Host not allowed")
		return
	}
	switch r.URL.Path {
	case loginPath:
		if r.Method != http.MethodGet {
			plainError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		g.login(w, r, safeNext(r.URL.Query().Get("next")))
		return
	case callbackPath:
		if r.Method != http.MethodGet {
			plainError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		g.callback(w, r)
		return
	case logoutPath:
		g.logout(w, r)
		return
	}
	token, s, ok := g.authenticated(r)
	if !ok {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isPageNavigation(r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, loginPath+"?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"请先通过企业 SSO 登录","login":"`+loginPath+`"}`+"\n")
		return
	}
	g.setCookie(w, sessionCookie, token, g.cfg.SessionTTL)
	g.forward(w, r, s)
}

// identityHeader 判断是否是 LoopForge 会读取的身份/代理头（大小写、-/_ 都不敏感）。
func identityHeader(name string) bool {
	n := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(name))
	switch n {
	case "staffname", "staffid", "xstaffname", "xstaffid", "xagentflowgatewaysecret",
		"xforwardedfor", "forwarded", "xrealip", "xforwardedhost", "xforwardedproto":
		return true
	}
	return false
}

func (g *gate) forward(w http.ResponseWriter, r *http.Request, s session) {
	for name := range r.Header {
		if identityHeader(name) {
			r.Header.Del(name)
		}
	}
	// 网关自己的 cookie 不交给 LoopForge。
	if cookies := r.Cookies(); len(cookies) > 0 {
		r.Header.Del("Cookie")
		var kept []string
		for _, c := range cookies {
			if c.Name != sessionCookie && c.Name != stateCookie {
				kept = append(kept, c.Name+"="+c.Value)
			}
		}
		if len(kept) > 0 {
			r.Header.Set("Cookie", strings.Join(kept, "; "))
		}
	}
	r.Header.Set("Staffname", s.job)
	if _, err := strconv.ParseInt(s.job, 10, 64); err == nil {
		r.Header.Set("Staffid", s.job)
	}
	r.Header.Set("X-AgentFlow-Gateway-Secret", g.cfg.IdentitySecret)
	g.proxy.ServeHTTP(w, r)
}

func (g *gate) login(w http.ResponseWriter, r *http.Request, next string) {
	state, err := randomToken()
	if err != nil {
		plainError(w, 503, "登录暂时不可用")
		return
	}
	g.mu.Lock()
	g.pruneLocked(g.now())
	if len(g.states) >= maxEntries {
		g.mu.Unlock()
		plainError(w, 503, "登录暂时不可用")
		return
	}
	g.states[state] = loginState{expires: g.now().Add(g.cfg.StateTTL), next: next}
	g.mu.Unlock()
	g.setCookie(w, stateCookie, state, g.cfg.StateTTL)
	u, _ := url.Parse(g.ssoEndpoint("/api/sso/federated-login"))
	u.RawQuery = url.Values{"redirect_system": {g.cfg.SystemCode}, "callback_state": {state},
		"redirect_path": {"/"}, "redirect_uri": {g.publicURL.String() + callbackPath}}.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

type ssoEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		User struct {
			JobNumber string `json:"job_number"`
			Status    int    `json:"status"`
		} `json:"user"`
		SSOSessionID string `json:"sso_session_id"`
	} `json:"data"`
}

func (g *gate) callback(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 || len(q["ticket"]) != 1 {
		plainError(w, 400, "登录回调参数无效，请重新登录")
		return
	}
	state, ticket := q.Get("state"), q.Get("ticket")
	cookie := cookieValue(r, stateCookie)
	if cookie == "" || !safeASCII(state, 43, 43) || subtle.ConstantTimeCompare([]byte(state), []byte(cookie)) != 1 || !safeASCII(ticket, 1, 200) {
		plainError(w, 400, "登录状态校验失败，请重新登录")
		return
	}
	g.mu.Lock()
	tx, ok := g.states[state]
	delete(g.states, state)
	if old := cookieValue(r, sessionCookie); old != "" {
		delete(g.sessions, old)
	}
	g.mu.Unlock()
	g.clearCookie(w, stateCookie)
	g.clearCookie(w, sessionCookie)
	if !ok || !g.now().Before(tx.expires) {
		plainError(w, 400, "登录已过期或已使用，请重新登录")
		return
	}
	body, _ := json.Marshal(map[string]string{"ticket": ticket})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.ssoEndpoint("/api/sso/verify"), bytes.NewReader(body))
	if err != nil {
		plainError(w, 502, "企业 SSO 暂时不可用")
		return
	}
	g.sign(req)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Printf("SSO verify failed: %v", err)
		plainError(w, 502, "企业 SSO 暂时不可用")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		plainError(w, 401, "企业 SSO 拒绝了这次登录，请重新登录")
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	var envelope ssoEnvelope
	if resp.StatusCode != 200 || err != nil || len(data) > 65536 || json.Unmarshal(data, &envelope) != nil {
		log.Printf("SSO verify failed: HTTP %d", resp.StatusCode)
		plainError(w, 502, "企业 SSO 暂时不可用")
		return
	}
	user := envelope.Data.User
	if !envelope.Success || user.Status != 1 || !safeASCII(user.JobNumber, 1, 64) {
		plainError(w, 401, "企业 SSO 拒绝了这次登录，请重新登录")
		return
	}
	if !g.allow.allowed(user.JobNumber, g.now()) {
		log.Printf("job %s not in allowlist", user.JobNumber)
		plainError(w, 403, "你的账号（工号 "+user.JobNumber+"）还没有开通 LoopForge，请联系管理员。")
		return
	}
	token, err := randomToken()
	if err != nil {
		plainError(w, 503, "登录暂时不可用")
		return
	}
	sid := envelope.Data.SSOSessionID
	if !safeASCII(sid, 1, 128) {
		sid = ""
	}
	now := g.now()
	g.mu.Lock()
	g.pruneLocked(now)
	if len(g.sessions) >= maxEntries {
		g.mu.Unlock()
		plainError(w, 503, "登录暂时不可用")
		return
	}
	g.sessions[token] = session{job: user.JobNumber, created: now, expires: now.Add(g.cfg.SessionTTL), ssoSID: sid, ssoCheckedAt: now}
	g.mu.Unlock()
	log.Printf("login ok: job %s", user.JobNumber)
	g.setCookie(w, sessionCookie, token, g.cfg.SessionTTL)
	http.Redirect(w, r, tx.next, http.StatusSeeOther) // 立刻去掉地址栏里的 ticket/state
}

func (g *gate) logout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self' "+g.ssoURL.Scheme+"://"+g.ssoURL.Host+"; frame-ancestors 'none'")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>退出 LoopForge</title><body style="font-family:sans-serif;padding:40px"><form method="post" action="`+logoutPath+`"><p>退出 LoopForge 和企业 SSO 登录？</p><button type="submit">退出登录</button></form></body></html>`)
		}
	case http.MethodPost:
		if r.Header.Get("Origin") != g.publicURL.String() {
			plainError(w, 403, "Origin not allowed")
			return
		}
		if token := cookieValue(r, sessionCookie); token != "" {
			g.mu.Lock()
			delete(g.sessions, token)
			g.mu.Unlock()
		}
		g.clearCookie(w, sessionCookie)
		// LoopForge 自己的登录 cookie 也一起清掉。
		http.SetCookie(w, &http.Cookie{Name: "agentflow_user", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
		u, _ := url.Parse(g.ssoEndpoint("/api/sso/logout"))
		u.RawQuery = url.Values{"redirect_system": {g.cfg.SystemCode}, "redirect_path": {"/"}}.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	default:
		plainError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// watchUpstream：本容器借用 platform 容器的网络。platform 重建后这里的网络会失效，
// 连续 1 分钟连不上上游就退出，让 Docker 重启本容器、重新加入新网络。
func (g *gate) watchUpstream() {
	client := &http.Client{Timeout: 3 * time.Second}
	failures := 0
	for range time.Tick(15 * time.Second) {
		resp, err := client.Get(g.upstream.String() + "/api/health")
		if err == nil {
			resp.Body.Close()
		}
		if err != nil || resp.StatusCode != 200 {
			failures++
			if failures >= 4 {
				log.Fatalf("upstream unhealthy for 60s, exiting so Docker restarts the gate")
			}
			continue
		}
		failures = 0
	}
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	return time.ParseDuration(v)
}

func configFromEnv() (config, error) {
	c := config{
		PublicOrigin:   os.Getenv("GATE_PUBLIC_ORIGIN"),
		ListenAddr:     os.Getenv("GATE_LISTEN_ADDR"),
		Upstream:       os.Getenv("GATE_UPSTREAM"),
		SSOBaseURL:     os.Getenv("SSO_BASE_URL"),
		SystemCode:     os.Getenv("SYSTEM_CODE"),
		SystemSecret:   []byte(os.Getenv("SYSTEM_SECRET")),
		IdentitySecret: os.Getenv("GATE_IDENTITY_SECRET"),
		AllowedFile:    os.Getenv("GATE_ALLOWED_JOBS_FILE"),
	}
	var err error
	if c.SessionTTL, err = durationEnv("GATE_SESSION_TTL", 12*time.Hour); err != nil {
		return c, err
	}
	if c.SessionMax, err = durationEnv("GATE_SESSION_MAX", 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.StateTTL, err = durationEnv("GATE_STATE_TTL", 5*time.Minute); err != nil {
		return c, err
	}
	if c.ListenAddr == "" {
		return c, errors.New("GATE_LISTEN_ADDR is required")
	}
	return c, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	c, err := configFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	g, err := newGate(c)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	go g.watchUpstream()
	srv := &http.Server{Addr: c.ListenAddr, Handler: g, ReadHeaderTimeout: 15 * time.Second, MaxHeaderBytes: 1 << 20}
	log.Printf("loopforge sso gate listening on %s for %s", c.ListenAddr, g.publicURL)
	fmt.Fprintln(os.Stderr, srv.ListenAndServe())
	os.Exit(1)
}
