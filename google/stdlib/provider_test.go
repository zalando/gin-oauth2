package stdlib

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ginstd "github.com/zalando/gin-oauth2/stdlib"
	"golang.org/x/oauth2"
	goauth "google.golang.org/api/oauth2/v2"
)

type idp struct {
	*httptest.Server
	tokenCalls    atomic.Int32
	userinfoCalls atomic.Int32
	failToken     atomic.Bool
	failUserinfo  atomic.Bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	i := &idp{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		i.tokenCalls.Add(1)
		if i.failToken.Load() || r.FormValue("code") != "good-code" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/oauth2/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		i.userinfoCalls.Add(1)
		if i.failUserinfo.Load() || r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"marilyn@example.org","name":"Marilyn","id":"42"}`)
	})
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Close)
	return i
}

func newProvider(t *testing.T, i *idp, mod func(*Config)) *Provider {
	t.Helper()
	c := Config{
		RedirectURL:  "http://127.0.0.1:8081/auth/",
		ClientID:     "cid",
		ClientSecret: "csecret",
		Scopes:       []string{"email"},
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		Endpoint:     oauth2.Endpoint{AuthURL: i.URL + "/auth", TokenURL: i.URL + "/token"},
		UserinfoURL:  i.URL,
	}
	if mod != nil {
		mod(&c)
	}
	p, err := New(c)
	require.NoError(t, err)
	return p
}

type app struct {
	*httptest.Server
	client *http.Client
	jar    *cookiejar.Jar
}

func newApp(t *testing.T, p *Provider) *app {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /login", p.LoginHandler())
	mux.Handle("GET /auth/", p.Auth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		u2, ok2 := ginstd.Value[goauth.Userinfo](r.Context(), "user")
		fmt.Fprintf(w, "%s %v %v", u.Email, ok, ok2 && u2.Email == u.Email)
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &app{
		Server: srv,
		jar:    jar,
		client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (a *app) get(t *testing.T, path string) (int, string, *http.Response) {
	t.Helper()
	resp, err := a.client.Get(a.URL + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	var b [4096]byte
	n, _ := resp.Body.Read(b[:])
	return resp.StatusCode, string(b[:n]), resp
}

var stateRe = regexp.MustCompile(`state=([^&'"]+)`)

func (a *app) login(t *testing.T) string {
	t.Helper()
	code, body, _ := a.get(t, "/login")
	require.Equal(t, 200, code)
	m := stateRe.FindStringSubmatch(body)
	require.Len(t, m, 2, body)
	state, err := url.QueryUnescape(m[1])
	require.NoError(t, err)
	return state
}

func callback(state, code string) string {
	return "/auth/?state=" + url.QueryEscape(state) + "&code=" + code
}

func TestLoginAndAuth(t *testing.T) {
	i := newIDP(t)
	a := newApp(t, newProvider(t, i, nil))

	state := a.login(t)
	code, body, resp := a.get(t, callback(state, "good-code"))
	assert.Equal(t, 200, code)
	assert.Equal(t, "marilyn@example.org true true", body)
	assert.NotEmpty(t, resp.Cookies())
	assert.Equal(t, int32(1), i.tokenCalls.Load())
	assert.Equal(t, int32(1), i.userinfoCalls.Load())

	// session cookie is enough, no further calls to the provider
	code, body, _ = a.get(t, "/auth/")
	assert.Equal(t, 200, code)
	assert.Equal(t, "marilyn@example.org true true", body)
	assert.Equal(t, int32(1), i.tokenCalls.Load())
	assert.Equal(t, int32(1), i.userinfoCalls.Load())
}

func TestLoginPageEscapesAndSetsCookie(t *testing.T) {
	i := newIDP(t)
	a := newApp(t, newProvider(t, i, nil))

	code, body, resp := a.get(t, "/login")
	assert.Equal(t, 200, code)
	assert.Contains(t, body, i.URL+"/auth?")
	assert.Contains(t, body, "client_id=cid")
	require.Len(t, resp.Cookies(), 1)
	c := resp.Cookies()[0]
	assert.Equal(t, "ginoauth_google", c.Name)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.False(t, c.Secure)
}

func TestSecureCookieForHTTPSRedirect(t *testing.T) {
	i := newIDP(t)
	a := newApp(t, newProvider(t, i, func(c *Config) { c.RedirectURL = "https://example.org/auth/" }))
	_, _, resp := a.get(t, "/login")
	require.Len(t, resp.Cookies(), 1)
	assert.True(t, resp.Cookies()[0].Secure)
}

func TestInvalidState(t *testing.T) {
	i := newIDP(t)

	t.Run("no session", func(t *testing.T) {
		a := newApp(t, newProvider(t, i, nil))
		code, _, _ := a.get(t, callback("x", "good-code"))
		assert.Equal(t, 401, code)
	})
	t.Run("empty state", func(t *testing.T) {
		a := newApp(t, newProvider(t, i, nil))
		a.login(t)
		code, _, _ := a.get(t, "/auth/?code=good-code")
		assert.Equal(t, 401, code)
	})
	t.Run("wrong state", func(t *testing.T) {
		a := newApp(t, newProvider(t, i, nil))
		a.login(t)
		code, _, _ := a.get(t, callback("other", "good-code"))
		assert.Equal(t, 401, code)
	})
	t.Run("redirect to login url", func(t *testing.T) {
		a := newApp(t, newProvider(t, i, func(c *Config) { c.LoginURL = "http://127.0.0.1:8081/login" }))
		code, _, resp := a.get(t, "/auth/")
		assert.Equal(t, 302, code)
		assert.Equal(t, "http://127.0.0.1:8081/login", resp.Header.Get("Location"))
	})
	assert.Zero(t, i.tokenCalls.Load())
}

func TestStateCanNotBeReplayed(t *testing.T) {
	i := newIDP(t)
	p := newProvider(t, i, nil)

	a := newApp(t, p)
	state := a.login(t)
	code, _, _ := a.get(t, callback(state, "good-code"))
	require.Equal(t, 200, code)

	// an attacker with the callback URL but another session is rejected
	b := newApp(t, p)
	b.login(t)
	code, _, _ = b.get(t, callback(state, "good-code"))
	assert.Equal(t, 401, code)

	// the state is consumed once the session is authenticated
	var sess = a.jar.Cookies(u2(a))
	require.Len(t, sess, 1)
	assert.Equal(t, int32(1), i.tokenCalls.Load())
}

func TestProviderFailures(t *testing.T) {
	t.Run("bad code", func(t *testing.T) {
		i := newIDP(t)
		a := newApp(t, newProvider(t, i, nil))
		state := a.login(t)
		code, _, _ := a.get(t, callback(state, "bad-code"))
		assert.Equal(t, 400, code)
	})
	t.Run("userinfo failure", func(t *testing.T) {
		i := newIDP(t)
		i.failUserinfo.Store(true)
		a := newApp(t, newProvider(t, i, nil))
		state := a.login(t)
		code, _, _ := a.get(t, callback(state, "good-code"))
		assert.Equal(t, 500, code)
		code, _, _ = a.get(t, "/auth/")
		assert.Equal(t, 401, code, "no session was created")
	})
}

func TestTamperedAndForeignCookies(t *testing.T) {
	i := newIDP(t)
	p1 := newProvider(t, i, nil)
	a := newApp(t, p1)
	state := a.login(t)
	code, _, _ := a.get(t, callback(state, "good-code"))
	require.Equal(t, 200, code)

	u, _ := url.Parse(a.URL)
	cookies := a.jar.Cookies(u)
	require.Len(t, cookies, 1)

	// cookie signed with another key
	p2 := newProvider(t, i, func(c *Config) { c.SessionKey = []byte("ffffffffffffffffffffffffffffffff") })
	b := newApp(t, p2)
	b.jar.SetCookies(u2(b), cookies)
	code, _, _ = b.get(t, "/auth/")
	assert.Equal(t, 401, code)

	// modified cookie
	c := newApp(t, p1)
	bad := *cookies[0]
	bad.Value = bad.Value[:len(bad.Value)-4] + "AAAA"
	c.jar.SetCookies(u2(c), []*http.Cookie{&bad})
	code, _, _ = c.get(t, "/auth/")
	assert.Equal(t, 401, code)

	// same key and cookie name is accepted by another instance
	d := newApp(t, newProvider(t, i, nil))
	d.jar.SetCookies(u2(d), cookies)
	code, body, _ := d.get(t, "/auth/")
	assert.Equal(t, 200, code)
	assert.Contains(t, body, "marilyn@example.org")
}

func u2(a *app) *url.URL {
	u, _ := url.Parse(a.URL)
	return u
}

func TestEncryptedSession(t *testing.T) {
	i := newIDP(t)
	a := newApp(t, newProvider(t, i, func(c *Config) { c.EncryptionKey = []byte("0123456789abcdef") }))
	state := a.login(t)
	code, _, _ := a.get(t, callback(state, "good-code"))
	assert.Equal(t, 200, code)
	code, _, _ = a.get(t, "/auth/")
	assert.Equal(t, 200, code)
}

func TestConcurrentSessions(t *testing.T) {
	i := newIDP(t)
	p := newProvider(t, i, nil)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := newApp(t, p)
			state := a.login(t)
			code, _, _ := a.get(t, callback(state, "good-code"))
			assert.Equal(t, 200, code)
		}()
	}
	wg.Wait()
}

func TestNewValidation(t *testing.T) {
	good := Config{RedirectURL: "http://x/auth/", ClientID: "c", SessionKey: []byte("k")}
	_, err := New(good)
	assert.NoError(t, err)

	for name, mod := range map[string]func(*Config){
		"no key":        func(c *Config) { c.SessionKey = nil },
		"no client id":  func(c *Config) { c.ClientID = "" },
		"bad redirect":  func(c *Config) { c.RedirectURL = "not a url" },
		"bad login url": func(c *Config) { c.LoginURL = "not a url" },
	} {
		c := good
		mod(&c)
		_, err := New(c)
		assert.Error(t, err, name)
	}
}

func TestNewFromFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cred.json")
	require.NoError(t, os.WriteFile(f, []byte(`{"clientid":"cid","secret":"sec"}`), 0o600))

	p, err := NewFromFile("http://x/auth/", f, []string{"email"}, []byte("k"))
	require.NoError(t, err)
	assert.Equal(t, "cid", p.conf.ClientID)
	assert.Equal(t, "sec", p.conf.ClientSecret)

	_, err = NewFromFile("http://x/auth/", filepath.Join(dir, "missing.json"), nil, []byte("k"))
	assert.Error(t, err)

	require.NoError(t, os.WriteFile(f, []byte(`{`), 0o600))
	_, err = NewFromFile("http://x/auth/", f, nil, []byte("k"))
	assert.Error(t, err)
}

func (a *app) url2() *url.URL { return u2(a) }
