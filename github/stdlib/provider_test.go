package stdlib

import (
	"fmt"
	"io"
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
)

type idp struct {
	*httptest.Server
	tokenCalls atomic.Int32
	userCalls  atomic.Int32
	failUser   atomic.Bool
	userJSON   atomic.Value
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	i := &idp{}
	i.userJSON.Store(`{"login":"marilyn","name":"Marilyn","url":"https://api.example/users/marilyn"}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		i.tokenCalls.Add(1)
		if r.FormValue("code") != "good-code" {
			http.Error(w, `{"error":"bad_verification_code"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"at","token_type":"bearer"}`)
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		i.userCalls.Add(1)
		if i.failUser.Load() || r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, i.userJSON.Load().(string))
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
		Scopes:       []string{"repo"},
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		Endpoint:     oauth2.Endpoint{AuthURL: i.URL + "/auth", TokenURL: i.URL + "/token"},
		APIBaseURL:   i.URL + "/api",
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
		u2, ok2 := ginstd.Value[AuthUser](r.Context(), "user")
		fmt.Fprintf(w, "%s|%s|%v|%v", u.Login, u.Name, ok, ok2 && u2 == u)
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

func (a *app) url() *url.URL {
	u, _ := url.Parse(a.URL)
	return u
}

func (a *app) get(t *testing.T, path string) (int, string, *http.Response) {
	t.Helper()
	resp, err := a.client.Get(a.URL + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp
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
	assert.Equal(t, "marilyn|Marilyn|true|true", body)
	assert.NotEmpty(t, resp.Cookies())
	assert.Equal(t, int32(1), i.tokenCalls.Load())
	assert.Equal(t, int32(1), i.userCalls.Load())

	code, body, _ = a.get(t, "/auth/")
	assert.Equal(t, 200, code)
	assert.Equal(t, "marilyn|Marilyn|true|true", body)
	assert.Equal(t, int32(1), i.tokenCalls.Load(), "no further provider calls")
	assert.Equal(t, int32(1), i.userCalls.Load())
}

func TestLoginPageAndCookie(t *testing.T) {
	i := newIDP(t)
	a := newApp(t, newProvider(t, i, nil))

	code, body, resp := a.get(t, "/login")
	assert.Equal(t, 200, code)
	assert.Contains(t, body, i.URL+"/auth?")
	assert.Contains(t, body, "client_id=cid")
	require.Len(t, resp.Cookies(), 1)
	c := resp.Cookies()[0]
	assert.Equal(t, "ginoauth_github", c.Name)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.False(t, c.Secure)

	b := newApp(t, newProvider(t, i, func(c *Config) { c.RedirectURL = "https://example.org/auth/" }))
	_, _, resp = b.get(t, "/login")
	require.Len(t, resp.Cookies(), 1)
	assert.True(t, resp.Cookies()[0].Secure)
}

func TestInvalidState(t *testing.T) {
	i := newIDP(t)

	a := newApp(t, newProvider(t, i, nil))
	code, _, _ := a.get(t, callback("x", "good-code"))
	assert.Equal(t, 401, code, "no session")

	code, _, _ = a.get(t, "/auth/")
	assert.Equal(t, 401, code, "no state at all")

	a.login(t)
	code, _, _ = a.get(t, "/auth/?code=good-code")
	assert.Equal(t, 401, code, "empty state")
	code, _, _ = a.get(t, callback("other", "good-code"))
	assert.Equal(t, 401, code, "wrong state")

	assert.Zero(t, i.tokenCalls.Load())
}

func TestStatesAreNotShared(t *testing.T) {
	i := newIDP(t)
	p := newProvider(t, i, nil)

	a, b := newApp(t, p), newApp(t, p)
	stateA := a.login(t)
	stateB := b.login(t)
	assert.NotEqual(t, stateA, stateB)

	code, _, _ := b.get(t, callback(stateA, "good-code"))
	assert.Equal(t, 401, code, "state of another session")
	code, _, _ = a.get(t, callback(stateA, "good-code"))
	assert.Equal(t, 200, code)
}

func TestProviderFailures(t *testing.T) {
	t.Run("bad code", func(t *testing.T) {
		i := newIDP(t)
		a := newApp(t, newProvider(t, i, nil))
		state := a.login(t)
		code, _, _ := a.get(t, callback(state, "bad-code"))
		assert.Equal(t, 400, code)
	})
	t.Run("user lookup failure", func(t *testing.T) {
		i := newIDP(t)
		i.failUser.Store(true)
		a := newApp(t, newProvider(t, i, nil))
		state := a.login(t)
		code, _, _ := a.get(t, callback(state, "good-code"))
		assert.Equal(t, 400, code)
		code, _, _ = a.get(t, "/auth/")
		assert.Equal(t, 401, code, "no session was created")
	})
}

func TestNilUserFields(t *testing.T) {
	i := newIDP(t)
	i.userJSON.Store(`{"login":"marilyn"}`)
	a := newApp(t, newProvider(t, i, nil))
	state := a.login(t)
	code, body, _ := a.get(t, callback(state, "good-code"))
	assert.Equal(t, 200, code)
	assert.Equal(t, "marilyn||true|true", body)
}

func TestTamperedAndForeignCookies(t *testing.T) {
	i := newIDP(t)
	p1 := newProvider(t, i, nil)
	a := newApp(t, p1)
	state := a.login(t)
	code, _, _ := a.get(t, callback(state, "good-code"))
	require.Equal(t, 200, code)
	cookies := a.jar.Cookies(a.url())
	require.Len(t, cookies, 1)

	other := newApp(t, newProvider(t, i, func(c *Config) { c.SessionKey = []byte("ffffffffffffffffffffffffffffffff") }))
	other.jar.SetCookies(other.url(), cookies)
	code, _, _ = other.get(t, "/auth/")
	assert.Equal(t, 401, code, "signed with another key")

	tampered := newApp(t, p1)
	bad := *cookies[0]
	bad.Value = bad.Value[:len(bad.Value)-4] + "AAAA"
	tampered.jar.SetCookies(tampered.url(), []*http.Cookie{&bad})
	code, _, _ = tampered.get(t, "/auth/")
	assert.Equal(t, 401, code, "modified cookie")

	same := newApp(t, newProvider(t, i, nil))
	same.jar.SetCookies(same.url(), cookies)
	code, body, _ := same.get(t, "/auth/")
	assert.Equal(t, 200, code, "same key")
	assert.Contains(t, body, "marilyn")
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
		"no key":       func(c *Config) { c.SessionKey = nil },
		"no client id": func(c *Config) { c.ClientID = "" },
		"bad redirect": func(c *Config) { c.RedirectURL = "not a url" },
		"bad api url":  func(c *Config) { c.APIBaseURL = "http://[::1" },
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

	p, err := NewFromFile("http://x/auth/", f, []string{"repo"}, []byte("k"))
	require.NoError(t, err)
	assert.Equal(t, "cid", p.conf.ClientID)
	assert.Equal(t, "sec", p.conf.ClientSecret)

	_, err = NewFromFile("http://x/auth/", filepath.Join(dir, "missing.json"), nil, []byte("k"))
	assert.Error(t, err)

	require.NoError(t, os.WriteFile(f, []byte(`{`), 0o600))
	_, err = NewFromFile("http://x/auth/", f, nil, []byte("k"))
	assert.Error(t, err)
}
