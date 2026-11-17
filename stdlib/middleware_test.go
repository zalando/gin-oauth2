package stdlib

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ginoauth2 "github.com/zalando/gin-oauth2"
	"golang.org/x/oauth2"
)

const tokenInfoOK = `{"access_token":"%s","token_type":"Bearer","grant_type":"password","realm":"/employees","expires_in":600,"scope":["uid","cn"],"uid":"sszuecs","cn":"Sandor"}`

func tokenInfoServer(t *testing.T, delay time.Duration, headerMode bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		var tok string
		if headerMode {
			_, tok, _ = cutBearer(r.Header.Get("Authorization"))
		} else {
			tok = r.URL.Query().Get("access_token")
		}
		if tok == "bad" || tok == "" {
			fmt.Fprint(w, `{"error":"invalid_request","error_description":"Access Token not valid"}`)
			return
		}
		fmt.Fprintf(w, tokenInfoOK, tok)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cutBearer(h string) (string, string, bool) {
	for i := 0; i < len(h); i++ {
		if h[i] == ' ' {
			return h[:i], h[i+1:], true
		}
	}
	return "", "", false
}

func allow(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
	return WithValue(r, "uid", tc.Scopes["uid"]), true
}

func deny(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
	return r, false
}

type fixture struct {
	called *atomic.Int32
	next   http.Handler
}

func newFixture() *fixture {
	f := &fixture{called: &atomic.Int32{}}
	f.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.called.Add(1)
		uid, _ := Value[string](r.Context(), "uid")
		tc, ok := TokenContainerFromContext(r.Context())
		fmt.Fprintf(w, "uid=%s tc=%v", uid, ok && tc.Realm == "/employees")
	})
	return f
}

func do(h http.Handler, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/api/private", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthChainOptions(t *testing.T) {
	old := ginoauth2.VarianceTimer
	t.Cleanup(func() { ginoauth2.VarianceTimer = old })
	ginoauth2.VarianceTimer = 2 * time.Second

	for _, headerMode := range []bool{false, true} {
		srv := tokenInfoServer(t, 0, headerMode)
		o := ginoauth2.Options{
			Endpoint:            oauth2.Endpoint{AuthURL: "https://auth.example/token", TokenURL: srv.URL},
			AccessTokenInHeader: headerMode,
		}

		for _, tc := range []struct {
			name     string
			authz    string
			checks   []AccessCheckFunction
			status   int
			body     string
			location bool
			called   int32
		}{
			{name: "no header", checks: []AccessCheckFunction{allow}, status: 401, location: true},
			{name: "malformed header", authz: "Bearer", checks: []AccessCheckFunction{allow}, status: 401, location: true},
			{name: "tokeninfo error", authz: "Bearer bad", checks: []AccessCheckFunction{allow}, status: 401, location: true},
			{name: "token type mismatch", authz: "Basic abc", checks: []AccessCheckFunction{allow}, status: 401, location: true},
			{name: "allowed", authz: "Bearer good", checks: []AccessCheckFunction{allow}, status: 200, body: "uid=sszuecs tc=true", called: 1},
			{name: "denied", authz: "Bearer good", checks: []AccessCheckFunction{deny}, status: 403},
			{name: "no checks", authz: "Bearer good", status: 403},
			{name: "chain fallthrough", authz: "Bearer good", checks: []AccessCheckFunction{deny, allow}, status: 200, body: "uid=sszuecs tc=true", called: 1},
			{name: "chain first wins", authz: "Bearer good", checks: []AccessCheckFunction{
				func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
					return WithValue(r, "uid", "first"), true
				}, allow}, status: 200, body: "uid=first tc=true", called: 1},
		} {
			t.Run(fmt.Sprintf("header=%v/%s", headerMode, tc.name), func(t *testing.T) {
				f := newFixture()
				rec := do(AuthChainOptions(o, tc.checks...)(f.next), tc.authz)

				assert.Equal(t, tc.status, rec.Code)
				if tc.body != "" {
					assert.Equal(t, tc.body, rec.Body.String())
				}
				if tc.location {
					assert.Equal(t, "https://auth.example/token", rec.Header().Get("Location"))
				} else {
					assert.Empty(t, rec.Header().Get("Location"))
				}
				assert.Equal(t, tc.called, f.called.Load())
			})
		}
	}
}

func TestAuthAndAuthChain(t *testing.T) {
	srv := tokenInfoServer(t, 0, false)
	ep := oauth2.Endpoint{AuthURL: "a", TokenURL: srv.URL}

	for _, mw := range []Middleware{Auth(allow, ep), AuthChain(ep, deny, allow)} {
		rec := do(mw(newFixture().next), "Bearer good")
		assert.Equal(t, 200, rec.Code)
	}
	assert.Equal(t, 403, do(Auth(deny, ep)(newFixture().next), "Bearer good").Code)
}

func TestTimeout(t *testing.T) {
	old := ginoauth2.VarianceTimer
	t.Cleanup(func() { ginoauth2.VarianceTimer = old })
	ginoauth2.VarianceTimer = 50 * time.Millisecond

	srv := tokenInfoServer(t, 500*time.Millisecond, false)
	f := newFixture()
	h := Auth(allow, oauth2.Endpoint{AuthURL: "a", TokenURL: srv.URL})(f.next)

	start := time.Now()
	rec := do(h, "Bearer good")

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Less(t, time.Since(start), 400*time.Millisecond)
	assert.Zero(t, f.called.Load())
}

func TestHandlerNotBoundToTimeout(t *testing.T) {
	old := ginoauth2.VarianceTimer
	t.Cleanup(func() { ginoauth2.VarianceTimer = old })
	ginoauth2.VarianceTimer = 100 * time.Millisecond

	srv := tokenInfoServer(t, 0, false)
	h := Auth(allow, oauth2.Endpoint{AuthURL: "a", TokenURL: srv.URL})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		assert.NoError(t, r.Context().Err())
		w.WriteHeader(http.StatusNoContent)
	}))
	assert.Equal(t, http.StatusNoContent, do(h, "Bearer good").Code)
}

func TestContextHelpers(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	_, ok := TokenContainerFromContext(r.Context())
	assert.False(t, ok)

	r = WithValues(r, map[string]any{"a": "x", "b": 1})
	a, ok := Value[string](r.Context(), "a")
	require.True(t, ok)
	assert.Equal(t, "x", a)
	_, ok = Value[int](r.Context(), "a")
	assert.False(t, ok)
	_, ok = Value[string](r.Context(), "missing")
	assert.False(t, ok)
	assert.Same(t, r, WithValues(r, nil))
}
