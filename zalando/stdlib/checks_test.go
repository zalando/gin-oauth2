package stdlib

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	ginoauth2 "github.com/zalando/gin-oauth2"
	stdmw "github.com/zalando/gin-oauth2/stdlib"
	"github.com/zalando/gin-oauth2/zalando"
	"golang.org/x/oauth2"
)

func newTC(scopes map[string]any) *ginoauth2.TokenContainer {
	return &ginoauth2.TokenContainer{
		Token:     &oauth2.Token{AccessToken: "tok", TokenType: "Bearer"},
		Scopes:    scopes,
		GrantType: "password",
		Realm:     "/services",
	}
}

func newReq() *http.Request { return httptest.NewRequest("GET", "/", nil) }

func teamAPI(t *testing.T, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		assert.Equal(t, "marilyn", r.URL.Query().Get("member"))
		fmt.Fprint(w, body)
	}))
	old := zalando.TeamAPI
	zalando.TeamAPI = srv.URL
	t.Cleanup(func() { zalando.TeamAPI = old; srv.Close() })
}

func TestScopeCheck(t *testing.T) {
	tc := newTC(map[string]any{"my-scope-1": true, "my-scope-2": true, "uid": "marilyn"})

	r, ok := ScopeCheck("my-scope-1", "other")(tc, newReq())

	assert.True(t, ok)
	v, found := stdmw.Value[bool](r.Context(), "my-scope-1")
	assert.True(t, found)
	assert.True(t, v)
	_, found = stdmw.Value[bool](r.Context(), "my-scope-2")
	assert.False(t, found)
	uid, _ := stdmw.Value[string](r.Context(), "uid")
	assert.Equal(t, "marilyn", uid)

	_, ok = ScopeCheck("nope")(tc, newReq())
	assert.False(t, ok)
}

func TestScopeAndCheck(t *testing.T) {
	tc := newTC(map[string]any{"my-scope-1": true, "my-scope-2": true, "uid": "marilyn"})

	r, ok := ScopeAndCheck("uid", "my-scope-2")(tc, newReq())

	assert.True(t, ok)
	uid, _ := stdmw.Value[string](r.Context(), "uid")
	assert.Equal(t, "marilyn", uid)
	v, found := stdmw.Value[bool](r.Context(), "my-scope-2")
	assert.True(t, found)
	assert.True(t, v)

	_, ok = ScopeAndCheck("my-scope-1", "missing")(tc, newReq())
	assert.False(t, ok)
}

func TestUidCheck(t *testing.T) {
	at := []zalando.AccessTuple{{Realm: "/services", Uid: "marilyn", Cn: "Marilyn"}}

	r, ok := UidCheck(at)(newTC(map[string]any{"uid": "marilyn"}), newReq())
	assert.True(t, ok)
	uid, _ := stdmw.Value[string](r.Context(), "uid")
	cn, _ := stdmw.Value[string](r.Context(), "cn")
	assert.Equal(t, "marilyn", uid)
	assert.Equal(t, "Marilyn", cn)

	_, ok = UidCheck(at)(newTC(map[string]any{"uid": "other"}), newReq())
	assert.False(t, ok)

	wrongRealm := newTC(map[string]any{"uid": "marilyn"})
	wrongRealm.Realm = "/employees"
	_, ok = UidCheck(at)(wrongRealm, newReq())
	assert.False(t, ok)

	_, ok = UidCheck(at)(newTC(map[string]any{}), newReq())
	assert.False(t, ok, "missing uid must not panic")
}

func TestGroupCheck(t *testing.T) {
	teamAPI(t, `[{"id":"teapot","type":"official"},{"id":"guild","type":"guild"}]`)
	tc := newTC(map[string]any{"uid": "marilyn"})

	r, ok := GroupCheck([]zalando.AccessTuple{{Uid: "teapot"}})(tc, newReq())
	assert.True(t, ok)
	uid, _ := stdmw.Value[string](r.Context(), "uid")
	team, _ := stdmw.Value[string](r.Context(), "team")
	assert.Equal(t, "marilyn", uid)
	assert.Equal(t, "teapot", team)

	_, ok = GroupCheck([]zalando.AccessTuple{{Uid: "other"}})(tc, newReq())
	assert.False(t, ok)

	_, ok = GroupCheck([]zalando.AccessTuple{{Uid: "teapot"}})(newTC(map[string]any{}), newReq())
	assert.False(t, ok, "missing uid must not panic")
}

func TestGroupCheckBadResponse(t *testing.T) {
	teamAPI(t, `not json`)
	_, ok := GroupCheck([]zalando.AccessTuple{{Uid: "teapot"}})(newTC(map[string]any{"uid": "marilyn"}), newReq())
	assert.False(t, ok)
}

func TestNoAuthorization(t *testing.T) {
	teamAPI(t, `[{"id":"teapot","type":"official"}]`)
	r, ok := NoAuthorization()(newTC(map[string]any{"uid": "marilyn"}), newReq())
	assert.True(t, ok)
	team, _ := stdmw.Value[string](r.Context(), "team")
	assert.Equal(t, "teapot", team)

	teamAPI(t, `[{"id":"guild","type":"guild"}]`)
	r, ok = NoAuthorization()(newTC(map[string]any{"uid": "marilyn"}), newReq())
	assert.True(t, ok)
	_, found := stdmw.Value[string](r.Context(), "team")
	assert.False(t, found)

	_, ok = NoAuthorization()(newTC(map[string]any{}), newReq())
	assert.False(t, ok)
}

func TestEndToEnd(t *testing.T) {
	teamAPI(t, `[{"id":"teapot","type":"official"}]`)
	info := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","grant_type":"password","realm":"/employees","expires_in":600,"scope":["uid"],"uid":"marilyn"}`, r.URL.Query().Get("access_token"))
	}))
	defer info.Close()

	h := stdmw.AuthChain(oauth2.Endpoint{TokenURL: info.URL},
		UidCheck([]zalando.AccessTuple{{Realm: "/nope", Uid: "x"}}),
		GroupCheck([]zalando.AccessTuple{{Uid: "teapot"}}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := stdmw.Value[string](r.Context(), "uid")
		team, _ := stdmw.Value[string](r.Context(), "team")
		fmt.Fprintf(w, "%s@%s", uid, team)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, 200, rec.Code)
	assert.Equal(t, "marilyn@teapot", rec.Body.String())
}
