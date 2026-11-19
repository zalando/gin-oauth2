package stdlib

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "google.golang.org/api/oauth2/v2"
)

// A session written by the gin provider (gin-contrib/sessions) is
// accepted by the net/http provider.
func TestAcceptsGinSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := []byte("0123456789abcdef0123456789abcdef")
	router := gin.New()
	router.Use(sessions.Sessions("ginoauth_google", cookie.NewStore(key)))
	router.GET("/issue", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(sessionID, goauth.Userinfo{Email: "gin@example.org"})
		require.NoError(t, s.Save())
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "/issue", nil))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)

	i := newIDP(t)
	a := newApp(t, newProvider(t, i, func(c *Config) { c.SessionKey = key }))
	a.jar.SetCookies(a.url2(), cookies)
	code, body, _ := a.get(t, "/auth/")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "gin@example.org")
}
