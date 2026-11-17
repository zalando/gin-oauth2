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
)

// A session written by the gin provider (gin-contrib/sessions) is
// accepted by the net/http provider.
func TestAcceptsGinSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := []byte("0123456789abcdef0123456789abcdef")
	router := gin.New()
	router.Use(sessions.Sessions("ginoauth_github", cookie.NewStore(key)))
	router.GET("/issue", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(sessionID, AuthUser{Login: "ginuser", Name: "Gin"})
		require.NoError(t, s.Save())
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "/issue", nil))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)

	i := newIDP(t)
	a := newApp(t, newProvider(t, i, func(c *Config) { c.SessionKey = key }))
	a.jar.SetCookies(a.url(), cookies)
	code, body, _ := a.get(t, "/auth/")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "ginuser")
}
