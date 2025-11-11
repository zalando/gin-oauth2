package ginoauth2_test

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	ginoauth2 "github.com/zalando/gin-oauth2"
	"github.com/zalando/gin-oauth2/zalando"
	"golang.org/x/oauth2"
)

func TestAuthChainOptions(t *testing.T) {
	tokenserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(os.Stderr, r.Body)
		t.Logf("tokenserver")
		println("tokenserver")
		w.WriteHeader(200)
		w.Write([]byte("token-server"))
	}))
	defer tokenserver.Close()
	authserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(os.Stderr, r.Body)
		t.Logf("authserver")
		println("authserver")
		w.WriteHeader(200)
		w.Write([]byte("auth-server"))
	}))
	defer authserver.Close()

	scopeStrings := []string{"uid"}
	checkName := "foo"
	endpoint := oauth2.Endpoint{
		AuthURL:  authserver.URL,
		TokenURL: tokenserver.URL,
	}

	ginoauth2.Auth(zalando.ScopeAndCheck(checkName, scopeStrings...), endpoint)
	ginoauth2.AuthChain(endpoint, zalando.ScopeAndCheck(checkName, scopeStrings...))
	ginoauth2.AuthChainOptions(ginoauth2.Options{Endpoint: endpoint}, zalando.ScopeAndCheck(checkName, scopeStrings...))

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	authConfig := ginoauth2.AuthChainOptions(ginoauth2.Options{
		Endpoint:            endpoint,
		AccessTokenInHeader: true,
		Log:                 logger,
	}, zalando.ScopeAndCheck(checkName, scopeStrings...))

	router := gin.New()
	router.Use(authConfig)
	router.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("cn"); ok {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private for users to %s", v)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for users without cn"})
		}
	})

	w := PerformRequest(router, "GET", "/", http.Header{})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Failed to get status 401, got: %d", w.Code)
	}

	w = PerformRequest(router, "GET", "/", http.Header{"Authorization": []string{"foo"}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Failed to get status 401, got: %d", w.Code)
	}

	token := "eyJraWQiOiJwbGF0Zm9ybS1pYW0tc2FuZGJveC0yIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiIxZmFjYzkyMC0xZmIzLTQwYjAtOTg4Yi0yNDhhMTE5Zjg1MmEiLCJodHRwczovL2lkZW50aXR5LnphbGFuZG8uY29tL3JlYWxtIjoidXNlcnMiLCJodHRwczovL2lkZW50aXR5LnphbGFuZG8uY29tL3Rva2VuIjoiQmVhcmVyIiwiaHR0cHM6Ly9pZGVudGl0eS56YWxhbmRvLmNvbS9tYW5hZ2VkLWlkIjoic3N6dWVjcyIsImF6cCI6Inp0b2tlbiIsImh0dHBzOi8vaWRlbnRpdHkuemFsYW5kby5jb20vYnAiOiI4MTBkMWQwMC00MzEyLTQzZTUtYmQzMS1kODM3M2ZkZDI0YzciLCJhdXRoX3RpbWUiOjE3NjE4NTQ3NzMsImlzcyI6Imh0dHBzOi8vc2FuZGJveC5pZGVudGl0eS56YWxhbmRvLmNvbSIsImV4cCI6MTc2MTg2OTE3MywiaWF0IjoxNzYxODU0NzYzfQ.aw4iaFQyHVM4EfiaoSJY9ugrCQwLAiqK_oobQn-8x6lnS2PLGY75jURz5P6Kk6sQaM6zf70GpEGIuFrEhl9HOw"
	w = PerformRequest(router, "GET", "/", http.Header{"Authorization": []string{"Bearer", token}})
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get status 200, got: %d", w.Code)
	}

}

func PerformRequest(r http.Handler, method, path string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	maps.Copy(req.Header, header)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
