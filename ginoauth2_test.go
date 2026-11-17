package ginoauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func validTokenInfo() map[string]interface{} {
	return map[string]interface{}{
		"access_token": "tok",
		"token_type":   "Bearer",
		"grant_type":   "password",
		"realm":        "/employees",
		"expires_in":   float64(600),
		"scope":        []interface{}{"uid"},
		"uid":          "sszuecs",
	}
}

func TestParseTokenContainer(t *testing.T) {
	tok := &oauth2.Token{AccessToken: "tok", TokenType: "Bearer"}

	tc, err := ParseTokenContainer(tok, validTokenInfo())
	require.NoError(t, err)
	assert.Equal(t, "sszuecs", tc.Scopes["uid"])
	assert.Equal(t, "/employees", tc.Realm)
	assert.True(t, tc.Valid())

	for _, key := range []string{"token_type", "grant_type", "realm", "expires_in", "access_token", "scope"} {
		t.Run("missing "+key, func(t *testing.T) {
			data := validTokenInfo()
			delete(data, key)
			assert.NotPanics(t, func() {
				_, err := ParseTokenContainer(tok, data)
				assert.Error(t, err)
			})
		})
		t.Run("wrong type "+key, func(t *testing.T) {
			data := validTokenInfo()
			data[key] = 42
			assert.NotPanics(t, func() {
				_, err := ParseTokenContainer(tok, data)
				assert.Error(t, err)
			})
		})
	}

	data := validTokenInfo()
	data["scope"] = []interface{}{1}
	_, err = ParseTokenContainer(tok, data)
	assert.Error(t, err)

	_, err = ParseTokenContainer(&oauth2.Token{AccessToken: "other", TokenType: "Bearer"}, validTokenInfo())
	assert.Error(t, err)
	_, err = ParseTokenContainer(&oauth2.Token{AccessToken: "tok", TokenType: "Basic"}, validTokenInfo())
	assert.Error(t, err)
}

func TestExtractToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	_, err := ExtractToken(r)
	assert.Error(t, err)

	r.Header.Set("Authorization", "Bearer")
	_, err = ExtractToken(r)
	assert.Error(t, err)

	r.Header.Set("Authorization", "Bearer abc")
	tok, err := ExtractToken(r)
	require.NoError(t, err)
	assert.Equal(t, "abc", tok.AccessToken)
	assert.Equal(t, "Bearer", tok.TokenType)
}

func TestGetTokenContainerContext(t *testing.T) {
	for _, header := range []bool{false, true} {
		t.Run(fmt.Sprintf("header=%v", header), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if header {
					assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
					assert.Empty(t, r.URL.Query().Get("access_token"))
				} else {
					assert.Equal(t, "tok", r.URL.Query().Get("access_token"))
				}
				fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","grant_type":"password","realm":"/r","expires_in":60,"scope":["uid"],"uid":"u"}`)
			}))
			defer srv.Close()

			o := Options{Endpoint: oauth2.Endpoint{TokenURL: srv.URL}, AccessTokenInHeader: header}
			tc, err := GetTokenContainerContext(context.Background(), o, &oauth2.Token{AccessToken: "tok", TokenType: "Bearer"})
			require.NoError(t, err)
			assert.Equal(t, "u", tc.Scopes["uid"])

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = GetTokenContainerContext(ctx, o, &oauth2.Token{AccessToken: "tok", TokenType: "Bearer"})
			assert.Error(t, err)
		})
	}
}
