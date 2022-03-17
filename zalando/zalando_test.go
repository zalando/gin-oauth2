package zalando

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"

	ginoauth2 "github.com/zalando/gin-oauth2"
	"golang.org/x/oauth2"
)

// You have to have a current file $HOME/.chimp-token with only a
// valid Zalando access token.
var tokenFile string = fmt.Sprintf("%s/.chimp-token", os.Getenv("HOME"))

func getToken() (string, error) {
	file, err := os.Open(tokenFile)
	if err != nil {
		return "not a file", err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "reading failed", err
	}
	return strings.TrimSpace(string(data)), nil
}

func TestRequestTeamInfo(t *testing.T) {
	ginoauth2.AuthInfoURL = OAuth2Endpoint.TokenURL
	accessToken, err := getToken()
	if err != nil {
		t.Errorf("ERR: Could not get Access Token from file, caused by %q: %v", accessToken, err)
		t.FailNow()
	}

	token := oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(600) * time.Second),
	}
	tc, err := ginoauth2.GetTokenContainer(&token)
	if err != nil {
		t.Errorf("ERR: Could not get TokenContainer from ginoauth2: %v", err)
		t.FailNow()
	}
	resp, err := RequestTeamInfo(tc, TeamAPI)
	if err != nil {
		t.Errorf("ERR: Could not get TeamInfo for TokenContainer from TeamAPI: %v", err)
		t.FailNow()
	}
	var data []TeamInfo
	err = json.Unmarshal(resp, &data)
	if err != nil {
		t.Errorf("ERR: Could not unmarshal json data: %v", err)
		t.FailNow()
	}
	fmt.Printf("%+v\n", data)
}

func TestScopeCheck(t *testing.T) {
	// given
	tc := &ginoauth2.TokenContainer{
		Token: &oauth2.Token{
			AccessToken:  "sdgergSgadGSAHBSHsagsdv.",
			TokenType:    "Bearer",
			RefreshToken: "",
		},
		Scopes: map[string]interface{}{
			"my-scope-1": true,
			"my-scope-2": true,
			"uid":        "stups_marilyn-updater",
		},
		GrantType: "password",
		Realm:     "/services",
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	// when
	checkFn := ScopeCheck("name", "my-scope-1")
	result := checkFn(tc, ctx)

	// then
	assert.True(t, result)

	scopeVal, scopeOk := ctx.Get("my-scope-1")
	assert.True(t, scopeOk)
	assert.Equal(t, true, scopeVal)

	uid, uidOk := ctx.Get("uid")
	assert.True(t, uidOk)
	assert.Equal(t, "stups_marilyn-updater", uid)
}

func TestScopeAndCheck(t *testing.T) {
	// given
	tc := &ginoauth2.TokenContainer{
		Token: &oauth2.Token{
			AccessToken:  "sdgergSgadGSAHBSHsagsdv.",
			TokenType:    "Bearer",
			RefreshToken: "",
		},
		Scopes: map[string]interface{}{
			"my-scope-1": true,
			"my-scope-2": true,
			"uid":        "stups_marilyn-updater",
		},
		GrantType: "password",
		Realm:     "/services",
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	// when
	checkFn := ScopeAndCheck("name", "uid", "my-scope-2")
	result := checkFn(tc, ctx)

	// then
	assert.True(t, result)

	uidVal, uidOk := ctx.Get("uid")
	scopeVal, scopeOk := ctx.Get("my-scope-2")
	assert.True(t, uidOk)
	assert.Equal(t, "stups_marilyn-updater", uidVal)
	assert.True(t, scopeOk)
	assert.Equal(t, true, scopeVal)
}
