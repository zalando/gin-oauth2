// Package github provides you access to Github's OAuth2
// infrastructure.
package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	oauth2gh "golang.org/x/oauth2/github"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

var (
	conf  *oauth2.Config
	state string
	store sessions.Store
)

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v\n", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Setup(redirectURL, credFile string, scopes []string, secret []byte) {
	store = cookie.NewStore(secret)
	var c Credentials
	file, err := os.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v\n", err)
	}
	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     oauth2gh.Endpoint,
	}
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	state = randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()
	ctx.Writer.Write([]byte("<html><title>Golang Github</title> <body> <a href='" + GetLoginURL(state) + "'><button>Login with GitHub!</button> </a> </body></html>"))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

type AuthUser struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	URL     string `json:"url"`
}

func init() {
	gob.Register(AuthUser{})
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			ok       bool
			authUser AuthUser
			user     *github.User
		)

		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)
		mysession := session.Get("ginoauthgh")
		if authUser, ok = mysession.(AuthUser); ok {
			ctx.Set("user", authUser)
			ctx.Next()
			return
		}

		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid session state: %s", retrievedState))
			return
		}

		stdctx := context.Background()
		tok, err := conf.Exchange(stdctx, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to do exchange: %w", err))
			return
		}
		client := github.NewClient(conf.Client(stdctx, tok))
		user, _, err = client.Users.Get(stdctx, "")
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to get user: %w", err))
			return
		}
		// Protection: fields used in userinfo might be nil-pointers
		authUser = AuthUser{
			Login: stringFromPointer(user.Login),
			Name:  stringFromPointer(user.Name),
			URL:   stringFromPointer(user.URL),
		}

		// save userinfo, which could be used in Handlers
		ctx.Set("user", authUser)

		// populate cookie
		session.Set("ginoauthgh", authUser)
		if err := session.Save(); err != nil {
			glog.Errorf("Failed to save session: %v", err)
		}
	}
}

func stringFromPointer(strPtr *string) (res string) {
	if strPtr == nil {
		res = ""
		return res
	}
	res = *strPtr
	return res
}
