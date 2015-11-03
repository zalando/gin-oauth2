// Package ginoauth2 implements an OAuth2 based authorization
// middleware for the Gin https://github.com/gin-gonic/gin
// webframework.
//
// Example:
//     package main
//     import (
//     	"flag"
//     	"time"
//     	"github.com/gin-gonic/gin"
//     	"github.com/golang/glog"
//     	"github.com/zalando-techmonkeys/gin-glog"
//     	"github.com/zalando-techmonkeys/gin-oauth2"
//     	"golang.org/x/oauth2"
//     )
//
//     var USERS []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employees", "sszuecs", "Sandor Szücs"}, {"employees", "njuettner", "Nick Jüttner"}}
//     var OAuth2Endpoint = oauth2.Endpoint{
//     	AuthURL:  "https://token.oauth2.corp.com/access_token",
//     	TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//     }
//
//     func main() {
//     	flag.Parse()
//     	router := gin.New()
//     	router.Use(ginglog.Logger(3 * time.Second))
//     	router.Use(gin.Recovery())
//
//     	public := router.Group("/api")
//     	public.GET("/", func(c *gin.Context) {
//     		c.JSON(200, gin.H{"message": "Hello to public world"})
//     	})
//
//     	private := router.Group("/api/private")
//     	private.Use(ginoauth2.Auth(ginoauth2.UidCheck, OAuth2Endpoint, USERS))
//     	private.GET("/", func(c *gin.Context) {
//     		c.JSON(200, gin.H{"message": "Hello from private"})
//     	})
//
//     	glog.Info("bootstrapped application")
//     	router.Run(":8081")
//
package ginoauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
)

var AuthInfoURL string
var Realms []string = []string{"employees", "services"}
var Transport http.Transport = http.Transport{}

type AccessTuple struct {
	Realm string // p.e. "employees", "services"
	Uid   string // UnixName
	Cn    string // RealName
}

type TokenContainer struct {
	Token     *oauth2.Token
	Scopes    map[string]interface{} // LDAP record vom Benutzer (cn, ..
	GrantType string                 // password, ??
	Realm     string                 // services, employees
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("No authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("Incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func RequestAuthInfo(t *oauth2.Token) ([]byte, error) {
	var uv = make(url.Values)
	// uv.Set("realm", o.Realm)
	uv.Set("access_token", t.AccessToken)
	info_url := AuthInfoURL + "?" + uv.Encode()
	client := &http.Client{Transport: &Transport}
	req, err := http.NewRequest("GET", info_url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func ParseTokenContainer(t *oauth2.Token, data map[string]interface{}) (*TokenContainer, error) {
	tdata := make(map[string]interface{})

	ttype := data["token_type"].(string)
	gtype := data["grant_type"].(string)

	realm := data["realm"].(string)
	exp := data["expires_in"].(float64)
	tok := data["access_token"].(string)
	if ttype != t.TokenType {
		return nil, errors.New("Token type mismatch")
	}
	if tok != t.AccessToken {
		return nil, errors.New("Mismatch between verify request and answer")
	}

	scopes := data["scope"].([]interface{})
	for _, scope := range scopes {
		sscope := scope.(string)
		sval, ok := data[sscope]
		if ok {
			tdata[sscope] = sval
		}
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: tok,
			TokenType:   ttype,
			Expiry:      time.Now().Add(time.Duration(exp) * time.Second),
		},
		Scopes:    tdata,
		Realm:     realm,
		GrantType: gtype,
	}, nil
}

func GetTokenContainer(token *oauth2.Token) (*TokenContainer, error) {
	body, err := RequestAuthInfo(token)
	if err != nil {
		glog.Errorf("RequestAuthInfo failed caused by: %s", err)
		return nil, err
	}
	// extract AuthInfo
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		glog.Errorf("JSON.Unmarshal failed caused by: %s", err)
		return nil, err
	}
	if _, ok := data["error_description"]; ok {
		var s string
		s = data["error_description"].(string)
		glog.Errorf("RequestAuthInfo returned an error: %s", s)
		return nil, errors.New(s)
	}
	return ParseTokenContainer(token, data)
}

func getTokenContainer(ctx *gin.Context) (*TokenContainer, bool) {
	var oauth_token *oauth2.Token
	var tc *TokenContainer
	var err error

	if oauth_token, err = extractToken(ctx.Request); err != nil {
		glog.Errorf("Can not extract oauth2.Token, caused by: %s", err)
		return nil, false
	}
	if !oauth_token.Valid() {
		glog.Infof("Invalid Token - nil or expired")
		return nil, false
	}

	if tc, err = GetTokenContainer(oauth_token); err != nil {
		glog.Errorf("Can not extract TokenContainer, caused by: %s", err)
		return nil, false
	}

	return tc, true
}

//
// TokenContainer
//
// Validates that the AccessToken within TokenContainer is not expired and not empty.
func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

// Authorization function that checks UID scope
// TokenContainer must be Valid
// []AccessTuple: [{Realm:employee Uid:sszuecs Cn:Sandor Szücs} {Realm:employee Uid:njuettner Cn:Nick Jüttner}]
// gin.Context gin contex
func UidCheck(tc *TokenContainer, access_tuple []AccessTuple, ctx *gin.Context) bool {
	uid := tc.Scopes["uid"].(string)
	for idx := range access_tuple {
		at := access_tuple[idx]
		if uid == at.Uid {
			ctx.Set("uid", uid) //in this way I can set the authorized uid
			glog.Infof("Grant access to %s\n", uid)
			return true
		}
	}

	return false
}

// Router middleware that can be used to get an authenticated and authorized service for the whole router group.
// Example:
//
//      var endpoints oauth2.Endpoint = oauth2.Endpoint{
//	        AuthURL:  "https://token.oauth2.corp.com/access_token",
//	        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//      }
//      var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//      router := gin.Default()
//	private := router.Group("")
//	private.Use(ginoauth2.Auth(ginoatuh2.UidCheck, ginoauth2.endpoints, acl))
//	private.GET("/api/private", func(c *gin.Context) {
//		c.JSON(200, gin.H{"message": "Hello from private"})
//	})
//
func Auth(accessCheckFunction func(tc *TokenContainer, access_tuple []AccessTuple, ctx *gin.Context) bool, endpoints oauth2.Endpoint, users []AccessTuple) gin.HandlerFunc {
	// init
	glog.Infof("Register allowed users: %+v", users)
	AuthInfoURL = endpoints.TokenURL
	// middleware
	return func(ctx *gin.Context) {
		var token_container *TokenContainer
		token_container, ok := getTokenContainer(ctx)
		if !ok {
			// set LOCATION header to auth endpoint such that the user can easily get a new access-token
			ctx.Writer.Header().Set("Location", endpoints.AuthURL)
			ctx.AbortWithError(http.StatusUnauthorized, errors.New("No token in context"))
			return
		}

		if !token_container.Valid() {
			// set LOCATION header to auth endpoint such that the user can easily get a new access-token
			ctx.Writer.Header().Set("Location", endpoints.AuthURL)
			ctx.AbortWithError(http.StatusUnauthorized, errors.New("Invalid Token"))
			return
		}

		if !accessCheckFunction(token_container, users, ctx) {
			ctx.AbortWithError(http.StatusForbidden, errors.New("Access to the Resource is fobidden"))
			return
		}

		// access allowed
		ctx.Writer.Header().Set("Bearer", token_container.Token.AccessToken)
	}
}

// RequestLogger is a middleware that logs all the request and prints
// relevant information.  This can be used for logging all the
// requests that contain important information and are authorized.
// The assumption is that the request to log has a content and an Id
// identifiying who made the request uIdKey string to use as key to
// get the uid from the context contentKey string to use as key to get
// the content to be logged from the context.
//
// Example:
//
//      var endpoints oauth2.Endpoint = oauth2.Endpoint{
//	        AuthURL:  "https://token.oauth2.corp.com/access_token",
//	        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//      }
//      var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//      router := gin.Default()
//      router.Use(ginoauth2.RequestLogger("uid", "data"))
//
func RequestLogger(keys []string, contentKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request
		c.Next()
		err := c.Errors
		if request.Method != "GET" && err == nil {
			data, e := c.Get(contentKey)
			if e != false { //key is non existent
				values := make([]string, 0)
				for _, key := range keys {
					val, keyPresent := c.Get(key)
					if keyPresent {
						values = append(values, val.(string))
					}
				}
				glog.Info(fmt.Sprintf("Request: %+v for %s", data, strings.Join(values, "-")))
			}
		}
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
