// Package ginoauth2 implements an OAuth2 based authorization
// middleware for the Gin https://github.com/gin-gonic/gin
// webframework.
//
// Example:
//
//	package main
//	import (
//		"flag"
//		"time"
//		"github.com/gin-gonic/gin"
//		"github.com/golang/glog"
//		"github.com/szuecs/gin-glog"
//		"github.com/zalando/gin-oauth2"
//		"golang.org/x/oauth2"
//	)
//
//	var OAuth2Endpoint = oauth2.Endpoint{
//		AuthURL:  "https://token.oauth2.corp.com/access_token",
//		TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	}
//
//	func UidCheck(tc *TokenContainer, ctx *gin.Context) bool {
//	 uid := tc.Scopes["uid"].(string)
//	 if uid != "sszuecs" {
//	  return false
//	 }
//	 ctx.Set("uid", uid)
//	 return true
//	}
//
//	func main() {
//		flag.Parse()
//		router := gin.New()
//		router.Use(ginglog.Logger(3 * time.Second))
//		router.Use(gin.Recovery())
//
//		ginoauth2.VarianceTimer = 300 * time.Millisecond // defaults to 30s
//
//		public := router.Group("/api")
//		public.GET("/", func(c *gin.Context) {
//			c.JSON(200, gin.H{"message": "Hello to public world"})
//		})
//
//		private := router.Group("/api/private")
//		private.Use(ginoauth2.Auth(UidCheck, OAuth2Endpoint))
//		private.GET("/", func(c *gin.Context) {
//			c.JSON(200, gin.H{"message": "Hello from private"})
//		})
//
//		glog.Info("bootstrapped application")
//		router.Run(":8081")
package ginoauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// VarianceTimer controls the max runtime of Auth() and AuthChain() middleware
var VarianceTimer time.Duration = 30000 * time.Millisecond

// AuthInfoURL is the URL to get information of your token
var AuthInfoURL string

// Transport to use for client http connections to AuthInfoURL
var Transport = http.Transport{}

// TokenContainer stores all relevant token information
type TokenContainer struct {
	Token     *oauth2.Token
	Scopes    map[string]interface{} // LDAP record vom Benutzer (cn, ..
	GrantType string                 // password, ??
	Realm     string                 // services, employees
}

// AccessCheckFunction is a function that checks if a given token grants
// access.
type AccessCheckFunction func(tc *TokenContainer, ctx *gin.Context) bool

type Options struct {
	Endpoint            oauth2.Endpoint
	AccessTokenInHeader bool
}

var accessTokenMask = regexp.MustCompile("[?&]access_token=[^&]+")

func maskAccessToken(a interface{}) string {
	s := fmt.Sprint(a)
	s = accessTokenMask.ReplaceAllString(s, "<MASK>")
	return s
}

// ExtractToken extracts the access token and its type from the
// Authorization header of the request.
func ExtractToken(r *http.Request) (*oauth2.Token, error) {
	return extractToken(r)
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("no authorization header")
	}

	typ, token, ok := strings.Cut(hdr, " ")
	if !ok {
		return nil, errors.New("invalid authorization header")
	}
	return &oauth2.Token{AccessToken: token, TokenType: typ}, nil
}

func requestAuthInfo(o Options, t *oauth2.Token) ([]byte, error) {
	return requestAuthInfoContext(context.Background(), AuthInfoURL, o, t)
}

func requestAuthInfoContext(ctx context.Context, baseURL string, o Options, t *oauth2.Token) ([]byte, error) {
	var infoURL string
	if o.AccessTokenInHeader {
		infoURL = baseURL
	} else {
		var uv = make(url.Values)
		uv.Set("access_token", t.AccessToken)
		infoURL = baseURL + "?" + uv.Encode()
	}

	client := &http.Client{Transport: &Transport}
	req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
	if err != nil {
		return nil, err
	}

	if o.AccessTokenInHeader {
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func RequestAuthInfo(t *oauth2.Token) ([]byte, error) {
	return requestAuthInfo(Options{}, t)
}

func ParseTokenContainer(t *oauth2.Token, data map[string]interface{}) (*TokenContainer, error) {
	tdata := make(map[string]interface{})

	ttype, ok := data["token_type"].(string)
	if !ok {
		return nil, errors.New("missing or invalid token_type")
	}
	gtype, ok := data["grant_type"].(string)
	if !ok {
		return nil, errors.New("missing or invalid grant_type")
	}
	realm, ok := data["realm"].(string)
	if !ok {
		return nil, errors.New("missing or invalid realm")
	}
	exp, ok := data["expires_in"].(float64)
	if !ok {
		return nil, errors.New("missing or invalid expires_in")
	}
	tok, ok := data["access_token"].(string)
	if !ok {
		return nil, errors.New("missing or invalid access_token")
	}
	if ttype != t.TokenType {
		return nil, errors.New("token type mismatch")
	}
	if tok != t.AccessToken {
		return nil, errors.New("mismatch between verify request and answer")
	}

	scopes, ok := data["scope"].([]interface{})
	if !ok {
		return nil, errors.New("missing or invalid scope")
	}
	for _, scope := range scopes {
		sscope, ok := scope.(string)
		if !ok {
			return nil, errors.New("invalid scope entry")
		}
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

func getTokenContainerForToken(o Options, token *oauth2.Token) (*TokenContainer, error) {
	return getTokenContainerForTokenContext(context.Background(), AuthInfoURL, o, token)
}

func getTokenContainerForTokenContext(ctx context.Context, baseURL string, o Options, token *oauth2.Token) (*TokenContainer, error) {
	body, err := requestAuthInfoContext(ctx, baseURL, o, token)
	if err != nil {
		errorf("[Gin-OAuth] RequestAuthInfo failed caused by: %s", err)
		return nil, err
	}
	// extract AuthInfo
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		errorf("[Gin-OAuth] JSON.Unmarshal failed caused by: %s", err)
		return nil, err
	}
	if si, ok := data["error_description"]; ok {
		s, ok := si.(string)
		if !ok {
			s = ""
		}
		errorf("[Gin-OAuth] RequestAuthInfo returned an error: %s", s)
		return nil, errors.New(s)
	}
	return ParseTokenContainer(token, data)
}

func GetTokenContainer(token *oauth2.Token) (*TokenContainer, error) {
	return getTokenContainerForToken(Options{}, token)
}

// GetTokenContainerContext validates the token against the tokeninfo
// endpoint o.Endpoint.TokenURL and returns its TokenContainer. The
// request is bound to ctx and does not depend on the AuthInfoURL
// global.
func GetTokenContainerContext(ctx context.Context, o Options, token *oauth2.Token) (*TokenContainer, error) {
	return getTokenContainerForTokenContext(ctx, o.Endpoint.TokenURL, o, token)
}

func getTokenContainer(o Options, ctx *gin.Context) (*TokenContainer, bool) {
	var oauthToken *oauth2.Token
	var tc *TokenContainer
	var err error

	if oauthToken, err = extractToken(ctx.Request); err != nil {
		errorf("[Gin-OAuth] Can not extract oauth2.Token, caused by: %s", err)
		return nil, false
	}
	if !oauthToken.Valid() {
		infof("[Gin-OAuth] Invalid Token - nil or expired")
		return nil, false
	}

	if tc, err = getTokenContainerForToken(o, oauthToken); err != nil {
		errorf("[Gin-OAuth] Can not extract TokenContainer, caused by: %s", err)
		return nil, false
	}

	return tc, true
}

// Valid validates that the AccessToken within TokenContainer is not
// expired and not empty.
func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

// Auth implements a router middleware that can be used to get an
// authenticated and authorized service for the whole router group.
// Example:
//
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := gin.Default()
//		private := router.Group("")
//		private.Use(ginoauth2.Auth(ginoauth2.UidCheck, ginoauth2.endpoints))
//		private.GET("/api/private", func(c *gin.Context) {
//			c.JSON(200, gin.H{"message": "Hello from private"})
//		})
func Auth(accessCheckFunction AccessCheckFunction, endpoints oauth2.Endpoint) gin.HandlerFunc {
	return AuthChain(endpoints, accessCheckFunction)
}

// AuthChain is a router middleware that can be used to get an authenticated
// and authorized service for the whole router group. Similar to Auth, but
// takes a chain of AccessCheckFunctions and only fails if all of them fails.
// Example:
//
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := gin.Default()
//		    private := router.Group("")
//	     checkChain := []AccessCheckFunction{
//	         ginoauth2.UidCheck,
//	         ginoauth2.GroupCheck,
//	     }
//	     private.Use(ginoauth2.AuthChain(checkChain, ginoauth2.endpoints))
//	     private.GET("/api/private", func(c *gin.Context) {
//	         c.JSON(200, gin.H{"message": "Hello from private"})
//	     })
func AuthChain(endpoint oauth2.Endpoint, accessCheckFunctions ...AccessCheckFunction) gin.HandlerFunc {
	return AuthChainOptions(Options{Endpoint: endpoint}, accessCheckFunctions...)
}

func AuthChainOptions(o Options, accessCheckFunctions ...AccessCheckFunction) gin.HandlerFunc {
	// init
	AuthInfoURL = o.Endpoint.TokenURL
	// middleware
	return func(ctx *gin.Context) {
		t := time.Now()
		varianceControl := make(chan bool, 1)

		go func() {
			tokenContainer, ok := getTokenContainer(o, ctx)
			if !ok {
				// set LOCATION header to auth endpoint such that the user can easily get a new access-token
				ctx.Writer.Header().Set("Location", o.Endpoint.AuthURL)
				ctx.AbortWithError(http.StatusUnauthorized, errors.New("no token in context"))
				varianceControl <- false
				return
			}

			if !tokenContainer.Valid() {
				// set LOCATION header to auth endpoint such that the user can easily get a new access-token
				ctx.Writer.Header().Set("Location", o.Endpoint.AuthURL)
				ctx.AbortWithError(http.StatusUnauthorized, errors.New("invalid Token"))
				varianceControl <- false
				return
			}

			for i, fn := range accessCheckFunctions {
				if fn(tokenContainer, ctx) {
					varianceControl <- true
					break
				}

				if len(accessCheckFunctions)-1 == i {
					ctx.AbortWithError(http.StatusForbidden, errors.New("access to the Resource is forbidden"))
					varianceControl <- false
					return
				}
			}
		}()

		select {
		case ok := <-varianceControl:
			if !ok {
				infofv2("[Gin-OAuth] %12v %s access not allowed", time.Since(t), ctx.Request.URL.Path)
				return
			}
		case <-time.After(VarianceTimer):
			ctx.AbortWithError(http.StatusGatewayTimeout, errors.New("authorization check overtime"))
			infofv2("[Gin-OAuth] %12v %s overtime", time.Since(t), ctx.Request.URL.Path)
			return
		}

		infofv2("[Gin-OAuth] %12v %s access allowed", time.Since(t), ctx.Request.URL.Path)
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
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := gin.Default()
//	     router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
func RequestLogger(keys []string, contentKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request
		c.Next()
		err := c.Errors
		if request.Method != "GET" && err == nil {
			if data, ok := c.Get(contentKey); !ok {
				values := make([]string, 0)
				for _, key := range keys {
					val, keyPresent := c.Get(key)
					if keyPresent {
						values = append(values, val.(string))
					}
				}
				infof("[Gin-OAuth] Request: %+v for %s", data, strings.Join(values, "-"))
			}
		}
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
