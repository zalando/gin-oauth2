package main

import (
	"flag"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/zalando-techmonkeys/gin-glog"
	"github.com/zalando-techmonkeys/gin-oauth2"
	"golang.org/x/oauth2"
)

var OAuth2Endpoint = oauth2.Endpoint{
	AuthURL:  "https://token.auth.zalando.com/access_token",
	TokenURL: "https://auth.zalando.com/z/oauth2/tokeninfo",
}

type AccessTuple struct {
	Realm string // p.e. "employees", "services"
	Uid   string // UnixName
	Cn    string // RealName
}

var USERS []AccessTuple = []AccessTuple{
	{"employees", "sszuecs", "Sandor Szücs"},
	{"employees", "njuettner", "Nick Jüttner"},
}

// Authorization function that checks UID scope
// TokenContainer must be Valid
// gin.Context gin contex
func UidCheck(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	uid := tc.Scopes["uid"].(string)
	for idx := range USERS {
		at := USERS[idx]
		if uid == at.Uid {
			ctx.Set("uid", uid) //in this way I can set the authorized uid
			glog.Infof("Grant access to %s\n", uid)
			return true
		}
	}

	return false
}

func main() {

	flag.Parse()
	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

	public := router.Group("/api")
	public.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello to public world"})
	})

	private := router.Group("/api/private")
	glog.Infof("Register allowed users: %+v", USERS)
	private.Use(ginoauth2.Auth(UidCheck, OAuth2Endpoint))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private"})
	})

	glog.Info("bootstrapped application")
	router.Run(":8081")
}
