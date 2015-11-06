package main

import (
	"flag"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/zalando-techmonkeys/gin-glog"
	"github.com/zalando-techmonkeys/gin-oauth2"
	"github.com/zalando-techmonkeys/gin-oauth2/zalando"
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
	zalando.Access_tuple = []zalando.AccessTuple{{"teams", "Techmonkeys", "Platform Engineering / System"}}
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
	private_user := router.Group("/api/private_user")
	glog.Infof("Register allowed users: %+v and groups: %+v", USERS, zalando.Access_tuple)
	private.Use(ginoauth2.Auth(zalando.GroupCheck, zalando.OAuth2Endpoint))
	private_user.Use(ginoauth2.Auth(UidCheck, zalando.OAuth2Endpoint))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for groups"})
	})
	private_user.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for users"})
	})

	glog.Info("bootstrapped application")
	router.Run(":8081")
}
