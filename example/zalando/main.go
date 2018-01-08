// Zalando specific example.
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/szuecs/gin-glog"
	"github.com/zalando/gin-oauth2"
	"github.com/zalando/gin-oauth2/zalando"
)

var USERS []zalando.AccessTuple = []zalando.AccessTuple{
	{"/employees", "sszuecs", "Sandor Szücs"},
	{"/employees", "njuettner", "Nick Jüttner"},
}

var TEAMS []zalando.AccessTuple = []zalando.AccessTuple{
	{"teams", "opensourceguild", "OpenSource"},
	{"teams", "tm", "Platform Engineering / System"},
	{"teams", "teapot", "Platform / Cloud API"},
}
var SERVICES []zalando.AccessTuple = []zalando.AccessTuple{
	{"services", "foo", "Fooservice"},
}

func main() {
	flag.Parse()
	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

	ginoauth2.VarianceTimer = 300 * time.Millisecond // defaults to 30s

	public := router.Group("/api")
	public.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello to public world"})
	})

	private := router.Group("/api/private")
	privateGroup := router.Group("/api/privateGroup")
	privateUser := router.Group("/api/privateUser")
	privateService := router.Group("/api/privateService")
	glog.Infof("Register allowed users: %+v and groups: %+v and services: %+v", USERS, TEAMS, SERVICES)

	private.Use(ginoauth2.AuthChain(zalando.OAuth2Endpoint, zalando.UidCheck(USERS), zalando.GroupCheck(TEAMS), zalando.UidCheck(SERVICES)))
	privateGroup.Use(ginoauth2.Auth(zalando.GroupCheck(TEAMS), zalando.OAuth2Endpoint))
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck(USERS), zalando.OAuth2Endpoint))
	//privateService.Use(ginoauth2.Auth(zalando.UidCheck(SERVICES), zalando.OAuth2Endpoint))
	privateService.Use(ginoauth2.Auth(zalando.ScopeAndCheck("uidcheck", "uid", "bar"), zalando.OAuth2Endpoint))

	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for groups and users"})
	})
	privateGroup.GET("/", func(c *gin.Context) {
		uid, okUid := c.Get("uid")
		if team, ok := c.Get("team"); ok && okUid {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private for groups to %s member of %s", uid, team)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for groups without uid and team"})
		}
	})
	privateUser.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("cn"); ok {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private for users to %s", v)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for users without cn"})
		}
	})
	privateService.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("cn"); ok {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private for services to %s", v)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for services without cn"})
		}
	})

	glog.Info("bootstrapped application")
	router.Run(":8081")
}
