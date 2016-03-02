// Zalando specific example.
package main

import (
	"flag"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/zalando-techmonkeys/gin-glog"
	"github.com/zalando-techmonkeys/gin-oauth2"
	"github.com/zalando-techmonkeys/gin-oauth2/zalando"
)

type AccessTuple struct {
	Realm string // p.e. "employees", "services"
	Uid   string // UnixName
	Cn    string // RealName
}

var USERS []AccessTuple = []AccessTuple{
	{"employees", "sszuecs", "Sandor Szücs"},
	{"employees", "njuettner", "Nick Jüttner"},
}

func main() {
	zalando.AccessTuples = []zalando.AccessTuple{{"teams", "tm", "Platform Engineering / System"}}
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
	privateUser := router.Group("/api/privateUser")
	glog.Infof("Register allowed users: %+v and groups: %+v", USERS, zalando.AccessTuples)
	private.Use(ginoauth2.Auth(zalando.GroupCheck, zalando.OAuth2Endpoint))
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck, zalando.OAuth2Endpoint))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for groups"})
	})
	privateUser.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for users"})
	})

	glog.Info("bootstrapped application")
	router.Run(":8081")
}
