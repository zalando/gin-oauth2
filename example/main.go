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

//var USERS []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employees", "njuettner", "Nick Jüttner"}}
var USERS []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employees", "sszuecs", "Sandor Szücs"}, {"employees", "njuettner", "Nick Jüttner"}}

var OAuth2Endpoint = oauth2.Endpoint{
	AuthURL:  "https://token.auth.zalando.com/access_token",
	TokenURL: "https://auth.zalando.com/z/oauth2/tokeninfo",
}

func main() {

	flag.Parse()
	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger("uid", "data"))
	router.Use(gin.Recovery())

	public := router.Group("/api")
	public.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello to public world"})
	})

	private := router.Group("/api/private")
	private.Use(ginoauth2.Auth(ginoauth2.UidCheck, OAuth2Endpoint, USERS))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private"})
	})

	glog.Info("bootstrapped application")
	router.Run(":8081")
}
