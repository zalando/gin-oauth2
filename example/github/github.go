package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/zalando/gin-oauth2/github"
)

var redirectURL, credFile string

func init() {
	bin := path.Base(os.Args[0])
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage of %s
================
`, bin)
		flag.PrintDefaults()
	}
	flag.StringVar(&redirectURL, "redirect", "http://127.0.0.1:8081/auth/", "URL to be redirected to after authorization.")
	flag.StringVar(&credFile, "cred-file", "./example/github/test-clientid.github.json", "Credential JSON file")
}
func main() {
	flag.Parse()

	scopes := []string{
		"repo",
		// You have to select your own scope from here -> https://developer.github.com/v3/oauth/#scopes
	}
	secret := []byte("secret")
	sessionName := "goquestsession"
	router := gin.Default()
	// init settings for github auth
	github.Setup(redirectURL, credFile, scopes, secret)
	router.Use(github.Session(sessionName))

	router.GET("/login", github.LoginHandler)

	// protected url group
	private := router.Group("/auth")
	private.Use(github.Auth())
	private.GET("/", UserInfoHandler)
	private.GET("/api", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")
}

func UserInfoHandler(ctx *gin.Context) {
	var (
		res github.AuthUser
		val interface{}
		ok  bool
	)

	val = ctx.MustGet("user")
	if res, ok = val.(github.AuthUser); !ok {
		res = github.AuthUser{
			Name: "no User",
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": res})
}
