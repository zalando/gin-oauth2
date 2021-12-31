package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/zalando/gin-oauth2/google"
	goauth "google.golang.org/api/oauth2/v2"
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
	flag.StringVar(&credFile, "cred-file", "./example/google/test-clientid.google.json", "Credential JSON file")
}
func main() {
	flag.Parse()

	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.email",
		// You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
	}
	secret := []byte("secret")
	sessionName := "goquestsession"

	router := gin.Default()
	// init settings for google auth
	google.Setup(redirectURL, credFile, scopes, secret)
	router.Use(google.Session(sessionName))

	router.GET("/login", google.LoginHandler)

	// protected url group
	private := router.Group("/auth")
	private.Use(google.Auth())
	private.GET("/", UserInfoHandler)
	private.GET("/api", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")
}

func UserInfoHandler(ctx *gin.Context) {
	var (
		res goauth.Userinfo
		ok  bool
	)

	val := ctx.MustGet("user")
	if res, ok = val.(goauth.Userinfo); !ok {
		res = goauth.Userinfo{Name: "no user"}
	}

	ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": res.Email})
}
