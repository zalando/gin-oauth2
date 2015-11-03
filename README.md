# ginoauth2

This projects implements an OAuth2 middleware ready to use with [Gin Framework](https://github.com/gin-gonic/gin).

## Installation

    go get github.com/gin-gonic/gin
    go get github.com/golang/glog
    go get github.com/zalando-techmonkeys/gin-glog
    go get github.com/zalando-techmonkeys/gin-oauth2

## Requirements

You need an OAuth2 Token provider and a Tokeninfo service.

## Usage

### Example
```go
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

var USERS []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employees", "sszuecs", "Sandor Szücs"}, {"employees", "njuettner", "Nick Jüttner"}}

var OAuth2Endpoint = oauth2.Endpoint{
	AuthURL:  "https://token.oauth2.corp.com/access_token",
	TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
}

func main() {

	flag.Parse()
	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid", "team"}, "data"))
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
```

## Test

Run example app:

    % go run example/main.go -v=2 -logtostderr
    [GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
    - using env:   export GIN_MODE=release
    - using code:  gin.SetMode(gin.ReleaseMode)
    [GIN-debug] GET   /api/                     --> main.func·001 (4 handlers)
    I1028 10:12:44.908274   22325 ginoauth2.go:238] Register allowed users: [{Realm:employees Uid:sszuecs Cn:Sandor Szücs} {Realm:employees Uid:njuettner Cn:Nick Jüttner}]
    [GIN-debug] GET   /api/private/             --> main.func·002 (5 handlers)
    I1028 10:12:44.908342   22325 main.go:41] bootstrapped application
    [GIN-debug] Listening and serving HTTP on :8081
    I1028 10:12:46.794502   22325 ginoauth2.go:213] Grant access to sszuecs
    I1028 10:12:46.794571   22325 ginglog.go:93] [GIN] | 200 | 194.162911ms | [::1]:58629 |   GET     /api/private/

Get an Access Token from your token provider (```oauth2.Endpoint.AuthURL```):

    % curl https://$USER:$PASSWORD@token.oauth2.corp.com/access_token
    07c39a44-23f2-3012-a6f7-5334c5f9a51f

Request:

    % curl --request GET --header "Authorization: Bearer 07c39a44-23f2-3012-a6f7-5334c5f9a51f" http://localhost:8081/api/private
    {"message":"Hello from private"}

## License

See [LICENSE](LICENSE) file.
