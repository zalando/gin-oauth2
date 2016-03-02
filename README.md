# Gin-OAuth2

[![Go Report Card](http://goreportcard.com/badge/zalando-techmonkeys/gin-oauth2)](http://goreportcard.com/report/zalando-techmonkeys/gin-oauth2)

This project implements an OAuth2 middleware ready to use with the
[Gin Framework](https://github.com/gin-gonic/gin). It makes
authorization simple to define and flexible to use.

## Requirements

You need an OAuth2 Token provider and a Tokeninfo service.

Gin-OAuth2 uses the following [Go](https://golang.org/) packages as dependencies:

* github.com/gin-gonic/gin
* github.com/golang/glog
* github.com/zalando-techmonkeys/gin-glog

## Installation

    go get github.com/zalando-techmonkeys/gin-oauth2

## Usage

This shows a full
[Example](https://github.com/zalando-techmonkeys/gin-oauth2/blob/master/example/main.go)
how to use this middleware.

### Uid based access

You have to define your access triples that define who has access to a
resource. In this snippet we have two employees that can be granted
access to resources.

        type AccessTuple struct {
	     Realm string // p.e. "employees", "services"
             Uid   string // UnixName
             Cn    string // RealName
        }
        var USERS []AccessTuple = []AccessTuple{
	    {"employees", "sszuecs", "Sandor Szücs"},
            {"employees", "njuettner", "Nick Jüttner"},
        }

Next you have to define which Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

At last you define which access you grant to the defined users.
We use a router group, such that we can add a bunch of router paths
and HTTP verbs.

	privateUser := router.Group("/api/privateUser")
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck, zalando.OAuth2Endpoint))
	privateUser.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for users"})
	})

To test, you can use curl.

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users}

### Team based access

You have to define your access triples that define who has access to a
resource. In this snippet we have one team that can be granted
access to resources.

	zalando.AccessTuples = []zalando.AccessTuple{
            {"teams", "tm", "Platform Engineering / System"},
        }

Next you have to define which Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

At last you define which access you grant to the defined team.
We use a router group, such that we can add a bunch of router paths
and HTTP verbs.

	private := router.Group("/api/private")
	private.Use(ginoauth2.Auth(zalando.GroupCheck, zalando.OAuth2Endpoint))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

To test you can use curl.

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/private/
        {"message":"Hello from private for groups"}


### Run example service

Run example service:

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

    % TOKEN=$(curl https://$USER:$PASSWORD@token.oauth2.corp.com/access_token)

Request:

    % curl --request GET --header "Authorization: Bearer $TOKEN" http://localhost:8081/api/private
    {"message":"Hello from private for groups""}

## License

See [LICENSE](LICENSE) file.
