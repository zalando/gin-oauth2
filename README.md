# Gin-OAuth2

[![Go Report Card](http://goreportcard.com/badge/zalando-techmonkeys/gin-oauth2)](http://goreportcard.com/report/zalando-techmonkeys/gin-oauth2)

Gin-OAuth2 is specially made for [Gin Framework](https://github.com/gin-gonic/gin)
users who also want to use OAuth2. It was created by Go developers
who needed Gin middleware for working with OAuth2 and couldn't find
any.

## Project Context and Features

When it comes to choosing a Go framework, there's a lot of confusion
about what to use. The scene is very fragmented, and detailed
comparisons of different frameworks are still somewhat rare. Meantime,
how to handle dependencies and structure projects are big topics in
the Go community. We've liked using Gin for its speed,
accessibility, and usefulness in developing microservice
architectures. In creating Gin-OAuth2, we wanted to take fuller
advantage of Gin's capabilities and help other devs do likewise.

Gin-OAuth2 is expressive, flexible, and very easy to use. It allows you to:
- do OAuth2 authorization based on HTTP routing
- create router groups to place OAuth2 authorization on top, using HTTP verbs and passing them.
- more easily decouple services by promoting a "say what to do, not how to do it" approach
- configure your REST API directly in the code (see the "Usage" example below)
- write your own authorization functions

## How OAuth 2 Works

If you're just starting out with OAuth2, you might find these
resources useful:

- [OAuth 2 Simplified](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)
- [An Introduction to OAuth 2](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)

## Requirements

- [Gin](https://github.com/gin-gonic/gin)
- An OAuth2 Token provider (we recommend that you use your own,
  p.e. use [dex](https://github.com/coreos/dex))
- a Tokeninfo service (p.e. use [dex](https://github.com/coreos/dex))

Gin-OAuth2 uses the following [Go](https://golang.org/) packages as
dependencies:

* github.com/gin-gonic/gin
* github.com/golang/glog
* github.com/zalando-techmonkeys/gin-glog

## Installation

Assuming you've installed Go and Gin, run this:

    go get github.com/zalando-techmonkeys/gin-oauth2

## Usage

[This example](https://github.com/zalando-techmonkeys/gin-oauth2/blob/master/example/main.go) shows you how to use Gin-OAuth2.

### Uid-Based Access

First, define your access triples to identify who has access to a
given resource. This snippet shows how to grant resource access to two
hypothetical employees:

        type AccessTuple struct {
	     Realm string // p.e. "employees", "services"
             Uid   string // UnixName
             Cn    string // RealName
        }
        var USERS []AccessTuple = []AccessTuple{
	    {"employees", "sszuecs", "Sandor Szücs"},
            {"employees", "njuettner", "Nick Jüttner"},
        }

Next, define which Gin middlewares you use. The third line in this
snippet is a basic audit log:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

Finally, define which type of access you grant to the defined
users. We'll use a router group, so that we can add a bunch of router
paths and HTTP verbs:

	privateUser := router.Group("/api/privateUser")
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck, zalando.OAuth2Endpoint))
	privateUser.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for users"})
	})

#### Testing

To test, you can use curl:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users}

### Team-based access

As for Uid-Based Access, define your access triples to identify who
has access to a given resource. In this snippet, we can grant resource
access to an entire team instead of individuals:

	zalando.AccessTuples = []zalando.AccessTuple{
            {"teams", "tm", "Platform Engineering / System"},
        }

Now define which Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:

	private := router.Group("/api/private")
	private.Use(ginoauth2.Auth(zalando.GroupCheck, zalando.OAuth2Endpoint))
	private.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/private/
        {"message":"Hello from private for groups"}

### Run Example Service

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

## Contributing/TODO

We welcome contributions from the community; just submit a pull
request. To help you get started, here are some items that we'd love
help with:

- Adding automated tests, possibly with
  [dex](https://github.com/coreos/dex) to include Travis CI in the
  setup Add integration with other open-source token providers into
- Adding other OAuth2 providers like google, github, .. would be a
  very nice contribution
- the code base

Please use github issues as starting point for contributions, new
ideas or bugreports.

## Contact

* E-Mail: team-techmonkeys@zalando.de
* IRC on freenode: #zalando-techmonkeys

## Contributors

Thanks to:

- Olivier Mengué

## License

See [LICENSE](LICENSE) file.
