# Gin-OAuth2

[![Go Report
Card](https://goreportcard.com/badge/zalando/gin-oauth2)](https://goreportcard.com/report/zalando/gin-oauth2) [![Build Status](https://travis-ci.org/zalando/gin-oauth2.svg?branch=master)](https://travis-ci.org/zalando/gin-oauth2) [![GoDoc](https://godoc.org/github.com/zalando/gin-oauth2?status.svg)](https://godoc.org/github.com/zalando/gin-oauth2)


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
- create router groups to place OAuth2 authorization on top, using HTTP verbs and passing them
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

* [Gin](https://github.com/gin-gonic/gin)
* [glog](https://github.com/golang/glog)
* [gin-glog](https://github.com/szuecs/gin-glog)

## Installation

Assuming you've installed Go and Gin, run this:

    go get github.com/zalando/gin-oauth2

## Usage

[This example](https://github.com/zalando/gin-oauth2/blob/master/example/zalando/main.go) shows you how to use Gin-OAuth2.

### Uid-Based Access

First, define your access triples to identify who has access to a
given resource. This snippet shows how to grant resource access to two
hypothetical employees:

        // from zalando package
        // type AccessTuple struct {
        //      Realm string // p.e. "employees", "services"
        //      Uid   string // UnixName
        //      Cn    string // RealName
        // }
        var USERS []zalando.AccessTuple = []zalando.AccessTuple{
	    {"/employees", "sszuecs", "Sandor Szücs"},
            {"/employees", "njuettner", "Nick Jüttner"},
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
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck(USERS), zalando.OAuth2Endpoint))
	privateUser.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("cn"); ok {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private for users to %s", v)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for users without cn"})
		}
	})

#### Testing

To test, you can use curl:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users to Sandor Szücs"}

### Team-Based Access

As with Uid-based access, define your access triples to identify who
has access to a given resource. With this snippet, you can grant resource
access to an entire team instead of individuals:

        var TEAMS []zalando.AccessTuple = []zalando.AccessTuple{
	    {"teams", "opensourceguild", "OpenSource Guild"},
	    {"teams", "tm", "Platform / System"},
	    {"teams", "teapot", "Platform / Cloud API"},
        }

Now define which Gin middlewares you use:

	router := gin.New()
	router.Use(ginglog.Logger(3 * time.Second))
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:

	privateGroup := router.Group("/api/privateGroup")
	privateGroup.Use(ginoauth2.Auth(zalando.GroupCheck(TEAMS), zalando.OAuth2Endpoint))
	privateGroup.GET("/", func(c *gin.Context) {
		uid, okUid := c.Get("uid")
		if team, ok := c.Get("team"); ok && okUid {
			c.JSON(200, gin.H{"message": fmt.Sprintf("Hello from private to %s member of %s", uid, team)})
		} else {
			c.JSON(200, gin.H{"message": "Hello from private for groups without uid and team"})
		}
	})

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}

### Run Example Service

Run example service:

    % go run example/zalando/main.go -v=2 -logtostderr
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

Get an access token from your token provider (```oauth2.Endpoint.AuthURL```):

    % TOKEN=$(curl https://$USER:$PASSWORD@token.oauth2.corp.com/access_token)

Request:

    % curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
    {"message":"Hello from private to sszuecs member of teapot"}

### Google-Based Access

As shown in [this great article](http://skarlso.github.io/2016/06/12/google-signin-with-go/) about Gin and Google signin, you have to create credentials for an "OAuth client ID." In your [Google Cloud Console](https://console.cloud.google.com), you will find "Credentials" in the "API Manager":

![Picture of Google Cloud Console showing API Manager](https://raw.githubusercontent.com/zalando/gin-oauth2/master/doc/gcp-credentials.png)

You have to specify a path to your [clientid credential file](./example/google/test-clientid.google.json) and a slice of
scopes that you request for authorization.
You have also to specify the URL to get redirected to upon completion of the Google OAuth2.
Lastly, you have to choose a secret for the CookieStore and a session.
This OAuth2 flow is also known as [Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-4.1).

        redirectURL := "http://127.0.0.1:8081/auth/"
        credFile := "./example/google/test-clientid.google.json" // you have to build your own
        scopes := []string{
               "https://www.googleapis.com/auth/userinfo.email",
               // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
	}
	secret := []byte("secret") //
	sessionName := "goquestsession"

	router := gin.Default()
	// init settings for google auth
	google.Setup(redirectURL, credFile, scopes, secret)
	router.Use(google.Session(sessionName))


After the base setup, register a login handler. You might want to implement it yourself (pull requests are welcome):

	router.GET("/login", google.LoginHandler)

With a publicly accessible login resource in place, we can protect a private router group accessibly only with a Google authorized session. Auth will save your user information in the Gin context bucket "user."

	// protected url group
	private := router.Group("/auth")
	private.Use(google.Auth())
	private.GET("/", UserInfoHandler)
	private.GET("/api", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")

A handler will fetch user information from the gin.Context that's stored in google.Auth.

        func UserInfoHandler(ctx *gin.Context) {
	        ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": ctx.MustGet("user").(google.User)})
        }

#### Testing Google Auth

- Created your Google clientid stored in clientid.google.json similar to and grant redirect to example/google/test-clientid.google.json as described in the [article](http://skarlso.github.io/2016/06/12/google-signin-with-go/) mentioned before.
- run the server: ```% go run example/google/google.go -cred-file clientid.google.json```
- open [http://127.0.0.1:8081/login](http://127.0.0.1:8081/login) in your browser
- In your browser, follow the login, and choose your identity to login with
- You'll be redirected to the http://127.0.0.1:8081/auth endpoint, which should show your identity data

### GitHub-Based Access

As shown in [this blog post](https://blog.kowalczyk.info/article/f/Accessing-GitHub-API-from-Go.html) about Go and GitHub signin, you have to [register your application](https://github.com/settings/applications/new) with GitHub to get an "OAuth client ID." In your [developer applications](https://github.com/settings/developers), you will find your "Credentials":

From this article the flow of OAuth2 is:

* the user is on your website and clicks “login with GitHub” link
* you redirect the user to GitHub’s authorization page. In that url you specify desired access level and a random secret
the user authorizes your app by clicking on a link
* GitHub redirects to a callback url on your website (which you provided when registering the app with GitHub)
* in the url handler, extract “secret” and “code” args
* you have to check that the secret is the same as the one you sent to GitHub (security measure that prevents forgery)
* you call another GitHub url to exchange code for access token

You have to specify a path to your [clientid credential file](./example/github/test-clientid.github.json) and a slice of
scopes that you request for authorization.
You have also to specify the URL to get redirected to upon completion of the GitHub OAuth2.
Lastly, you have to choose a secret for the CookieStore and a session.
This OAuth2 flow is also known as [Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-4.1).

        redirectURL := "http://127.0.0.1:8081/auth/"
        credFile := "./example/github/test-clientid.github.json" // you have to build your own
        scopes := []string{
               "repo",
               // You have to select your own scope from here -> https://developer.github.com/v3/oauth/#scopes
	}
	secret := []byte("secret") //
	sessionName := "goquestsession"

	router := gin.Default()
	// init settings for github auth
	github.Setup(redirectURL, credFile, scopes, secret)
	router.Use(github.Session(sessionName))


After the base setup, register a login handler. You might want to implement it yourself (pull requests are welcome):

	router.GET("/login", github.LoginHandler)

With a publicly accessible login resource in place, we can protect a private router group accessibly only with a GitHub authorized session. Auth will save your user information in the Gin context bucket "user."

	// protected url group
	private := router.Group("/auth")
	private.Use(google.Auth())
	private.GET("/", UserInfoHandler)
	private.GET("/api", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")

A handler will fetch user information from the gin.Context that's stored in github.Auth.

        func UserInfoHandler(ctx *gin.Context) {
	        ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": ctx.MustGet("user")})
        }

#### Testing GitHub Auth

- Created your GitHub clientid stored in clientid.github.json similar to and grant redirect to example/github/test-clientid.github.json, get this from your [GitHub application](https://github.com/settings/applications).
- run the server: ```% go run example/github/github.go -cred-file clientid.github.json```
- open [http://127.0.0.1:8081/login](http://127.0.0.1:8081/login) in your browser
- In your browser, follow the login, and choose your identity to login with
- You'll be redirected to the http://127.0.0.1:8081/auth endpoint, which should show your identity data

## Contributing/TODO

We welcome contributions from the community; just submit a pull request. To help you get started, here are some items that we'd love help with:

- Adding automated tests, possibly with
  [dex](https://github.com/coreos/dex), to include Travis CI in the
  setup
- Adding integration with other open-source token providers
- Refactoring and rebuilding a customizable Google LoginHandler
- Adding other OAuth2 providers like Google and GitHub
- The code base

Please use GitHub issues as the starting point for contributions, new ideas and/or bug reports.

## Contact

* E-Mail: team-teapot@zalando.de
* Security issues: Please send an email to
  [maintainers](MAINTAINERS). We'll try to get back to you within two
  workdays. If you don't hear back ,then send an email to team-teapot@zalando.de.

## Contributors

Thanks to:

- Olivier Mengué
- Josta Yee

## License

See [LICENSE](LICENSE) file.
