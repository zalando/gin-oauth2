// Zalando specific example using plain net/http handlers.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	ginoauth2 "github.com/zalando/gin-oauth2"
	"github.com/zalando/gin-oauth2/stdlib"
	"github.com/zalando/gin-oauth2/zalando"
	zalandostd "github.com/zalando/gin-oauth2/zalando/stdlib"
)

var users = []zalando.AccessTuple{
	{Realm: "/employees", Uid: "sszuecs", Cn: "Sandor Szücs"},
	{Realm: "/employees", Uid: "njuettner", Cn: "Nick Jüttner"},
}

var teams = []zalando.AccessTuple{
	{Realm: "teams", Uid: "opensourceguild", Cn: "OpenSource"},
	{Realm: "teams", Uid: "teapot", Cn: "Platform / Cloud API"},
}

var services = []zalando.AccessTuple{
	{Realm: "services", Uid: "foo", Cn: "Fooservice"},
}

func main() {
	flag.Parse()

	ginoauth2.VarianceTimer = 300 * time.Millisecond // defaults to 30s

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello to public world")
	})

	private := stdlib.AuthChain(zalando.OAuth2Endpoint,
		zalandostd.UidCheck(users),
		zalandostd.GroupCheck(teams),
		zalandostd.UidCheck(services),
	)
	privateGroup := stdlib.Auth(zalandostd.GroupCheck(teams), zalando.OAuth2Endpoint)
	privateService := stdlib.Auth(zalandostd.ScopeAndCheck("uid", "bar"), zalando.OAuth2Endpoint)

	mux.Handle("GET /api/private/{$}", private(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from private for groups and users")
	})))
	mux.Handle("GET /api/privateGroup/{$}", privateGroup(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, okUID := stdlib.Value[string](r.Context(), "uid")
		team, okTeam := stdlib.Value[string](r.Context(), "team")
		if okUID && okTeam {
			fmt.Fprintf(w, "Hello from private for groups to %s member of %s\n", uid, team)
		} else {
			fmt.Fprintln(w, "Hello from private for groups without uid and team")
		}
	})))
	mux.Handle("GET /api/privateService/{$}", privateService(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, _ := stdlib.TokenContainerFromContext(r.Context())
		fmt.Fprintf(w, "Hello from private for services, realm %s\n", tc.Realm)
	})))

	glog.Info("bootstrapped application")
	glog.Fatal(http.ListenAndServe(":8081", mux))
}
