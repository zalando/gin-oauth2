// Zalando specific example.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/zalando/gin-oauth2"
	"github.com/zalando/gin-oauth2/zalando"
	"goji.io"
	"goji.io/pat"
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

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		glog.Infof("loggerMiddleware: Got request: %s", req.URL)
		next.ServeHTTP(rw, req)
	})
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := pat.Param(r, "name")
	fmt.Fprintf(w, "Hello, %s!\n", name)
}

func main() {
	flag.Parse()
	// start glog flusher
	go func() {
		for range time.Tick(1 * time.Second) {
			glog.Flush()
		}
	}()

	mux := goji.NewMux()
	mux.Use(loggerMiddleware)
	mux.Use(ginoauth2.RequestLoggerNetHTTP([]string{"uid"}, "data"))
	ginoauth2.VarianceTimer = 3000 * time.Millisecond // defaults to 30s

	public := goji.SubMux()
	mux.Handle(pat.New("/api/*"), public)
	public.HandleFunc(pat.Get("/:name"), hello)

	private := goji.SubMux()
	mux.Handle(pat.New("/private/*"), private)
	privateGroup := goji.SubMux()
	mux.Handle(pat.New("/privateGroup/*"), privateGroup)
	privateUser := goji.SubMux()
	mux.Handle(pat.New("/privateUser/*"), privateUser)
	privateService := goji.SubMux()
	mux.Handle(pat.New("/privateService/*"), privateService)
	glog.Infof("Register allowed users: %+v and groups: %+v and services: %+v", USERS, TEAMS, SERVICES)

	private.Use(ginoauth2.AuthChainNetHTTP(zalando.OAuth2Endpoint, zalando.UidCheckNetHTTP(USERS), zalando.GroupCheckNetHTTP(TEAMS), zalando.UidCheckNetHTTP(SERVICES)))
	privateGroup.Use(ginoauth2.AuthNetHTTP(zalando.GroupCheckNetHTTP(TEAMS), zalando.OAuth2Endpoint))
	privateUser.Use(ginoauth2.AuthNetHTTP(zalando.UidCheckNetHTTP(USERS), zalando.OAuth2Endpoint))
	privateService.Use(ginoauth2.AuthNetHTTP(zalando.ScopeAndCheckNetHTTP("uidcheck", "uid", "bar"), zalando.OAuth2Endpoint))

	private.HandleFunc(pat.Get("/"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		uid := h.Get("uid")
		fmt.Fprintf(w, "Hello from private for groups and users: %s\n", uid)
	}))

	privateGroup.HandleFunc(pat.Get("/"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		uid := h.Get("uid")
		team := h.Get("team")
		fmt.Fprintf(w, "Hello from private group: uid: %s, team: %s\n", uid, team)
	}))

	privateUser.HandleFunc(pat.Get("/"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		uid := h.Get("uid")
		fmt.Fprintf(w, "Hello from private user: uid: %s\n", uid)
	}))

	privateService.HandleFunc(pat.Get("/"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		cn := h.Get("cn")
		fmt.Fprintf(w, "Hello from private service cn: %s\n", cn)
	}))

	glog.Info("bootstrapped application")
	http.ListenAndServe("localhost:8081", mux)

}
