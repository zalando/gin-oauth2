// GitHub sign-in example using plain net/http handlers.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/golang/glog"
	githubstd "github.com/zalando/gin-oauth2/github/stdlib"
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

	// init settings for github auth
	provider, err := githubstd.NewFromFile(redirectURL, credFile, scopes, secret)
	if err != nil {
		glog.Fatalf("failed to setup github auth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /login", provider.LoginHandler())

	// protected urls
	private := provider.Auth()
	mux.Handle("GET /auth/{$}", private(http.HandlerFunc(UserInfoHandler)))
	mux.Handle("GET /auth/api", private(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"message": "Hello from private for groups"})
	})))

	glog.Fatal(http.ListenAndServe("127.0.0.1:8081", mux))
}

func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := githubstd.UserFromContext(r.Context())
	if !ok {
		user.Name = "no User"
	}
	writeJSON(w, map[string]any{"Hello": "from private", "user": user})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
