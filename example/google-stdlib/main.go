// Google sign-in example using plain net/http handlers.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/golang/glog"
	googlestd "github.com/zalando/gin-oauth2/google/stdlib"
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

	// init settings for google auth
	provider, err := googlestd.NewFromFile(redirectURL, credFile, scopes, secret)
	if err != nil {
		glog.Fatalf("failed to setup google auth: %v", err)
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
	user, ok := googlestd.UserFromContext(r.Context())
	if !ok {
		user.Name = "no user"
	}
	writeJSON(w, map[string]string{"Hello": "from private", "user": user.Email})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
