// Package stdlib provides GitHub sign-in for plain net/http
// handlers. It is the net/http counterpart of package
// github.com/zalando/gin-oauth2/github and uses the same session
// layout, so cookies issued by one are accepted by the other if
// session name and secret match.
//
// Example:
//
//	p, err := githubstd.New(githubstd.Config{
//		RedirectURL:  "http://127.0.0.1:8081/auth/",
//		ClientID:     id,
//		ClientSecret: secret,
//		Scopes:       []string{"repo"},
//		SessionKey:   []byte("secret"),
//	})
//	mux.Handle("GET /login", p.LoginHandler())
//	mux.Handle("GET /auth/", p.Auth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		user, _ := githubstd.UserFromContext(r.Context())
//		fmt.Fprintln(w, user.Login)
//	})))
package stdlib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/golang/glog"
	gogithub "github.com/google/go-github/github"
	ginoauth2gh "github.com/zalando/gin-oauth2/github"
	"github.com/zalando/gin-oauth2/internal/oauthsession"
	"github.com/zalando/gin-oauth2/stdlib"
	"golang.org/x/oauth2"
	oauth2gh "golang.org/x/oauth2/github"
)

const (
	stateKey       = "state"
	sessionID      = "ginoauthgh"
	defaultSession = "ginoauth_github"
	userContextKey = "user"
)

// AuthUser is the user information stored in the session and the
// request context. It is the same type as used by the gin provider.
type AuthUser = ginoauth2gh.AuthUser

// Credentials stores github client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

// Config configures a Provider.
type Config struct {
	RedirectURL  string
	ClientID     string
	ClientSecret string
	Scopes       []string

	// SessionKey signs the session cookie, required.
	SessionKey []byte
	// EncryptionKey is optional and encrypts the session cookie
	// (16, 24 or 32 bytes).
	EncryptionKey []byte
	// SessionName is the cookie name, defaults to "ginoauth_github".
	SessionName string

	// Endpoint defaults to GitHub's OAuth2 endpoint.
	Endpoint oauth2.Endpoint
	// APIBaseURL overrides the base URL of the GitHub API, which is
	// useful for GitHub Enterprise. It must end with a slash.
	APIBaseURL string
}

// Provider implements GitHub sign-in for net/http. It is safe for
// concurrent use.
type Provider struct {
	conf        *oauth2.Config
	store       *oauthsession.Store
	sessionName string
	apiBaseURL  *url.URL
}

// New creates a Provider.
func New(c Config) (*Provider, error) {
	if len(c.SessionKey) == 0 {
		return nil, errors.New("github: SessionKey is required")
	}
	if c.ClientID == "" {
		return nil, errors.New("github: ClientID is required")
	}
	ru, err := url.ParseRequestURI(c.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("github: invalid RedirectURL: %w", err)
	}
	var base *url.URL
	if c.APIBaseURL != "" {
		base, err = url.Parse(c.APIBaseURL)
		if err != nil {
			return nil, fmt.Errorf("github: invalid APIBaseURL: %w", err)
		}
		if !strings.HasSuffix(base.Path, "/") {
			base.Path += "/"
		}
	}
	endpoint := c.Endpoint
	if endpoint == (oauth2.Endpoint{}) {
		endpoint = oauth2gh.Endpoint
	}
	name := c.SessionName
	if name == "" {
		name = defaultSession
	}
	return &Provider{
		conf: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Scopes:       c.Scopes,
			Endpoint:     endpoint,
		},
		store:       oauthsession.NewStore(ru.Scheme == "https", c.SessionKey, c.EncryptionKey),
		sessionName: name,
		apiBaseURL:  base,
	}, nil
}

// NewFromFile is like New and reads the client credentials from a
// JSON file ({"clientid": "...", "secret": "..."}), like
// github.Setup.
func NewFromFile(redirectURL, credFile string, scopes []string, secret []byte) (*Provider, error) {
	file, err := os.ReadFile(credFile)
	if err != nil {
		return nil, fmt.Errorf("github: reading credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(file, &c); err != nil {
		return nil, fmt.Errorf("github: parsing credentials: %w", err)
	}
	return New(Config{
		RedirectURL:  redirectURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       scopes,
		SessionKey:   secret,
	})
}

// GetLoginURL returns the URL of GitHub's consent page for state.
func (p *Provider) GetLoginURL(state string) string {
	return p.conf.AuthCodeURL(state)
}

var loginPage = template.Must(template.New("login").Parse(`<html><title>Golang Github</title> <body> <a href='{{.}}'><button>Login with GitHub!</button> </a> </body></html>`))

// LoginHandler stores a fresh state in the session and renders a
// page that links to GitHub's consent page.
func (p *Provider) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := oauthsession.RandomState()
		if err != nil {
			glog.Errorf("[Gin-OAuth] Failed to read rand: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		sess := p.store.Load(r, p.sessionName)
		sess.Values[stateKey] = state
		if err := p.store.Save(w, r, sess); err != nil {
			glog.Errorf("[Gin-OAuth] Failed to save session: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginPage.Execute(w, p.GetLoginURL(state)); err != nil {
			glog.Errorf("[Gin-OAuth] Failed to render login page: %v", err)
		}
	})
}

// Auth returns a middleware that only lets requests with a GitHub
// authorized session pass. The user is available in the request
// context via UserFromContext or stdlib.Value[AuthUser](ctx, "user").
//
// Responses: 401 for a missing or invalid state, 400 if the code
// exchange or the user lookup fails and 500 if the session can not be
// saved.
func (p *Provider) Auth() stdlib.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := p.store.Load(r, p.sessionName)

			if user, ok := sess.Values[sessionID].(AuthUser); ok {
				next.ServeHTTP(w, stdlib.WithValue(r, userContextKey, user))
				return
			}

			if !oauthsession.StateMatches(sess.Values[stateKey], r.URL.Query().Get(stateKey)) {
				http.Error(w, "invalid session state", http.StatusUnauthorized)
				return
			}

			ctx := r.Context()
			tok, err := p.conf.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				glog.Errorf("[Gin-OAuth] failed to do exchange: %v", err)
				http.Error(w, "failed to do exchange", http.StatusBadRequest)
				return
			}
			user, err := p.fetchUser(ctx, tok)
			if err != nil {
				glog.Errorf("[Gin-OAuth] failed to get user: %v", err)
				http.Error(w, "failed to get user", http.StatusBadRequest)
				return
			}

			delete(sess.Values, stateKey)
			sess.Values[sessionID] = user
			if err := p.store.Save(w, r, sess); err != nil {
				glog.Errorf("[Gin-OAuth] Failed to save session: %v", err)
				http.Error(w, "failed to save session", http.StatusInternalServerError)
				return
			}
			next.ServeHTTP(w, stdlib.WithValue(r, userContextKey, user))
		})
	}
}

func (p *Provider) fetchUser(ctx context.Context, tok *oauth2.Token) (AuthUser, error) {
	client := gogithub.NewClient(p.conf.Client(ctx, tok))
	if p.apiBaseURL != nil {
		client.BaseURL = p.apiBaseURL
	}
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return AuthUser{}, err
	}
	return AuthUser{
		Login: deref(user.Login),
		Name:  deref(user.Name),
		URL:   deref(user.URL),
	}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// UserFromContext returns the user stored by Auth.
func UserFromContext(ctx context.Context) (AuthUser, bool) {
	return stdlib.Value[AuthUser](ctx, userContextKey)
}
