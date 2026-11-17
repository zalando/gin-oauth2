// Package stdlib provides Google sign-in for plain net/http
// handlers. It is the net/http counterpart of package
// github.com/zalando/gin-oauth2/google and uses the same session
// layout, so cookies issued by one are accepted by the other if
// session name and secret match.
//
// Example:
//
//	p, err := googlestd.New(googlestd.Config{
//		RedirectURL:  "http://127.0.0.1:8081/auth/",
//		ClientID:     id,
//		ClientSecret: secret,
//		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
//		SessionKey:   []byte("secret"),
//	})
//	mux.Handle("GET /login", p.LoginHandler())
//	mux.Handle("GET /auth/", p.Auth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		user, _ := googlestd.UserFromContext(r.Context())
//		fmt.Fprintln(w, user.Email)
//	})))
package stdlib

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/zalando/gin-oauth2/internal/oauthsession"
	"github.com/zalando/gin-oauth2/stdlib"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	goauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

const (
	stateKey       = "state"
	sessionID      = "ginoauth_google_session"
	defaultSession = "ginoauth_google"
	userContextKey = "user"
)

func init() {
	gob.Register(goauth.Userinfo{})
}

// Credentials stores google client-ids.
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
	// SessionName is the cookie name, defaults to "ginoauth_google".
	SessionName string

	// LoginURL is optional. If set, unauthenticated requests are
	// redirected there instead of getting a 401.
	LoginURL string

	// Endpoint defaults to Google's OAuth2 endpoint.
	Endpoint oauth2.Endpoint
	// UserinfoURL overrides the base URL of the userinfo API.
	UserinfoURL string
}

// Provider implements Google sign-in for net/http. It is safe for
// concurrent use.
type Provider struct {
	conf        *oauth2.Config
	store       *oauthsession.Store
	sessionName string
	loginURL    string
	userinfoURL string
}

// New creates a Provider.
func New(c Config) (*Provider, error) {
	if len(c.SessionKey) == 0 {
		return nil, errors.New("google: SessionKey is required")
	}
	if c.ClientID == "" {
		return nil, errors.New("google: ClientID is required")
	}
	ru, err := url.ParseRequestURI(c.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("google: invalid RedirectURL: %w", err)
	}
	loginURL := strings.TrimSpace(c.LoginURL)
	if loginURL != "" {
		u, err := url.ParseRequestURI(loginURL)
		if err != nil {
			return nil, fmt.Errorf("google: invalid LoginURL: %w", err)
		}
		loginURL = u.String()
	}
	endpoint := c.Endpoint
	if endpoint == (oauth2.Endpoint{}) {
		endpoint = google.Endpoint
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
		loginURL:    loginURL,
		userinfoURL: c.UserinfoURL,
	}, nil
}

// NewFromFile is like New and reads the client credentials from a
// JSON file ({"clientid": "...", "secret": "..."}), like
// google.Setup.
func NewFromFile(redirectURL, credFile string, scopes []string, secret []byte) (*Provider, error) {
	file, err := os.ReadFile(credFile)
	if err != nil {
		return nil, fmt.Errorf("google: reading credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(file, &c); err != nil {
		return nil, fmt.Errorf("google: parsing credentials: %w", err)
	}
	return New(Config{
		RedirectURL:  redirectURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       scopes,
		SessionKey:   secret,
	})
}

// GetLoginURL returns the URL of Google's consent page for state.
func (p *Provider) GetLoginURL(state string) string {
	return p.conf.AuthCodeURL(state)
}

var loginPage = template.Must(template.New("login").Parse(`<html>
	<head>
		<title>Golang Google</title>
	</head>
	<body>
		<a href='{{.}}'>
			<button>Login with Google!</button>
		</a>
	</body>
</html>`))

// LoginHandler stores a fresh state in the session and renders a
// page that links to Google's consent page.
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

// Auth returns a middleware that only lets requests with a Google
// authorized session pass. The user is available in the request
// context via UserFromContext or stdlib.Value[goauth.Userinfo](ctx, "user").
//
// Responses: a redirect to Config.LoginURL if set, else 401 for a
// missing or invalid state, 400 if the code exchange fails and 500 if
// the userinfo can not be fetched or the session not saved.
func (p *Provider) Auth() stdlib.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := p.store.Load(r, p.sessionName)

			if user, ok := sess.Values[sessionID].(goauth.Userinfo); ok {
				next.ServeHTTP(w, stdlib.WithValue(r, userContextKey, user))
				return
			}

			if !oauthsession.StateMatches(sess.Values[stateKey], r.URL.Query().Get(stateKey)) {
				if p.loginURL != "" {
					http.Redirect(w, r, p.loginURL, http.StatusFound)
					return
				}
				http.Error(w, "invalid session state", http.StatusUnauthorized)
				return
			}

			ctx := r.Context()
			tok, err := p.conf.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				glog.Errorf("[Gin-OAuth] failed to exchange code for oauth token: %v", err)
				http.Error(w, "failed to exchange code for oauth token", http.StatusBadRequest)
				return
			}

			opts := []option.ClientOption{option.WithHTTPClient(p.conf.Client(ctx, tok))}
			if p.userinfoURL != "" {
				opts = append(opts, option.WithEndpoint(p.userinfoURL))
			}
			svc, err := goauth.NewService(ctx, opts...)
			if err != nil {
				glog.Errorf("[Gin-OAuth] Failed to create oauth service: %v", err)
				http.Error(w, "failed to create oauth service", http.StatusInternalServerError)
				return
			}
			info, err := svc.Userinfo.Get().Context(ctx).Do()
			if err != nil {
				glog.Errorf("[Gin-OAuth] Failed to get userinfo for user: %v", err)
				http.Error(w, "failed to get userinfo for user", http.StatusInternalServerError)
				return
			}
			// keep the cookie small: do not persist the API response headers
			user := *info
			user.ServerResponse = googleapi.ServerResponse{}

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

// UserFromContext returns the user stored by Auth.
func UserFromContext(ctx context.Context) (goauth.Userinfo, bool) {
	return stdlib.Value[goauth.Userinfo](ctx, userContextKey)
}
