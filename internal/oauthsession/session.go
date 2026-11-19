// Package oauthsession contains the cookie session handling shared by
// the net/http based google and github providers.
package oauthsession

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"

	"github.com/gorilla/sessions"
)

// Store is a signed (and optionally encrypted) cookie session store.
type Store struct {
	store *sessions.CookieStore
}

// NewStore creates a Store. authKey signs the cookie, encKey is
// optional and encrypts it. Cookies are HttpOnly and SameSite=Lax,
// which is required to survive the redirect back from the provider.
func NewStore(secure bool, authKey, encKey []byte) *Store {
	keys := [][]byte{authKey}
	if len(encKey) > 0 {
		keys = append(keys, encKey)
	}
	s := sessions.NewCookieStore(keys...)
	s.Options.Path = "/"
	s.Options.HttpOnly = true
	s.Options.Secure = secure
	s.Options.SameSite = http.SameSiteLaxMode
	return &Store{store: s}
}

// Load returns the session named name. A missing, tampered or
// otherwise undecodable cookie yields a fresh empty session.
func (s *Store) Load(r *http.Request, name string) *sessions.Session {
	sess, _ := s.store.New(r, name)
	if sess.Values == nil {
		sess.Values = make(map[interface{}]interface{})
	}
	return sess
}

// Save writes the session cookie to w.
func (s *Store) Save(w http.ResponseWriter, r *http.Request, sess *sessions.Session) error {
	return s.store.Save(r, w, sess)
}

// RandomState returns an unguessable value for the OAuth2 state parameter.
func RandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// StateMatches reports whether the state stored in the session equals
// the state returned by the provider. Empty states never match.
func StateMatches(stored interface{}, got string) bool {
	s, ok := stored.(string)
	if !ok || s == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s), []byte(got)) == 1
}
