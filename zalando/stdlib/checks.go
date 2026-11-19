// Package stdlib contains the Zalando specific authorization checks
// for the net/http middleware of github.com/zalando/gin-oauth2/stdlib.
// The checks set the same values ("uid", "team", "cn" and scope
// names) as their gin counterparts in package zalando. Handlers read
// them with stdlib.Value.
package stdlib

import (
	"net/http"

	ginoauth2 "github.com/zalando/gin-oauth2"
	stdmw "github.com/zalando/gin-oauth2/stdlib"
	"github.com/zalando/gin-oauth2/zalando"
)

func check(values map[string]any, granted bool, r *http.Request) (*http.Request, bool) {
	return stdmw.WithValues(r, values), granted
}

// GroupCheck checks, if the Token was issued for an employee of a
// specified team. As side effect it sets "uid" and "team" of the
// "official" team in the request context.
func GroupCheck(at []zalando.AccessTuple) stdmw.AccessCheckFunction {
	return func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
		values, granted := zalando.GroupCheckValues(r.Context(), at, tc)
		return check(values, granted, r)
	}
}

// UidCheck checks the UID scope. As side effect it sets "uid" and
// "cn" in the request context to the authorized uid and cn (Realname).
//
//lint:ignore ST1003 public interface
func UidCheck(at []zalando.AccessTuple) stdmw.AccessCheckFunction {
	return func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
		values, granted := zalando.UIDCheckValues(at, tc)
		return check(values, granted, r)
	}
}

// ScopeCheck does an OR check of scopes given from token of the
// request to all provided scopes. If one of provided scopes is in the
// Scopes of the token it grants access to the resource. The values
// of matching scopes and "uid" are set in the request context.
func ScopeCheck(scopes ...string) stdmw.AccessCheckFunction {
	return func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
		values, granted := zalando.ScopeCheckValues(tc, scopes...)
		return check(values, granted, r)
	}
}

// ScopeAndCheck does an AND check of scopes given from token of the
// request to all provided scopes. Only if all of provided scopes are
// found in the Scopes of the token it grants access to the resource.
// The values of the scopes and "uid" are set in the request context.
func ScopeAndCheck(scopes ...string) stdmw.AccessCheckFunction {
	return func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
		values, granted := zalando.ScopeAndCheckValues(tc, scopes...)
		return check(values, granted, r)
	}
}

// NoAuthorization sets "team" and "uid" in the request context
// without checking if the user/team is authorized.
func NoAuthorization() stdmw.AccessCheckFunction {
	return func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool) {
		values, granted := zalando.NoAuthorizationValues(r.Context(), tc)
		return check(values, granted, r)
	}
}
