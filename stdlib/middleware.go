// Package stdlib implements the OAuth2 based authorization
// middleware of gin-oauth2 for plain net/http handlers. The returned
// middlewares have the shape func(http.Handler) http.Handler and work
// with http.ServeMux and routers such as chi, gorilla/mux or alice.
//
// Example:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/private", stdlib.AuthChain(
//		zalando.OAuth2Endpoint,
//		zalandostd.UidCheck(users),
//	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		uid, _ := stdlib.Value[string](r.Context(), "uid")
//		fmt.Fprintf(w, "hello %s", uid)
//	})))
package stdlib

import (
	"context"
	"errors"
	"net/http"
	"time"

	ginoauth2 "github.com/zalando/gin-oauth2"
	"golang.org/x/oauth2"
)

// AccessCheckFunction checks if a given token grants access. It
// returns the request to pass to the next handler, which can carry
// additional values added via WithValue, and whether access is
// granted. Checks that do network I/O should use r.Context(), which
// is bound to ginoauth2.VarianceTimer.
type AccessCheckFunction func(tc *ginoauth2.TokenContainer, r *http.Request) (*http.Request, bool)

// Middleware is a net/http middleware.
type Middleware = func(http.Handler) http.Handler

// Auth returns a middleware that authenticates the request using the
// tokeninfo endpoint and authorizes it with the access check
// function.
func Auth(accessCheckFunction AccessCheckFunction, endpoint oauth2.Endpoint) Middleware {
	return AuthChain(endpoint, accessCheckFunction)
}

// AuthChain is similar to Auth, but takes a chain of
// AccessCheckFunctions. Access is granted by the first function that
// returns true and denied only if all of them fail.
func AuthChain(endpoint oauth2.Endpoint, accessCheckFunctions ...AccessCheckFunction) Middleware {
	return AuthChainOptions(ginoauth2.Options{Endpoint: endpoint}, accessCheckFunctions...)
}

// AuthChainOptions is like AuthChain with additional Options.
//
// Responses: 401 and a Location header pointing to
// Endpoint.AuthURL for a missing, invalid or expired token, 403 if
// no access check grants access and 504 if the check takes longer
// than ginoauth2.VarianceTimer.
func AuthChainOptions(o ginoauth2.Options, accessCheckFunctions ...AccessCheckFunction) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ctx, cancel := context.WithTimeout(r.Context(), ginoauth2.VarianceTimer)
			defer cancel()

			out, status, err := authorize(ctx, o, accessCheckFunctions, r.WithContext(ctx))
			if err != nil {
				if r.Context().Err() != nil {
					// client went away, nobody to respond to
					return
				}
				if status == http.StatusUnauthorized {
					// let the user easily find where to get a new access-token
					w.Header().Set("Location", o.Endpoint.AuthURL)
				}
				ginoauth2.DefaultLogger.Debugf("[Gin-OAuth] %12v %s access not allowed: %s", time.Since(start), r.URL.Path, err)
				http.Error(w, http.StatusText(status), status)
				return
			}

			ginoauth2.DefaultLogger.Debugf("[Gin-OAuth] %12v %s access allowed", time.Since(start), r.URL.Path)
			next.ServeHTTP(w, detach(r, out))
		})
	}
}

func authorize(ctx context.Context, o ginoauth2.Options, checks []AccessCheckFunction, r *http.Request) (*http.Request, int, error) {
	fail := func(status int, err error) (*http.Request, int, error) {
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, http.StatusGatewayTimeout, errors.New("authorization check overtime")
		}
		return nil, status, err
	}

	token, err := ginoauth2.ExtractToken(r)
	if err != nil {
		return fail(http.StatusUnauthorized, err)
	}
	if !token.Valid() {
		return fail(http.StatusUnauthorized, errors.New("invalid token - nil or expired"))
	}

	tc, err := ginoauth2.GetTokenContainerContext(ctx, o, token)
	if err != nil {
		return fail(http.StatusUnauthorized, err)
	}
	if !tc.Valid() {
		return fail(http.StatusUnauthorized, errors.New("invalid token"))
	}

	r = r.WithContext(context.WithValue(r.Context(), tokenContainerKey{}, tc))
	for _, fn := range checks {
		if next, ok := fn(tc, r); ok {
			if ctx.Err() != nil {
				return fail(http.StatusForbidden, ctx.Err())
			}
			if next == nil {
				next = r
			}
			return next, http.StatusOK, nil
		}
	}
	return fail(http.StatusForbidden, errors.New("access to the resource is forbidden"))
}

// detach returns out with a context that keeps all values added
// during authorization, but is not bound to the authorization
// timeout. Cancellation of the original request is still propagated.
func detach(orig, out *http.Request) *http.Request {
	return out.WithContext(&valuesContext{Context: orig.Context(), values: out.Context()})
}

type valuesContext struct {
	context.Context // deadline, cancellation and fallback values of the original request
	values          context.Context
}

func (c *valuesContext) Value(key any) any {
	if v := c.values.Value(key); v != nil {
		return v
	}
	return c.Context.Value(key)
}
