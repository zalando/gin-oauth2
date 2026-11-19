package stdlib

import (
	"context"
	"net/http"

	ginoauth2 "github.com/zalando/gin-oauth2"
)

type tokenContainerKey struct{}

type valueKey string

// TokenContainerFromContext returns the TokenContainer that was
// stored in the context by the authorization middleware.
func TokenContainerFromContext(ctx context.Context) (*ginoauth2.TokenContainer, bool) {
	tc, ok := ctx.Value(tokenContainerKey{}).(*ginoauth2.TokenContainer)
	return tc, ok && tc != nil
}

// WithValue returns a shallow copy of r whose context carries the
// value v under key. It is the stdlib counterpart of gin's
// Context.Set and is meant to be used by AccessCheckFunction
// implementations.
func WithValue(r *http.Request, key string, v any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), valueKey(key), v))
}

// WithValues is like WithValue for multiple key/value pairs.
func WithValues(r *http.Request, values map[string]any) *http.Request {
	if len(values) == 0 {
		return r
	}
	ctx := r.Context()
	for k, v := range values {
		ctx = context.WithValue(ctx, valueKey(k), v)
	}
	return r.WithContext(ctx)
}

// Value returns the value stored under key by an access check, for
// example "uid", "team" or "cn". It is the stdlib counterpart of
// gin's Context.Get.
func Value[T any](ctx context.Context, key string) (T, bool) {
	v, ok := ctx.Value(valueKey(key)).(T)
	return v, ok
}
