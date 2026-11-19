// Package zalando contains Zalando specific definitions for
// authorization.
package zalando

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	ginoauth2 "github.com/zalando/gin-oauth2"
	"golang.org/x/oauth2"
)

// AccessTuples has to be set by the client to grant access.
var AccessTuples []AccessTuple

// AccessTuple is the type defined for use in AccessTuples.
type AccessTuple struct {
	Realm string `yaml:"realm,omitempty"` // p.e. "employees", "services"
	//lint:ignore ST1003 public interface
	Uid string `yaml:"uid,omitempty"` // UnixName
	Cn  string `yaml:"cn,omitempty"`  // RealName
}

// TeamInfo is defined like in TeamAPI json.
type TeamInfo struct {
	//lint:ignore ST1003 public interface
	Id string
	//lint:ignore ST1003 public interface
	Id_name string
	//lint:ignore ST1003 public interface
	Team_id string
	Type    string
	Name    string
	Mail    []string
}

// OAuth2Endpoint is similar to the definitions in golang.org/x/oauth2
var OAuth2Endpoint = oauth2.Endpoint{
	AuthURL:  "https://identity.zalando.com/oauth2/token",
	TokenURL: "https://info.services.auth.zalando.com/oauth2/tokeninfo",
}

// TeamAPI is a custom API
var TeamAPI string = "https://teams.auth.zalando.com/api/teams"

// RequestTeamInfo is a function that returns team information for a
// given token.
func RequestTeamInfo(ctx context.Context, tc *ginoauth2.TokenContainer, uri string) ([]byte, error) {
	var uv = make(url.Values)
	uv.Set("member", tc.Scopes["uid"].(string))
	infoURL := uri + "?" + uv.Encode()
	client := &http.Client{Transport: &ginoauth2.Transport}
	req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tc.Token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func uidOf(tc *ginoauth2.TokenContainer) (string, bool) {
	uid, ok := tc.Scopes["uid"].(string)
	return uid, ok
}

// GroupCheckValues is the framework independent implementation of
// GroupCheck. It returns the values to expose to the handler ("uid"
// and "team" of the official team) and whether access is granted.
// The values are returned even if access is not granted.
func GroupCheckValues(ctx context.Context, at []AccessTuple, tc *ginoauth2.TokenContainer) (map[string]any, bool) {
	uid, ok := uidOf(tc)
	if !ok {
		glog.Errorf("[Gin-OAuth] token has no uid scope")
		return nil, false
	}
	blob, err := RequestTeamInfo(ctx, tc, TeamAPI)
	if err != nil {
		glog.Errorf("[Gin-OAuth] failed to get team info, caused by: %s", err)
		return nil, false
	}
	var data []TeamInfo
	err = json.Unmarshal(blob, &data)
	if err != nil {
		glog.Errorf("[Gin-OAuth] JSON.Unmarshal failed, caused by: %s", err)
		return nil, false
	}
	values := map[string]any{}
	granted := false
	for _, teamInfo := range data {
		for idx := range at {
			if teamInfo.Id == at[idx].Uid {
				granted = true
				glog.Infof("[Gin-OAuth] Grant access to %s as team member of \"%s\"\n", uid, teamInfo.Id)
			}
			if teamInfo.Type == "official" {
				values["uid"] = uid
				values["team"] = teamInfo.Id
			}
		}
	}
	return values, granted
}

// UIDCheckValues is the framework independent implementation of
// UidCheck. It returns the values to expose to the handler ("uid" and
// "cn") and whether access is granted.
func UIDCheckValues(at []AccessTuple, tc *ginoauth2.TokenContainer) (map[string]any, bool) {
	uid, ok := uidOf(tc)
	if !ok {
		return nil, false
	}
	for idx := range at {
		if tc.Realm == at[idx].Realm && uid == at[idx].Uid {
			glog.Infof("[Gin-OAuth] Grant access to %s\n", uid)
			return map[string]any{"uid": uid, "cn": at[idx].Cn}, true
		}
	}
	return nil, false
}

// ScopeCheckValues is the framework independent implementation of
// ScopeCheck. It returns the values of the matching scopes and "uid"
// to expose to the handler and whether access is granted.
func ScopeCheckValues(tc *ginoauth2.TokenContainer, scopes ...string) (map[string]any, bool) {
	values := map[string]any{}
	found := 0
	for _, s := range scopes {
		if cur, ok := tc.Scopes[s]; ok {
			glog.V(2).Infof("Found configured scope %s", s)
			found++
			values[s] = cur
		}
	}
	//Getting the uid for identification of the service calling
	if cur, ok := tc.Scopes["uid"]; ok {
		values["uid"] = cur
	}
	return values, found > 0
}

// ScopeAndCheckValues is the framework independent implementation of
// ScopeAndCheck. It returns the values of the matching scopes and
// "uid" to expose to the handler and whether access is granted.
func ScopeAndCheckValues(tc *ginoauth2.TokenContainer, scopes ...string) (map[string]any, bool) {
	values := map[string]any{}
	for _, s := range scopes {
		cur, ok := tc.Scopes[s]
		if !ok {
			return values, false
		}
		glog.V(2).Infof("Found configured scope %s", s)
		values[s] = cur
	}
	//Getting the uid for identification of the service calling
	if cur, ok := tc.Scopes["uid"]; ok {
		values["uid"] = cur
	}
	return values, true
}

// NoAuthorizationValues is the framework independent implementation
// of NoAuthorization. It returns the values to expose to the handler
// ("uid" and "team") and whether access is granted.
func NoAuthorizationValues(ctx context.Context, tc *ginoauth2.TokenContainer) (map[string]any, bool) {
	uid, ok := uidOf(tc)
	if !ok {
		return nil, false
	}
	blob, err := RequestTeamInfo(ctx, tc, TeamAPI)
	if err != nil {
		return nil, false
	}

	var data []TeamInfo
	err = json.Unmarshal(blob, &data)
	if err != nil {
		glog.Errorf("[Gin-OAuth] JSON.Unmarshal failed, caused by: %s", err)
		return nil, false
	}
	for _, teamInfo := range data {
		if teamInfo.Type == "official" {
			return map[string]any{"uid": uid, "team": teamInfo.Id}, true
		}
	}
	return nil, true
}

func requestContext(ctx *gin.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx.Request != nil {
		base = ctx.Request.Context()
	}
	return context.WithTimeout(base, ginoauth2.VarianceTimer)
}

func apply(ctx *gin.Context, values map[string]any) {
	for k, v := range values {
		ctx.Set(k, v)
	}
}

// GroupCheck is an authorization function that checks, if the Token
// was issued for an employee of a specified team. The given
// TokenContainer must be valid. As side effect it sets "uid" and
// "team" in the gin.Context to the "official" team.
func GroupCheck(at []AccessTuple) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		reqCtx, cancel := requestContext(ctx)
		defer cancel()
		values, granted := GroupCheckValues(reqCtx, ats, tc)
		apply(ctx, values)
		return granted
	}
}

// UidCheck is an authorization function that checks UID scope
// TokenContainer must be Valid. As side effect it sets "uid" and
// "cn" in the gin.Context to the authorized uid and cn (Realname).
//
//lint:ignore ST1003 public interface
func UidCheck(at []AccessTuple) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		values, granted := UIDCheckValues(ats, tc)
		apply(ctx, values)
		return granted
	}
}

// ScopeCheck does an OR check of scopes given from token of the
// request to all provided scopes. If one of provided scopes is in the
// Scopes of the token it grants access to the resource.
func ScopeCheck(name string, scopes ...string) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	glog.Infof("ScopeCheck %s configured to grant access for scopes: %v", name, scopes)
	configuredScopes := scopes
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		values, granted := ScopeCheckValues(tc, configuredScopes...)
		apply(ctx, values) // set value from token of configured scope to the context, which you can use in your application.
		return granted
	}
}

// ScopeAndCheck does an AND check of scopes given from token of the
// request to all provided scopes. Only if all of provided scopes are found in the
// Scopes of the token it grants access to the resource.
func ScopeAndCheck(name string, scopes ...string) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	glog.Infof("ScopeCheck %s configured to grant access only if scopes: %v are present", name, scopes)
	configuredScopes := scopes
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		values, granted := ScopeAndCheckValues(tc, configuredScopes...)
		apply(ctx, values) // set value from token of configured scope to the context, which you can use in your application.
		return granted
	}
}

// NoAuthorization sets "team" and "uid" in the context without
// checking if the user/team is authorized.
func NoAuthorization() func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		reqCtx, cancel := requestContext(ctx)
		defer cancel()
		values, granted := NoAuthorizationValues(reqCtx, tc)
		apply(ctx, values)
		return granted
	}
}
