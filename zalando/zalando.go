// Package zalando contains Zalando specific definitions for
// authorization.
package zalando

import (
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
	Uid   string `yaml:"uid,omitempty"`   // UnixName
	Cn    string `yaml:"cn,omitempty"`    // RealName
}

// TeamInfo is defined like in TeamAPI json.
type TeamInfo struct {
	Id      string
	Id_name string
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
func RequestTeamInfo(tc *ginoauth2.TokenContainer, uri string) ([]byte, error) {
	var uv = make(url.Values)
	uv.Set("member", tc.Scopes["uid"].(string))
	info_url := uri + "?" + uv.Encode()
	client := &http.Client{Transport: &ginoauth2.Transport}
	req, err := http.NewRequest("GET", info_url, nil)
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

// GroupCheck is an authorization function that checks, if the Token
// was issued for an employee of a specified team. The given
// TokenContainer must be valid. As side effect it sets "uid" and
// "team" in the gin.Context to the "official" team.
func GroupCheck(at []AccessTuple) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		blob, err := RequestTeamInfo(tc, TeamAPI)
		if err != nil {
			glog.Errorf("[Gin-OAuth] failed to get team info, caused by: %s", err)
			return false
		}
		var data []TeamInfo
		err = json.Unmarshal(blob, &data)
		if err != nil {
			glog.Errorf("[Gin-OAuth] JSON.Unmarshal failed, caused by: %s", err)
			return false
		}
		granted := false
		for _, teamInfo := range data {
			for idx := range ats {
				at := ats[idx]
				if teamInfo.Id == at.Uid {
					granted = true
					glog.Infof("[Gin-OAuth] Grant access to %s as team member of \"%s\"\n", tc.Scopes["uid"].(string), teamInfo.Id)
				}
				if teamInfo.Type == "official" {
					ctx.Set("uid", tc.Scopes["uid"].(string))
					ctx.Set("team", teamInfo.Id)
				}
			}
		}
		return granted
	}
}

// UidCheck is an authorization function that checks UID scope
// TokenContainer must be Valid. As side effect it sets "uid" and
// "cn" in the gin.Context to the authorized uid and cn (Realname).
func UidCheck(at []AccessTuple) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		uid := tc.Scopes["uid"].(string)
		for idx := range ats {
			at := ats[idx]
			if tc.Realm == at.Realm && uid == at.Uid {
				ctx.Set("uid", uid)  //in this way I can set the authorized uid
				ctx.Set("cn", at.Cn) //in this way I can set the authorized Realname
				glog.Infof("[Gin-OAuth] Grant access to %s\n", uid)
				return true
			}
		}
		return false
	}
}

// ScopeCheck does an OR check of scopes given from token of the
// request to all provided scopes. If one of provided scopes is in the
// Scopes of the token it grants access to the resource.
func ScopeCheck(name string, scopes ...string) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	glog.Infof("ScopeCheck %s configured to grant access for scopes: %v", name, scopes)
	configuredScopes := scopes
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		scopesFromToken := make([]string, 0)
		for _, s := range configuredScopes {
			if cur, ok := tc.Scopes[s]; ok {
				glog.V(2).Infof("Found configured scope %s", s)
				scopesFromToken = append(scopesFromToken, s)
				ctx.Set(s, cur) // set value from token of configured scope to the context, which you can use in your application.
			}
		}
		//Getting the uid for identification of the service calling
		if cur, ok := tc.Scopes["uid"]; ok {
			ctx.Set("uid", cur)
		}
		return len(scopesFromToken) > 0
	}
}

// ScopeAndCheck does an AND check of scopes given from token of the
// request to all provided scopes. Only if all of provided scopes are found in the
// Scopes of the token it grants access to the resource.
func ScopeAndCheck(name string, scopes ...string) func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	glog.Infof("ScopeCheck %s configured to grant access only if scopes: %v are present", name, scopes)
	configuredScopes := scopes
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		scopesFromToken := make([]string, 0)
		for _, s := range configuredScopes {
			if cur, ok := tc.Scopes[s]; ok {
				glog.V(2).Infof("Found configured scope %s", s)
				scopesFromToken = append(scopesFromToken, s)
				ctx.Set(s, cur) // set value from token of configured scope to the context, which you can use in your application.
			} else {
				return false
			}
		}
		//Getting the uid for identification of the service calling
		if cur, ok := tc.Scopes["uid"]; ok {
			ctx.Set("uid", cur)
		}
		return true
	}
}

// NoAuthorization sets "team" and "uid" in the context without
// checking if the user/team is authorized.
func NoAuthorization() func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
	return func(tc *ginoauth2.TokenContainer, ctx *gin.Context) bool {
		blob, err := RequestTeamInfo(tc, TeamAPI)
		var data []TeamInfo
		err = json.Unmarshal(blob, &data)
		if err != nil {
			glog.Errorf("[Gin-OAuth] JSON.Unmarshal failed, caused by: %s", err)
		}
		for _, teamInfo := range data {
			if teamInfo.Type == "official" {
				ctx.Set("uid", tc.Scopes["uid"].(string))
				ctx.Set("team", teamInfo.Id)
				return true
			}
		}
		return true
	}
}
