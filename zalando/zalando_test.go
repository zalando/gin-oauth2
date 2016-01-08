package zalando

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/zalando-techmonkeys/gin-oauth2"
	"golang.org/x/oauth2"
)

func TestRequestTeamInfo(t *testing.T) {
	ginoauth2.AuthInfoURL = OAuth2Endpoint.TokenURL
	input := "YOUR_TOKEN_HERE"
	token := oauth2.Token{
		AccessToken: input,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(600) * time.Second),
	}
	tc, err := ginoauth2.GetTokenContainer(&token)
	if err != nil {
		t.FailNow()
	}
	resp, _ := RequestTeamInfo(tc, TeamAPI)
	var data []TeamInfo
	err = json.Unmarshal(resp, &data)
	if err != nil {
		t.FailNow()
	}
	fmt.Printf("%+v\n", data)
}
