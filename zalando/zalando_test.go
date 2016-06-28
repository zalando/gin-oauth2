package zalando

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/zalando/gin-oauth2"
	"golang.org/x/oauth2"
)

// You have to have a current file $HOME/.chimp-token with only a
// valid Zalando access token.
var tokenFile string = fmt.Sprintf("%s/.chimp-token", os.Getenv("HOME"))

func getToken() (string, error) {
	file, err := os.Open(tokenFile)
	if err != nil {
		return "not a file", err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "reading failed", err
	}
	return string(data), nil
}

func TestRequestTeamInfo(t *testing.T) {
	ginoauth2.AuthInfoURL = OAuth2Endpoint.TokenURL
	accessToken, err := getToken()
	if err != nil {
		fmt.Printf("ERR: Could not get Access Token from file, caused by %q.", accessToken)
		t.FailNow()
	}

	token := oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(600) * time.Second),
	}
	tc, err := ginoauth2.GetTokenContainer(&token)
	if err != nil {
		fmt.Printf("ERR: Could not get TokenContainer from ginoauth2.")
		t.FailNow()
	}
	resp, err := RequestTeamInfo(tc, TeamAPI)
	if err != nil {
		fmt.Printf("ERR: Could not get TeamInfo for TokenContainer from TeamAPI.")
		t.FailNow()
	}
	var data []TeamInfo
	err = json.Unmarshal(resp, &data)
	if err != nil {
		fmt.Printf("ERR: Could not unmarshal json data.")
		t.FailNow()
	}
	fmt.Printf("%+v\n", data)
}
