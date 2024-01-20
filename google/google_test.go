package google

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupFromString(t *testing.T) {
	t.Run("should assign store and config accordingly", func(t *testing.T) {
		store = nil
		conf = nil
		SetupFromString("http://fake.fake", "clientid", "clientsecret", []string{}, []byte("secret"))
		assert.NotNil(t, conf)
		assert.NotNil(t, store)
		assert.Equal(t, conf.ClientID, "clientid")
		assert.Equal(t, conf.ClientSecret, "clientsecret")
	})
}

func TestWithLoginURL(t *testing.T) {

	var testCases = []struct {
		description    string
		urlParm        string
		expectUrlLogin string
		isErrNil       bool
	}{
		{
			description:    "should assign a valid url without error",
			urlParm:        "http://fake.fake",
			expectUrlLogin: "http://fake.fake",
			isErrNil:       true,
		},
		{
			description:    "should assign a sanitizable url without error",
			urlParm:        " http://fake.fake   ",
			expectUrlLogin: "http://fake.fake",
			isErrNil:       true,
		},
		{
			description:    "should not assign an invalid url, and should return an error",
			urlParm:        "not a parseable url",
			expectUrlLogin: "",
			isErrNil:       false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			loginURL = ""
			err := WithLoginURL(testCase.urlParm)
			assert.Equal(t, testCase.expectUrlLogin, loginURL)
			assert.Equal(t, testCase.isErrNil, err == nil)
		})
	}
}
