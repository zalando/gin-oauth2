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
	t.Run("should assign the login url", func(t *testing.T) {
		loginURL = ""
		url := "http://fake.fake"
		WithLoginURL(url)
		assert.NotEmpty(t, url)
		assert.Equal(t, url, loginURL)
	})
}
