package ginoauth2

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

type mockLogger struct{ buffer bytes.Buffer }

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	m.buffer.WriteString(fmt.Sprintf("ERROR: "+format, args...))
}
func (m *mockLogger) Infof(format string, args ...interface{}) {
	m.buffer.WriteString(fmt.Sprintf("INFO: "+format, args...))
}
func (m *mockLogger) Debugf(format string, args ...interface{}) {
	m.buffer.WriteString(fmt.Sprintf("DEBUG: "+format, args...))
}

func TestLogWithMaskedAccessToken(t *testing.T) {
	mockLog := &mockLogger{}
	DefaultLogger = mockLog
	tests := []struct{ name, input, expected string }{
		{"With access token", "&access_token=abcdefghijklmnop&", "INFO: <MASK>&"},
		{"Without access token", "no_token_here", "INFO: no_token_here"},
		{"Empty string", "", "INFO: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLog.buffer.Reset()

			infof("%s", tt.input)

			logOutput := mockLog.buffer.String()
			if logOutput != tt.expected {
				t.Errorf("Expected log to contain %q, got %q", tt.expected, logOutput)
			}
			if strings.Contains(logOutput, "abcdefghijklmnop") {
				t.Errorf("Log should not contain the original token")
			}
		})
	}
}
