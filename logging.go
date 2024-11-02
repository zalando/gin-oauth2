package ginoauth2

import (
	"fmt"
	"io"
	"os"

	"github.com/golang/glog"
)

// Logger is the interface used by GinOAuth2 to log messages.
type Logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

type glogLogger struct {
	output io.Writer
}

// DefaultLogger is the default logger used by GinOAuth2 if no other logger is provided.
// To use a different logger, set the DefaultLogger variable to a logger of your choice.
// Replacement loggers must implement the Logger interface.
//
// Example:
//
//	import "github.com/zalando/gin-oauth2"
//
//	ginoauth2.DefaultLogger = &logrusLogger{} // use logrus
var DefaultLogger Logger = &glogLogger{output: os.Stderr}

func maskLogArgs(args ...interface{}) []interface{} {
	for i := range args {
		args[i] = maskAccessToken(args[i])
	}

	return args
}

// SetOutput sets the output destination for the logger
func (gl *glogLogger) setOutput(w io.Writer) {
	gl.output = w
}

// Errorf is a logging function using glog.Errorf
func (gl *glogLogger) Errorf(f string, args ...interface{}) {
	glog.ErrorDepth(1, fmt.Sprintf(f, args...))
	if gl.output != nil {
		fmt.Fprintf(gl.output, f+"\n", args...)
	}
}

// Infof is a logging function using glog.Infof
func (gl *glogLogger) Infof(f string, args ...interface{}) {
	glog.InfoDepth(1, fmt.Sprintf(f, args...))
	if gl.output != nil {
		fmt.Fprintf(gl.output, f+"\n", args...)
	}
}

// Debugf is a verbose logging function using glog.V(2)
func (gl *glogLogger) Debugf(f string, args ...interface{}) {
	if glog.V(2) {
		glog.InfoDepth(1, fmt.Sprintf(f, args...))
	}
	if gl.output != nil {
		fmt.Fprintf(gl.output, f+"\n", args...)
	}
}

func errorf(f string, args ...interface{}) {
	DefaultLogger.Errorf(f, maskLogArgs(args...)...)
}

func infof(f string, args ...interface{}) {
	DefaultLogger.Infof(f, maskLogArgs(args...)...)
}

func infofv2(f string, args ...interface{}) {
	DefaultLogger.Debugf(f, maskLogArgs(args...)...)
}
