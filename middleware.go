package gimlet

import "github.com/urfave/negroni"

// Middleware is a local alias for negroni.Handler types.
type Middleware negroni.Handler

type contextKey string

const (
	requestIDKey contextKey = "request-id"
	loggerKey               = "logger"
	startAtKey              = "start-at"
)
