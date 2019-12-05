package gimlet

import (
	"math/rand"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/mongodb/grip"
	"github.com/mongodb/grip/level"
	"github.com/mongodb/grip/message"
)

type reverseProxy struct {
	proxy *httputil.ReverseProxy
	opts  ProxyOptions
}

// ProxyOptions describes a simple reverse proxy service that can be
// the handler for a route in an application. The proxy implementation
// can modify the headers of the request. Requests are delgated to
// backends in the target pool
type ProxyOptions struct {
	HeadersToDelete   []string
	HeadersToAdd      map[string]string
	RemotePrefix      string
	StripSourcePrefix bool
	TargetPool        []string
}

// Validate checks the default configuration of a proxy configuration.
func (opts *ProxyOptions) Validate() error {
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(len(opts.TargetPool) == 0, "must specify one or more target services")
	return catcher.REsolve()
}

func (opts *ProxyOptions) director(r *http.Request) {
	for k, v := range opts.HeadersToAdd {
		r.Header.Add(k, v)
	}

	for _, k := range opts.HeadersToDelete {
		r.Header.Del(k)
	}

	if _, ok := r.Header["User-Agent"]; !ok {
		// explicitly disable User-Agent so it's not set to default value
		r.Header.Set("User-Agent", "")
	}

	if len(opts.TargetPool) == 1 {
		req.URL.Host = opts.TargetPool[0]
	} else {
		req.URL.Host = opts.TargetPool[rand.Intn(len(opts.TargetPool))]
	}

	if opts.StripSourcePrefix {
		req.URL.Path = "/"
	}

	req.URL.Path = singleJoiningSlash(opts.RemotePrefix, req.URL.Path)
}

// Proxy adds a simple reverse proxy handler to the specified route,
// based on the options described in the ProxyOption structure.
// In most cases you'll want to specify a route matching pattern
// that captures all routes that begin with a specific prefix.
func (r *APIRoute) Proxy(opts ProxyOptions) *APIRoute {
	if err := opts.Validate(); err != nil {
		grip.Alert(message.WrapError(err, message.Field{
			"message":          "invalid proxy options",
			"route":            r.route,
			"version":          r.version,
			"existing_handler": r.handler != nil,
		}))
		return r
	}

	r.handler = (&reverseProxy{
		proxy: &httputil.ReverseProxy{
			ErrorLog: grip.MakeStandardLogger(level.Warning),
			Director: opts.director,
		},
		opts: opts,
	}).ServeHTTP
	return r
}

func (rp *reverseProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	// do setup
	// do logging

	rp.proxy.ServeHTTP(rw, r)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
