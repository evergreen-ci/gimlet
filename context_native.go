// +build go1.7

package gimlet

import (
	"context"
	"net/http"
)

func getContext(r *http.Request) context.Context { return r.Context() }
