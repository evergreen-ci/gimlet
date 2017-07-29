// +build !go1.7

package gimlet

import (
	"net/http"

	"golang.org/x/net/context"
)

func getContext(_ *http.Request) context.Context { return context.Background() }
