package gimlet

import (
	"context"
	"net/http"
)

// WriteHTMLResponse writes an HTML response with the specified error code.
func WriteHTMLResponse(ctx context.Context, w http.ResponseWriter, code int, data interface{}) {
	writeResponse(ctx, HTML, w, code, data)
}

// WriteHTML writes the data, converted to text as possible, to the
// response body as HTML with a successful status code.
func WriteHTML(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 200
	WriteHTMLResponse(ctx, w, http.StatusOK, data)
}

// WriteHTMLError write the data, converted to text as possible, to
// the response body as HTML with a bad-request (e.g. 400) response code.
func WriteHTMLError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 400
	WriteHTMLResponse(ctx, w, http.StatusBadRequest, data)
}

// WriteHTMLInternalError write the data, converted to text as possible, to
// the response body as HTML with an internal server error (e.g. 500)
// response code.
func WriteHTMLInternalError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 500
	WriteHTMLResponse(ctx, w, http.StatusInternalServerError, data)
}
