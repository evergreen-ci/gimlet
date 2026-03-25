package gimlet

import (
	"context"
	"net/http"
)

// WriteTextResponse writes data to the response body with the given
// code as plain text after attempting to convert the data to a byte
// array.
func WriteTextResponse(ctx context.Context, w http.ResponseWriter, code int, data interface{}) {
	writeResponse(ctx, TEXT, w, code, data)
}

// WriteText writes the data, converted to text as possible, to the response body, with a successful
// status code.
func WriteText(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 200
	WriteTextResponse(ctx, w, http.StatusOK, data)
}

// WriteTextError write the data, converted to text as possible, to the response body with a
// bad-request (e.g. 400) response code.
func WriteTextError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 400
	WriteTextResponse(ctx, w, http.StatusBadRequest, data)
}

// WriteTextInternalError write the data, converted to text as possible, to the response body with an
// internal server error (e.g. 500) response code.
func WriteTextInternalError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 500
	WriteTextResponse(ctx, w, http.StatusInternalServerError, data)
}
