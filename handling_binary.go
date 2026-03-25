package gimlet

import (
	"context"
	"net/http"
)

// WriteBinaryResponse writes binary data to a response with the specified code.
func WriteBinaryResponse(ctx context.Context, w http.ResponseWriter, code int, data interface{}) {
	writeResponse(ctx, BINARY, w, code, data)
}

// WriteBinary writes the data, converted to a byte slice as possible, to the response body, with a successful
// status code.
func WriteBinary(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 200
	WriteBinaryResponse(ctx, w, http.StatusOK, data)
}

// WriteBinaryError write the data, converted to a byte slice as
// possible, to the response body with a bad-request (e.g. 400)
// response code.
func WriteBinaryError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 400
	WriteBinaryResponse(ctx, w, http.StatusBadRequest, data)
}

// WriteBinaryInternalError write the data, converted to a byte slice
// as possible, to the response body with an internal server error
// (e.g. 500) response code.
func WriteBinaryInternalError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 500
	WriteBinaryResponse(ctx, w, http.StatusInternalServerError, data)
}
