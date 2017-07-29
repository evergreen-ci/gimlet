package gimlet

import (
	"net/http"

	"github.com/mongodb/grip"
)

// WriteHTMLResponse writes an HTML response with the specified error code.
func WriteHTMLResponse(w http.ResponseWriter, code int, data interface{}) {
	out := convertToBytes(data)

	w.Header().Set("Content-Type", "plain/text; charset=utf-8")
	w.WriteHeader(code)
	size, err := w.Write(out)
	if err != nil {
		grip.Warningf("encountered error %s writing a %d (of %d) response",
			err.Error(), size, len(out))
	}
}

// WriteHTML writes the data, converted to text as possible, to the
// response body as HTML with a successful status code.
func WriteHTML(w http.ResponseWriter, data interface{}) {
	// 200
	WriteHTMLResponse(w, http.StatusOK, data)
}

// WriteErrorHTML write the data, converted to text as possible, to
// the response body as HTML with a bad-request (e.g. 400) response code.
func WriteErrorHTML(w http.ResponseWriter, data interface{}) {
	// 400
	WriteHTMLResponse(w, http.StatusBadRequest, data)
}

// WriteErrorHTML write the data, converted to text as possible, to
// the response body as HTML with an internal server error (e.g. 500)
// response code.
func WriteInternalErrorHTML(w http.ResponseWriter, data interface{}) {
	// 500
	WriteHTMLResponse(w, http.StatusInternalServerError, data)
}
