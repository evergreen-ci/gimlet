package gimlet

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/mongodb/grip"
)

func convertToBytes(data interface{}) []byte {
	switch data := data.(type) {
	case []byte:
		return data
	case string:
		return []byte(data)
	case error:
		return []byte(data.Error())
	case []string:
		return []byte(strings.Join(data, "\n"))
	case fmt.Stringer:
		return []byte(data.String())
	case *bytes.Buffer:
		return data.Bytes()
	default:
		return []byte(fmt.Sprintf("%v", data))
	}
}

// WriteTextResponse writes data to the response body with the given
// code as plain text after attempting to convert the data to a byte
// array.
func WriteTextResponse(w http.ResponseWriter, code int, data interface{}) {
	out := convertToBytes(data)

	w.Header().Set("Content-Type", "plain/text; charset=utf-8")
	w.WriteHeader(code)
	size, err := w.Write(out)
	if err != nil {
		grip.Warningf("encountered error %s writing a %d (of %d) response",
			err.Error(), size, len(out))
	}
}

// WriteText writes the data, converted to text as possible, to the response body, with a successful
// status code.
func WriteText(w http.ResponseWriter, data interface{}) {
	// 200
	WriteTextResponse(w, http.StatusOK, data)
}

// WriteErrorText write the data, converted to text as possible, to the response body with a
// bad-request (e.g. 400) response code.
func WriteErrorText(w http.ResponseWriter, data interface{}) {
	// 400
	WriteTextResponse(w, http.StatusBadRequest, data)
}

// WriteErrorText write the data, converted to text as possible, to the response body with an
// internal server error (e.g. 500) response code.
func WriteInternalErrorText(w http.ResponseWriter, data interface{}) {
	// 500
	WriteTextResponse(w, http.StatusInternalServerError, data)
}
