package gimlet

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/mongodb/grip"
)

func WriteBinaryRespones(w http.ResponseWriter, code int, data interface{}) {
	var out []byte

	switch data := data.(type) {
	case []byte:
		out = data
	case string:
		out = []byte(data)
	case error:
		out = []byte(data.Error())
	case []string:
		for _, s := range data {
			out = append(out, []byte(s)...)
		}
	case fmt.Stringer:
		out = []byte(data.String())
	case *bytes.Buffer:
		out = data.Bytes()
	default:
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(status)
	w.Write(out)
}

// WriteBinaryResponse writes data to the response body with the given
// code as plain text after attempting to convert the data to a byte
// array.
func WriteBinaryResponse(w http.ResponseWriter, code int, data interface{}) {
	out := convertToBytes(data)

	w.Header().Set("Content-Type", "plain/text; charset=utf-8")
	w.WriteHeader(code)
	size, err := w.Write(out)
	if err != nil {
		grip.Warningf("encountered error %s writing a %d (of %d) response",
			err.Error(), size, len(out))
	}
}

// WriteBinary writes the data, converted to a byte slice as possible, to the response body, with a successful
// status code.
func WriteBinary(w http.ResponseWriter, data interface{}) {
	// 200
	WriteBinaryResponse(w, http.StatusOK, data)
}

// WriteErrorBinary write the data, converted to a byte slice as possible, to the response body with a
// bad-request (e.g. 400) response code.
func WriteErrorBinary(w http.ResponseWriter, data interface{}) {
	// 400
	WriteBinaryResponse(w, http.StatusBadRequest, data)
}

// WriteErrorBinary write the data, converted to a byte slice as possible, to the response body with an
// internal server error (e.g. 500) response code.
func WriteInternalErrorBinary(w http.ResponseWriter, data interface{}) {
	// 500
	WriteBinaryResponse(w, http.StatusInternalServerError, data)
}
