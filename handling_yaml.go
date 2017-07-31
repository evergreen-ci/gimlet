package gimlet

import (
	"io"
	"io/ioutil"
	"net/http"

	"github.com/mongodb/grip"
	yaml "gopkg.in/yaml.v2"
)

// WriteYAMLResponse writes a YAML document to the body of an HTTP
// request, setting the return status of to 500 if the YAML
// seralization process encounters an error, otherwise return
func WriteYAMLResponse(w http.ResponseWriter, code int, data interface{}) {
	out, err := yaml.Marshal(data)
	if err != nil {
		grip.CatchDebug(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(code)
	size, err := w.Write(out)
	if err != nil {
		grip.Warningf("encountered error %s writing a %d response", err.Error(), size)
	}
}

// WriteYAML is a helper method to write YAML data to the body of an
// HTTP request and return 200 (successful.)
func WriteYAML(w http.ResponseWriter, data interface{}) {
	// 200
	WriteYAMLResponse(w, http.StatusOK, data)
}

// WriteErrorYAML is a helper method to write YAML data to the body of
// an HTTP request and return 400 (user error.)
func WriteErrorYAML(w http.ResponseWriter, data interface{}) {
	// 400
	WriteYAMLResponse(w, http.StatusBadRequest, data)
}

// WriteInternalErrorYAML is a helper method to write YAML data to the
// body of an HTTP request and return 500 (internal error.)
func WriteInternalErrorYAML(w http.ResponseWriter, data interface{}) {
	// 500
	WriteYAMLResponse(w, http.StatusInternalServerError, data)
}

// GetYAML parses YAML from a io.ReadCloser (e.g. http/*Request.Body
// or http/*Response.Body) into an object specified by the
// request. Used in handler functiosn to retreve and parse data
// submitted by the client.
func GetYAML(r io.ReadCloser, data interface{}) error {
	defer r.Close()

	// TODO: limited reader
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(bytes, data)
}
