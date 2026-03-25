package gimlet

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mongodb/grip"
	yaml "gopkg.in/yaml.v2"
)

// WriteYAMLResponse writes a YAML document to the body of an HTTP
// request, setting the return status of to 500 if the YAML
// seralization process encounters an error, otherwise return
func WriteYAMLResponse(ctx context.Context, w http.ResponseWriter, code int, data interface{}) {
	defer func() {
		if msg := recover(); msg != nil {
			m := fmt.Sprintf("parsing YAML message: %v", msg)
			grip.Debug(ctx, m)
			http.Error(w, m, http.StatusInternalServerError)
		}
	}()

	// ignoring the error because the yaml library always panics
	out, _ := yaml.Marshal(data)
	writeResponse(ctx, YAML, w, code, out)
}

// WriteYAML is a helper method to write YAML data to the body of an
// HTTP request and return 200 (successful.)
func WriteYAML(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 200
	WriteYAMLResponse(ctx, w, http.StatusOK, data)
}

// WriteYAMLError is a helper method to write YAML data to the body of
// an HTTP request and return 400 (user error.)
func WriteYAMLError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 400
	WriteYAMLResponse(ctx, w, http.StatusBadRequest, data)
}

// WriteYAMLInternalError is a helper method to write YAML data to the
// body of an HTTP request and return 500 (internal error.)
func WriteYAMLInternalError(ctx context.Context, w http.ResponseWriter, data interface{}) {
	// 500
	WriteYAMLResponse(ctx, w, http.StatusInternalServerError, data)
}
