package gimlet

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type writeResponseBaseFunc func(http.ResponseWriter, int, interface{})
type writeResponseFunc func(http.ResponseWriter, interface{})

func TestResponseWritingFunctions(t *testing.T) {
	assert := assert.New(t)
	baseCases := map[OutputFormat]writeResponseBaseFunc{
		JSON:   WriteJSONResponse,
		BINARY: WriteBinaryResponse,
		YAML:   WriteYAMLResponse,
		TEXT:   WriteTextResponse,
		HTML:   WriteHTMLResponse,
	}

	for of, wf := range baseCases {
		for _, code := range []int{200, 400, 500} {
			r := httptest.NewRecorder()
			wf(r, code, "")
			assert.Equal(code, r.Code)

			header := r.Header()
			assert.Len(header, 1)
			ct, ok := header["Content-Type"]
			assert.True(ok)
			assert.Equal(ct, []string{of.ContentType()})

			body := r.Body.Bytes()
			assert.True(len(body) < 4)
		}
	}
}

func TestSerializationErrors(t *testing.T) {
	assert := assert.New(t)

	baseCases := map[OutputFormat]writeResponseBaseFunc{
		JSON: WriteJSONResponse,
		YAML: WriteYAMLResponse,
	}

	for _, wf := range baseCases {
		r := httptest.NewRecorder()

		wf(r, http.StatusOK, struct{ Foo chan struct{} }{Foo: make(chan struct{})})
		assert.Equal(r.Code, http.StatusInternalServerError)

		wf(r, http.StatusOK, errors.New("foo"))
		assert.Equal(r.Code, http.StatusInternalServerError)
	}
}

func TestResponsesWritingHelpers(t *testing.T) {
	assert := assert.New(t)
	testTable := map[int]map[OutputFormat]writeResponseFunc{
		http.StatusOK: {
			JSON:   WriteJSON,
			BINARY: WriteBinary,
			YAML:   WriteYAML,
			TEXT:   WriteText,
			HTML:   WriteHTML,
		},
		http.StatusBadRequest: {
			JSON:   WriteErrorJSON,
			BINARY: WriteErrorBinary,
			YAML:   WriteErrorYAML,
			TEXT:   WriteErrorText,
			HTML:   WriteErrorHTML,
		},
		http.StatusInternalServerError: {
			JSON:   WriteInternalErrorJSON,
			BINARY: WriteInternalErrorBinary,
			YAML:   WriteInternalErrorYAML,
			TEXT:   WriteInternalErrorText,
			HTML:   WriteInternalErrorHTML,
		},
	}

	for status, cases := range testTable {
		for of, wf := range cases {
			r := httptest.NewRecorder()
			wf(r, struct{}{})
			assert.Equal(status, r.Code)
			ct, ok := r.Header()["Content-Type"]
			assert.True(ok)
			assert.Equal(ct, []string{of.ContentType()})
			body := r.Body.Bytes()
			assert.True(len(body) < 4)
		}
	}
}
