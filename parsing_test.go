package gimlet

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonishParser func(io.ReadCloser, interface{}) error

func TestReadingStructuredDataFromRequestBodies(t *testing.T) {
	assert := assert.New(t)

	type form struct {
		Name  string `json:"name" yaml:"name"`
		Count int    `json:"count" yaml:"count"`
	}

	for _, parserFunc := range []jsonishParser{GetYAML, GetJSON, GetJSONUnlimited, GetYAMLUnlimited} {

		// case one: everything works

		buf := bytes.NewBufferString(`{"name": "gimlet", "count": 2}`)

		bufcloser := ioutil.NopCloser(buf)
		out := form{}

		assert.NoError(parserFunc(bufcloser, &out))
		assert.Equal(2, out.Count)
		assert.Equal("gimlet", out.Name)

		// case two: basd json

		buf = bytes.NewBufferString(`{"name": "gimlet"`)
		bufcloser = ioutil.NopCloser(buf)
		out2 := form{}

		assert.Error(parserFunc(bufcloser, &out2))

		assert.Zero(out2.Count)
		assert.Zero(out2.Name)

		assert.Error(parserFunc(nil, map[string]string{}))
	}
}

func TestGetVarsInvocation(t *testing.T) {
	assert.Panics(t, func() { GetVars(nil) })
	assert.Nil(t, GetVars(&http.Request{}))
	assert.Nil(t, GetVars(httptest.NewRequest("GET", "http://localhost/bar", nil)))
}

type erroringReadCloser struct{}

func (*erroringReadCloser) Read(_ []byte) (int, error) { return 0, errors.New("test") }
func (*erroringReadCloser) Close() error               { return nil }

func TestRequestReadingErrorPropogating(t *testing.T) {
	errc := &erroringReadCloser{}

	assert.Error(t, GetJSON(errc, "foo"))
	assert.Error(t, GetYAML(errc, "foo"))
	assert.Error(t, GetJSONUnlimited(errc, "foo"))
	assert.Error(t, GetYAMLUnlimited(errc, "foo"))
}

func TestSetURLVars(t *testing.T) {
	r, err := http.NewRequest("GET", "/url", nil)
	assert.NoError(t, err)
	var nilMap map[string]string
	assert.Equal(t, nilMap, GetVars(r))
	vars := map[string]string{"foo": "bar"}
	r = SetURLVars(r, vars)
	assert.Equal(t, vars, GetVars(r))
}

func TestDecodeVars(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/url", nil)
	require.NoError(t, err)
	vars := map[string]string{"task_id": "should%21decode", "project_id": "shouldnt_decode", "patch_id": "shouldnt/decode"}
	r = SetURLVars(r, vars)
	assert.Equal(t, "should!decode", GetVars(r)["task_id"])
	assert.Equal(t, "shouldnt_decode", GetVars(r)["project_id"])
	assert.Equal(t, "shouldnt/decode", GetVars(r)["patch_id"])
}
