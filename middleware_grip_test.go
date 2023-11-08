package gimlet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/evergreen-ci/negroni"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/level"
	"github.com/mongodb/grip/logging"
	"github.com/mongodb/grip/message"
	"github.com/mongodb/grip/send"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestLogger(t *testing.T) {
	assert := assert.New(t)

	sender, err := send.NewInternalLogger("test", grip.GetSender().Level())
	assert.NoError(err)
	middleware := NewAppLogger().(*appLogging)
	middleware.Journaler = logging.MakeGrip(sender)

	next := func(w http.ResponseWriter, r *http.Request) {
		middleware.Journaler.Info("hello")
	}
	assert.False(sender.HasMessage())
	req := &http.Request{
		URL: &url.URL{},
	}
	rw := negroni.NewResponseWriter(nil)

	startAt := getNumber()
	middleware.ServeHTTP(rw, req, next)
	assert.Equal(startAt+2, getNumber())
	assert.True(sender.HasMessage())
	assert.Equal(sender.Len(), 2)
}

func TestRequestPanicLogger(t *testing.T) {
	assert := assert.New(t)

	sender, err := send.NewInternalLogger("test", grip.GetSender().Level())
	assert.NoError(err)
	middleware := NewRecoveryLogger(logging.MakeGrip(sender)).(*appRecoveryLogger)

	next := func(w http.ResponseWriter, r *http.Request) {
		middleware.Journaler.Info("hello")
	}
	assert.False(sender.HasMessage())
	req := &http.Request{
		URL: &url.URL{},
	}
	rw := negroni.NewResponseWriter(nil)

	startAt := getNumber()
	middleware.ServeHTTP(rw, req, next)
	assert.Equal(startAt+2, getNumber())
	assert.True(sender.HasMessage())
	assert.Equal(sender.Len(), 2)
}

func TestRequestPanicLoggerWithPanic(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	sender, err := send.NewInternalLogger("test", grip.GetSender().Level())
	assert.NoError(err)
	middleware := NewRecoveryLogger(logging.MakeGrip(sender))

	next := func(w http.ResponseWriter, r *http.Request) {
		panic("oops")
	}
	assert.False(sender.HasMessage())
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{},
	}
	testrw := httptest.NewRecorder()
	rw := negroni.NewResponseWriter(testrw)

	startAt := getNumber()
	middleware.ServeHTTP(rw, req, next)

	assert.Equal(startAt+2, getNumber())
	assert.True(sender.HasMessage())
	assert.Equal(sender.Len(), 1)

	m, ok := sender.GetMessageSafe()
	require.True(ok)
	require.NotNil(m)
	_, ok = m.Message.Raw().(message.Fields)
	assert.True(ok)
}

func TestRequestPanicLoggerWithErrAbortHandler(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	sender, err := send.NewInternalLogger("test", grip.GetSender().Level())
	assert.NoError(err)
	middleware := NewRecoveryLogger(logging.MakeGrip(sender))

	next := func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{},
	}
	testrw := httptest.NewRecorder()
	rw := negroni.NewResponseWriter(testrw)

	startAt := getNumber()
	middleware.ServeHTTP(rw, req, next)

	assert.Equal(startAt+2, getNumber())
	assert.True(sender.HasMessage())

	assert.Equal(sender.Len(), 1)
	m, ok := sender.GetMessageSafe()
	require.True(ok)
	require.NotNil(m)
	assert.Equal(level.Debug, m.Priority)
	fields, ok := m.Message.Raw().(message.Fields)
	require.True(ok)
	assert.Equal("hit suppressed abort panic", fields["message"])
}

func TestDefaultGripMiddlwareSetters(t *testing.T) {
	assert := assert.New(t)
	r := &http.Request{
		URL: &url.URL{Path: "foo"},
	}
	r = r.WithContext(context.Background())
	ctx := r.Context()

	var l grip.Journaler
	assert.NotPanics(func() { l = GetLogger(ctx) })
	assert.NotNil(l)
	assert.Equal(l.GetSender(), grip.GetSender())

	now := time.Now()
	logger := logging.MakeGrip(send.MakeInternalLogger())

	assert.NotEqual(logger, GetLogger(ctx))
	assert.Zero(getRequestStartAt(ctx))

	r = setupLogger(l, r)
	ctx = r.Context()

	assert.Equal(l, GetLogger(ctx))

	id := GetRequestID(ctx)

	assert.True(id > 0, "%d", id)
	assert.NotZero(getRequestStartAt(ctx))
	assert.True(now.Before(getRequestStartAt(ctx)))

}

func TestLoggingAnnotations(t *testing.T) {
	assert := assert.New(t)

	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{},
	}
	req = setLoggingAnnotations(req, loggingAnnotations{})
	AddLoggingAnnotation(req, "key", "value")

	la := getLoggingAnnotations(req.Context())
	val, ok := la["key"]
	assert.True(ok)
	assert.Equal("value", val)
}

func TestLoggingAnnotation(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	sender, err := send.NewInternalLogger("test", grip.GetSender().Level())
	assert.NoError(err)
	middleware := NewRecoveryLogger(logging.MakeGrip(sender))

	var called bool
	next := func(w http.ResponseWriter, r *http.Request) {
		AddLoggingAnnotation(r, "key", "value")
		called = true
	}

	assert.False(sender.HasMessage())
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{},
	}

	testrw := httptest.NewRecorder()
	rw := negroni.NewResponseWriter(testrw)

	startAt := getNumber()
	middleware.ServeHTTP(rw, req, next)
	assert.True(called)

	assert.Equal(startAt+2, getNumber())
	assert.True(sender.HasMessage())
	assert.Equal(sender.Len(), 1)

	m, ok := sender.GetMessageSafe()
	require.True(ok)
	require.NotNil(m)

	fields, ok := m.Message.Raw().(message.Fields)
	assert.True(ok)
	val, ok := fields["key"]
	assert.True(ok)
	assert.Equal("value", val)
}
