package gimlet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mongodb/grip"
)

// Responder is an interface for constructing a response from a
// route. Fundamentally Responders are data types, and provide setters
// and getters to store data that
//
// In general, users will use one of gimlets response implementations,
// though clients may wish to build their own implementations to
// provide features not present in the existing
type Responder interface {
	// Validate returns an error if the page is not properly
	// constructed, although it is implementation specific, what
	// constitutes an invalid page.
	Validate() error

	//
	AddData(interface{}) error
	Data() interface{}

	SetFormat(OutputFormat) error
	Format() OutputFormat

	SetStatus(int) error
	Status() int

	Pages() *ResponsePages
	SetPages(*ResponsePages) error
}

type ResponsePages struct {
	Next *Page
	Prev *Page
}

func (r *ResponsePages) GetLinks(route string) string {
	links := []string{}

	if r.Next != nil {
		links = append(links, r.Next.GetLink(route))
	}

	if r.Prev != nil {
		links = append(links, r.Prev.GetLink(route))
	}

	return strings.Join(links, "\n")
}

func (r *ResponsePages) Validate() error {
	catcher := grip.NewCatcher()
	for _, p := range []*Page{r.Next, r.Prev} {
		if p == nil {
			continue
		}

		catcher.Add(p.Validate())
	}

	return catcher.Resolve()
}

type Page struct {
	BaseURL         string
	KeyQueryParam   string
	LimitQueryParam string

	Key      string
	Limit    int
	Relation string

	url *url.URL
}

func (p *Page) Validate() error {
	errs := []string{}

	if p.BaseURL == "" {
		errs = append(errs, "base url not specified")
	}

	if p.KeyQueryParam == "" {
		errs = append(errs, "key query parameter name not specified")
	}

	if p.LimitQueryParam == "" {
		errs = append(errs, "limit query parameter name not specified")
	}

	if p.Relation == "" {
		errs = append(errs, "page relation not specified")
	}

	if p.Key == "" {
		errs = append(errs, "limit not specified")
	}

	url, err := url.Parse(p.BaseURL)
	if err != nil {
		errs = append(errs, err.Error())
	}
	p.url = url

	return errors.New(strings.Join(errs, "; "))
}

func (p *Page) GetLink(route string) string {
	q := p.url.Query()
	q.Set(p.KeyQueryParam, p.Key)

	if p.Limit != 0 {
		q.Set(p.LimitQueryParam, fmt.Sprintf("%d", p.Limit))
	}

	p.url.RawQuery = q.Encode()

	return fmt.Sprintf("<%s>; rel=\"%s\"", p.url, p.Relation)
}

// RouteHandler provides an alternate method for defining routes with
// the goals of separating the core operations of handling a rest result.
type RouteHandler interface {
	// Factory produces, this makes it possible for you to store
	// request-scoped data in the implementation of the Handler
	// rather than attaching data to the context. The factory
	// allows gimlet to, internally, reconstruct a handler interface
	// for every request.
	Factory() Handler

	// Parse makes it possible to modify the request context and
	// populate the implementation of the RouteHandler. This also
	// allows you to isolate your interaction with the request
	// object.
	Parse(context.Context, *http.Request) (context.Context, error)

	// Runs the core buinsess logic for the route, returning a
	// Responder interface to provide structure around returning
	Run(context.Context) Responder
}

func handleHandler(h RouteHandler) http.HandleFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		handler := h.Factory()
		ctx, cancel := contetx.WithCancel(getContext())
		defer cancel()

		ctx, err = handler.Parse(ctx, r)
		if err != nil {
			grip.Error(err)
			WriteTextResponse(w, http.StatusBadRequest, err)
			return
		}

		resp := handler.Run(ctx)
		if resp == nil {
			grip.Error(err)
			WriteTextResponse(w, http.StatusInternalServerError, err)
			return
		}

		if err := resp.Validate(); err != nil {
			grip.Error(err)
			WriteTextResponse(w, http.StatusInternalServerError, err)
			return
		}

		if resp.Pages() != nil {
			w.Header().Set("Link", resp.Pages().GetLinks(r.URL.Path))
		}

		switch resp.Format() {
		case JSON:
			WriteJSONResponse(w, resp.Status(), resp.Data())
		case TEXT:
			WriteTextResponse(w, resp.Status(), resp.Data())
		case HTML:
			WriteHTMLResponse(w, resp.Status(), resp.Data())
		case BINARY:
			WriteBinaryRespones(w, resp.Status(), resp.Data())
		}
	}
}

func NewResponseBuilder() Responder { return &responseBuilder{} }

type responseBuilder struct {
	data   []interface{}
	format OutputFormat
	status int
	pages  *ResponsePages
}

func (r *responseBuilder) Data() interface{} {
	switch len(data) {
	case 1:
		return data[0]
	case 0:
		return struct{}{}
	default:
		return data
	}
}

func (r *responseBuilder) Validate() error       { return nil }
func (r *responseBuilder) Format() OutputFormat  { return r.format }
func (r *responseBuilder) Status() int           { return r.status }
func (r *responseBuilder) Pages() *ResponsePages { return r.pages }

func (r *responseBuilder) AddData(d interface{}) error {
	if r.data == nil {
		return errors.New("cannot add nil data to responder")
	}

	r.data = append(r.data, d)
}

func (r *responseBuilder) SetFormat(o OutputFormat) error {
	if !o.IsValid() {
		return errors.New("invalid output format")
	}

	r.format = o
	return nil
}

func (r *responseBuilder) SetStatus(s int) error {
	if http.StatusText(s) == "" {
		return fmt.Errorf("%d is not a valid HTTP status", s)
	}

	r.status = s
	return nil
}

func (r *responseBuilder) SetPages(p *ResponsePages) error {
	if err := p.Validate(); err != nil {
		return errors.Wrap(err, "cannot set an invalid page definition")
	}

	r.Pages = p
	return nil
}

func NewBasicResponder(data interface{}, f OutputFormat, s int) (Responder, error) {
	r := &responderImpl{}

	errs := []string{}
	if err := r.SetStatus(s); err != nil {
		errs = append(errs, err.Error())
	}

	if err := r.AddData(data); err != nil {
		errs = append(errs, err.Error())
	}

	if err := r.SetFormat(f); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) != 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

type responderImpl struct {
	data   interface{}
	format OutputFormat
	status int
	pages  *ResponsePages
}

func (r *responderImpl) Validate() error       { return nil }
func (r *responderImpl) Data() interface{}     { return r.data }
func (r *responderImpl) Format() OutputFormat  { return r.format }
func (r *responderImpl) Status() int           { return r.status }
func (r *responderImpl) Pages() *ResponsePages { return r.pages }

func (r *responderImpl) AddData(d interface{}) error {
	if r.data == nil {
		return errors.New("cannot add new data to responder")
	}

	r.data = d
	return nil
}

func (r *responderImpl) SetFormat(o OutputFormat) error {
	if !o.IsValid() {
		return errors.New("invalid output format")
	}

	r.format = o
	return nil
}

func (r *responderImpl) SetStatus(s int) error {
	if http.StatusText(s) == "" {
		return fmt.Errorf("%d is not a valid HTTP status", s)
	}

	r.status = s
	return nil
}

func (r *responseImpl) SetPages(p *ResponsePages) error {
	if err := p.Validate(); err != nil {
		return errors.Wrap(err, "cannot set an invalid page definition")
	}

	r.Pages = p
	return nil
}
