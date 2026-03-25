package gimlet

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePageInvalidUrls(t *testing.T) {
	p := &Page{}
	assert.Error(t, p.Validate())

	p.BaseURL = "fdalkja-**(3e/)\n\n+%%%%%"
	assert.Error(t, p.Validate())

	p.BaseURL = "http://example.com"
	p.KeyQueryParam = "key"
	p.LimitQueryParam = "limit"
	p.Relation = "next"
	p.Key = "value"
	assert.NoError(t, p.Validate())
}

func TestGetPageLink(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	url, err := url.Parse("http://example.net")
	assert.NoError(err)
	p := &Page{
		url: url,
	}

	p.BaseURL = "fdalkja-**(3e/)\n\n+%%%%%"
	assert.Equal(p.GetLink(ctx, "foo"), "<http://example.net?=>; rel=\"\"")
	p.BaseURL = ""

	assert.Equal("", p.BaseURL)
	assert.Equal(p.GetLink(ctx, "foo"), "</foo?=>; rel=\"\"")

	p.Limit = 400
	p.LimitQueryParam = "bar"
	p.KeyQueryParam = "baz"
	p.Key = "cheep"
	assert.Equal(p.GetLink(ctx, "foo"), "</foo?bar=400&baz=cheep>; rel=\"\"")
}

func TestPaginationMetadataGetLinks(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	rp := &ResponsePages{}
	assert.Nil(rp.Next)
	assert.Nil(rp.Prev)

	assert.Equal(rp.GetLinks(ctx, "/foo"), "")

	rp.Next = &Page{
		url: &url.URL{},
	}
	assert.Len(strings.Split(rp.GetLinks(ctx, "/bar"), ","), 1)

	rp.Prev = &Page{
		url: &url.URL{},
	}
	assert.Len(strings.Split(rp.GetLinks(ctx, "/baz"), ","), 2)

}
