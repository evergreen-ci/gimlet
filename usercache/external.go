package usercache

import (
	"context"

	"github.com/evergreen-ci/gimlet"
	"github.com/mongodb/grip"
	"github.com/pkg/errors"
)

// ExternalOptions provides functions to inject the functionality of the user
// cache from an external source.
type ExternalOptions struct {
	PutUserGetToken PutUserGetToken
	GetUserByToken  GetUserByToken
	ClearUserToken  ClearUserToken
	GetUserByID     GetUserByID
	GetOrCreateUser GetOrCreateUser
}

func (opts ExternalOptions) Validate() error {
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(opts.PutUserGetToken == nil, "PutUserGetToken must be defined")
	catcher.NewWhen(opts.GetUserByToken == nil, "GetUserByToken must be defined")
	catcher.NewWhen(opts.ClearUserToken == nil, "ClearUserToken must be defined")
	catcher.NewWhen(opts.GetUserByID == nil, "GetUserByID must be defined")
	catcher.NewWhen(opts.GetOrCreateUser == nil, "GetOrCreateUser must be defined")
	return catcher.Resolve()
}

// NewExternal returns an external user cache.
func NewExternal(opts ExternalOptions) (Cache, error) {
	if err := opts.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid cache options")
	}
	return &ExternalCache{Opts: opts}, nil
}

type ExternalCache struct {
	Opts ExternalOptions
}

func (c *ExternalCache) Add(ctx context.Context, u gimlet.User) error {
	_, err := c.Opts.GetOrCreateUser(ctx, u)
	return err
}
func (c *ExternalCache) Put(ctx context.Context, u gimlet.User) (string, error) {
	return c.Opts.PutUserGetToken(ctx, u)
}
func (c *ExternalCache) Get(ctx context.Context, token string) (gimlet.User, bool, error) {
	return c.Opts.GetUserByToken(ctx, token)
}
func (c *ExternalCache) Clear(ctx context.Context, u gimlet.User, all bool) error {
	return c.Opts.ClearUserToken(ctx, u, all)
}
func (c *ExternalCache) Find(ctx context.Context, id string) (gimlet.User, bool, error) {
	return c.Opts.GetUserByID(ctx, id)
}
func (c *ExternalCache) GetOrCreate(ctx context.Context, u gimlet.User) (gimlet.User, error) {
	return c.Opts.GetOrCreateUser(ctx, u)
}
