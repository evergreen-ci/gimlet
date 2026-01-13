package usercache

import (
	"context"

	"github.com/evergreen-ci/gimlet"
)

// PutUserGetToken returns a new token. Updating the user's TTL should happen in
// this function.
type PutUserGetToken func(context.Context, gimlet.User) (string, error)

// GetUserByToken is a function provided by the client to retrieve cached users
// by token.
// It returns an error if and only if there was an error retrieving the user
// from the cache.
// It returns (<user>, true, nil) if the user is present in the cache and is
// valid.
// It returns (<user>, false, nil) if the user is present in the cache but has
// expired.
// It returns (nil, false, nil) if the user is not present in the cache.
type GetUserByToken func(context.Context, string) (u gimlet.User, valid bool, err error)

// ClearUserToken is a function provided by the client to remove users' tokens
// from cache. Passing true will ignore the user passed and clear all users.
type ClearUserToken func(context.Context, gimlet.User, bool) error

// GetUserByID is a function provided by the client to get a user from persistent storage.
type GetUserByID func(context.Context, string) (u gimlet.User, valid bool, err error)

// GetOrCreateUser is a function provided by the client to get a user from
// persistent storage, or if the user does not exist, to create and save it.
type GetOrCreateUser func(context.Context, gimlet.User) (gimlet.User, error)

type Cache interface {
	Add(context.Context, gimlet.User) error
	Put(context.Context, gimlet.User) (string, error)
	Clear(context.Context, gimlet.User, bool) error
	GetOrCreate(context.Context, gimlet.User) (gimlet.User, error)
	Get(context.Context, string) (u gimlet.User, valid bool, err error)
	Find(context.Context, string) (u gimlet.User, valid bool, err error)
}
