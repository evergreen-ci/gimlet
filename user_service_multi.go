package gimlet

import (
	"context"
	"net/http"

	"github.com/mongodb/grip"
	"github.com/pkg/errors"
)

type multiUserManager struct {
	primary     UserManager
	secondaries []UserManager
}

// NewMultiUserManager multiplexes several UserManagers into a single
// UserManager. For write operations, UserManager methods are only invoked on
// the primary UserManager. For read operations, the UserManager runs the method
// against all managers until one returns a valid result. Managers are
// prioritized in the same order in which they are passed into this function.
func NewMultiUserManager(primary UserManager, secondaries ...UserManager) UserManager {
	return &multiUserManager{
		primary:     primary,
		secondaries: secondaries,
	}
}

func (um *multiUserManager) GetUserByToken(ctx context.Context, token string) (User, error) {
	var u User
	var err error
	if err = um.tryAllManagers(func(m UserManager) (bool, error) {
		u, err = m.GetUserByToken(ctx, token)
		return err == nil, err
	}); err != nil {
		return nil, errors.Wrap(err, "could not get user by token")
	}
	return u, nil
}

func (um *multiUserManager) CreateUserToken(username, password string) (string, error) {
	return um.primary.CreateUserToken(username, password)
}

func (um *multiUserManager) GetLoginHandler(rootURL string) http.HandlerFunc {
	var handler http.HandlerFunc
	_ = um.tryAllManagers(func(m UserManager) (bool, error) {
		handler = m.GetLoginHandler("")
		return handler == nil, nil
	})
	return handler
}

func (um *multiUserManager) GetLoginCallbackHandler() http.HandlerFunc {
	var handler http.HandlerFunc
	_ = um.tryAllManagers(func(m UserManager) (bool, error) {
		handler = m.GetLoginCallbackHandler()
		return handler == nil, nil
	})
	return handler
}

func (um *multiUserManager) IsRedirect() bool {
	var isRedirect bool
	_ = um.tryAllManagers(func(m UserManager) (bool, error) {
		isRedirect = m.IsRedirect()
		return isRedirect, nil
	})
	return isRedirect
}

func (um *multiUserManager) ReauthorizeUser(u User) error {
	var err error
	if err = um.tryAllManagers(func(m UserManager) (bool, error) {
		err = m.ReauthorizeUser(u)
		return err == nil, err
	}); err != nil {
		return errors.Wrap(err, "could not reauthorize user")
	}
	return nil
}

func (um *multiUserManager) GetUserByID(id string) (User, error) {
	var u User
	var err error
	if err = um.tryAllManagers(func(m UserManager) (bool, error) {
		u, err = m.GetUserByID(id)
		return err == nil, err
	}); err != nil {
		return nil, errors.Wrap(err, "could not get user by ID")
	}
	return u, nil
}

func (um *multiUserManager) GetOrCreateUser(u User) (User, error) {
	return um.primary.GetOrCreateUser(u)
}

func (um *multiUserManager) ClearUser(u User, all bool) error {
	return um.primary.ClearUser(u, all)
}

func (um *multiUserManager) GetGroupsForUser(username string) ([]string, error) {
	var groups []string
	var err error
	if err = um.tryAllManagers(func(m UserManager) (bool, error) {
		groups, err = m.GetGroupsForUser(username)
		return err == nil, err
	}); err != nil {
		return nil, errors.Wrap(err, "could not get groups for user")
	}
	return groups, nil
}

// tryAllManagers runs a function on each managers until either managerFunc tells
// it to stop (which is considered success) or it has tried and failed the
// operation on all managers.
func (um *multiUserManager) tryAllManagers(managerFunc func(UserManager) (stop bool, err error)) error {
	catcher := grip.NewBasicCatcher()
	for _, m := range append([]UserManager{um.primary}, um.secondaries...) {
		stop, err := managerFunc(m)
		if err == nil {
			return nil
		}
		if stop {
			return nil
		}
	}
	return catcher.Resolve()
}
