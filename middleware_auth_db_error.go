package gimlet

import (
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
)

// reauthenticationRequiredCode is the MongoDB error code for an expired auth
// session. See mongo/base/error_codes.yml.
const reauthenticationRequiredCode = 391

const reauthenticationRequiredName = "ReauthenticationRequired"

// isTransientDBAuthError returns whether the error came from the server's own
// database auth session expiring rather than the requester's credentials.
func isTransientDBAuthError(err error) bool {
	if err == nil {
		return false
	}

	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) && cmdErr.HasErrorCode(reauthenticationRequiredCode) {
		return true
	}

	// Match the message too, since a failed reauth attempt and a
	// multiUserManager aggregate both lose the typed error. The match is
	// broad, but a false positive only turns a 401 into a retryable 503 and
	// still sets no user. Neither string is driver API, so recheck them
	// against x/mongo/driver/operation.go on a driver upgrade.
	msg := err.Error()
	return strings.Contains(msg, "error reauthenticating") ||
		strings.Contains(msg, reauthenticationRequiredName)
}

// transientDBAuthErrorMessage is sent instead of an authorization failure so
// clients know the request is worth retrying.
const transientDBAuthErrorMessage = "database authentication is temporarily unavailable, retry the request"
