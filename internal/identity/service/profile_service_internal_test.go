package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNormalizeAndValidate_UnsetUsernameSkipsReservedCheck pins that an unset
// username is never compared against reservedUsernames.
//
// The empty string passes that check today only because it happens not to be a
// key in the map. This test removes the luck: it adds "" to the map and asserts
// an unset username is still accepted, so moving the reserved-handle check back
// out of the "is it set?" guard fails here rather than silently locking out
// every user who has not chosen a handle.
func TestNormalizeAndValidate_UnsetUsernameSkipsReservedCheck(t *testing.T) {
	reservedUsernames[""] = struct{}{}
	t.Cleanup(func() { delete(reservedUsernames, "") })

	out, err := normalizeAndValidate(ProfileInput{Username: "", Email: "alice@example.com"})

	require.NoError(t, err)
	require.Empty(t, out.Username)
}
