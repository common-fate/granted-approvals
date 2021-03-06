package api

import (
	"errors"
	"net/http"

	"github.com/common-fate/apikit/apio"
	"github.com/common-fate/granted-approvals/pkg/auth"
	"github.com/common-fate/granted-approvals/pkg/identity"
	"github.com/common-fate/granted-approvals/pkg/storage"
	"github.com/common-fate/granted-approvals/pkg/types"
)

// Returns a list of users
// (GET /api/v1/users/)
func (a *API) GetUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := storage.ListUsersForStatus{Status: types.IdpStatusACTIVE}

	_, err := a.DB.Query(ctx, &q)
	if err != nil {
		apio.Error(ctx, w, err)
		return
	}

	res := types.ListUserResponse{
		Users: make([]types.User, len(q.Result)),
	}

	for i, u := range q.Result {
		res.Users[i] = u.ToAPI()
	}

	apio.JSON(ctx, w, res, http.StatusOK)

}

// Returns a user based on userId
// (GET /api/v1/users/{userId})
func (a *API) GetUser(w http.ResponseWriter, r *http.Request, userId string) {
	ctx := r.Context()

	q := storage.GetUser{ID: userId}

	_, err := a.DB.Query(ctx, &q)
	// return a 404 if the user was not found.
	if errors.As(err, &identity.UserNotFoundError{}) {
		err = apio.NewRequestError(err, http.StatusNotFound)
	}

	if err != nil {
		apio.Error(ctx, w, err)
		return
	}

	apio.JSON(ctx, w, q.Result, http.StatusOK)
}

// Get details for the current user
// (GET /api/v1/users/me)
func (a *API) GetMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := auth.UserFromContext(ctx)
	admin := auth.IsAdmin(ctx)
	res := types.AuthUserResponse{
		User:    u.ToAPI(),
		IsAdmin: admin,
	}
	apio.JSON(ctx, w, res, http.StatusOK)
}
