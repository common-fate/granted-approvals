package api

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/common-fate/ddb/ddbmock"
	"github.com/common-fate/granted-approvals/pkg/identity"
	"github.com/common-fate/granted-approvals/pkg/storage"
	"github.com/stretchr/testify/assert"
)

func TestListGroups(t *testing.T) {
	type testcase struct {
		name      string
		idpGroups []identity.Group
		wantCode  int
		wantBody  string
	}

	testcases := []testcase{
		{
			name:     "ok",
			wantCode: http.StatusOK,
			idpGroups: []identity.Group{
				{
					ID:   "123",
					Name: "test",
				},
				{
					ID:   "1234",
					Name: "test",
				},
			},
			wantBody: `{"groups":[{"description":"","id":"123","name":"test"},{"description":"","id":"1234","name":"test"}],"next":null}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			db := ddbmock.New(t)
			db.MockQuery(&storage.ListGroupsForStatus{Result: tc.idpGroups})

			a := API{DB: db}
			handler := newTestServer(t, &a)

			req, err := http.NewRequest("GET", "/api/v1/admin/groups", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Cognito", "approvals:admin")

			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantCode, rr.Code)

			data, err := ioutil.ReadAll(rr.Body)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.wantBody, string(data))
		})
	}
}

func TestGetGroup(t *testing.T) {
	type testcase struct {
		name     string
		idpErr   error
		idpGroup *identity.Group
		wantCode int
		wantBody string
	}

	testcases := []testcase{
		{
			name:     "ok",
			wantCode: http.StatusOK,
			idpGroup: &identity.Group{

				ID:          "123",
				Name:        "Test",
				Description: "hello",
			},
			wantBody: `{"description":"hello","id":"123","name":"Test"}`,
		},
		{
			name:     "group not found",
			wantCode: http.StatusNotFound,
			idpErr:   identity.UserNotFoundError{User: "123"},
			wantBody: `{"error":"user 123 not found"}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			db := ddbmock.New(t)
			db.MockQueryWithErr(&storage.GetGroup{Result: tc.idpGroup}, tc.idpErr)

			a := API{DB: db}
			handler := newTestServer(t, &a)

			req, err := http.NewRequest("GET", "/api/v1/admin/groups/123", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantCode, rr.Code)

			data, err := ioutil.ReadAll(rr.Body)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.wantBody, string(data))
		})
	}
}
