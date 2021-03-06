package grantsvc

import (
	"context"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/common-fate/iso8601"

	"github.com/common-fate/ddb/ddbmock"
	ah_types "github.com/common-fate/granted-approvals/accesshandler/pkg/types"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/types/ahmocks"
	"github.com/common-fate/granted-approvals/pkg/access"
	"github.com/common-fate/granted-approvals/pkg/identity"
	"github.com/common-fate/granted-approvals/pkg/storage"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestCreateGrant(t *testing.T) {

	type testcase struct {
		name                           string
		withCreateGrantResponse        *ah_types.PostGrantsResponse
		withCreateGrantResponseErr     error
		withUser                       identity.User
		give                           CreateGrantOpts
		wantPostGRantsWithResponseBody ah_types.PostGrantsJSONRequestBody

		wantRequest *access.Request
		wantErr     error
	}
	clk := clock.NewMock()
	now := clk.Now()
	overrideStart := now.Add(time.Hour)
	// var err = "example 400 error"
	grantId := "abcd"
	testcases := []testcase{
		{
			name: "created success",
			give: CreateGrantOpts{
				Request: access.Request{
					Status: access.APPROVED,
					RequestedTiming: access.Timing{
						Duration:  time.Minute,
						StartTime: &now,
					}},
			},
			withCreateGrantResponse: &ah_types.PostGrantsResponse{
				JSON201: &struct {
					Grant *ah_types.Grant "json:\"grant,omitempty\""
				}{Grant: &ah_types.Grant{
					ID:      grantId,
					Start:   iso8601.New(now),
					End:     iso8601.New(now.Add(time.Minute)),
					Subject: "test@test.com",
				}},
			},
			withUser: identity.User{
				Email: "test@test.com",
			},
			wantPostGRantsWithResponseBody: ah_types.PostGrantsJSONRequestBody{
				Start:   iso8601.New(now),
				End:     iso8601.New(now.Add(time.Minute)),
				Subject: "test@test.com",
			},

			wantRequest: &access.Request{
				Status: access.APPROVED,
				RequestedTiming: access.Timing{
					Duration:  time.Minute,
					StartTime: &now,
				},
				Grant: &access.Grant{
					CreatedAt: clk.Now(),
					UpdatedAt: clk.Now(),
					Start:     now,
					End:       now.Add(time.Minute),
					Subject:   "test@test.com"},
			},
		},
		{
			name: "created success with override timing",
			give: CreateGrantOpts{
				Request: access.Request{
					Status: access.APPROVED,
					RequestedTiming: access.Timing{
						Duration:  time.Minute,
						StartTime: &now,
					},
					OverrideTiming: &access.Timing{
						Duration:  time.Minute * 2,
						StartTime: &overrideStart,
					}},
			},
			withCreateGrantResponse: &ah_types.PostGrantsResponse{
				JSON201: &struct {
					Grant *ah_types.Grant "json:\"grant,omitempty\""
				}{Grant: &ah_types.Grant{
					ID:      grantId,
					Start:   iso8601.New(overrideStart),
					End:     iso8601.New(overrideStart.Add(time.Minute * 2)),
					Subject: "test@test.com",
				}},
			},
			withUser: identity.User{
				Email: "test@test.com",
			},
			wantPostGRantsWithResponseBody: ah_types.PostGrantsJSONRequestBody{
				Start:   iso8601.New(overrideStart),
				End:     iso8601.New(overrideStart.Add(time.Minute * 2)),
				Subject: "test@test.com",
			},

			wantRequest: &access.Request{
				Status: access.APPROVED,

				RequestedTiming: access.Timing{
					Duration:  time.Minute,
					StartTime: &now,
				},
				OverrideTiming: &access.Timing{
					Duration:  time.Minute * 2,
					StartTime: &overrideStart,
				},
				Grant: &access.Grant{

					CreatedAt: clk.Now(),
					UpdatedAt: clk.Now(),
					Start:     overrideStart,
					End:       overrideStart.Add(time.Minute * 2),
					Subject:   "test@test.com"},
			},
		},
	}

	for _, tc := range testcases {

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			g := ahmocks.NewMockClientWithResponsesInterface(ctrl)
			g.EXPECT().PostGrantsWithResponse(gomock.Any(), gomock.Eq(tc.wantPostGRantsWithResponseBody)).Return(tc.withCreateGrantResponse, tc.withCreateGrantResponseErr).AnyTimes()
			c := ddbmock.New(t)
			c.MockQuery(&storage.GetUser{Result: &tc.withUser})

			s := Granter{AHClient: g, DB: c, Clock: clk}
			gotRequest, err := s.CreateGrant(context.Background(), tc.give)
			assert.Equal(t, tc.wantErr, err)

			assert.Equal(t, tc.wantRequest, gotRequest)
		})
	}
}
