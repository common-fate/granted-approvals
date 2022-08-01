package accesssvc

import (
	"context"
	"time"

	"github.com/common-fate/ddb"
	"github.com/common-fate/granted-approvals/pkg/access"
	"github.com/common-fate/granted-approvals/pkg/gevent"
	"github.com/common-fate/granted-approvals/pkg/rule"
	"github.com/common-fate/granted-approvals/pkg/service/grantsvc"
	"github.com/common-fate/granted-approvals/pkg/storage"
	"github.com/common-fate/granted-approvals/pkg/storage/dbupdate"
	"github.com/common-fate/granted-approvals/pkg/types"
)

type AddReviewOpts struct {
	ReviewerID      string
	ReviewerIsAdmin bool
	Reviewers       []access.Reviewer
	Decision        access.Decision
	// Comment is optional on a review
	Comment *string
	// OverrideTimings are optional overrides for the request timings
	OverrideTiming *access.Timing
	Request        access.Request
	AccessRule     rule.AccessRule
}

type AddReviewResult struct {
	// The updated request, after the review is complete.
	Request access.Request
}

// AddReviewAndGrantAccess reviews a Request. It updates the status of the Request depending on the review decision.
// If the review approves access, access is granted.
func (s *Service) AddReviewAndGrantAccess(ctx context.Context, opts AddReviewOpts) (*AddReviewResult, error) {
	request := opts.Request
	if request.Status != access.PENDING {
		return nil, InvalidStatusError{Status: request.Status}
	}

	originalStatus := request.Status

	isAllowed := canReview(opts)
	if !isAllowed {
		return nil, ErrUserNotAuthorized
	}

	r := access.Review{
		ID:              types.NewRequestReviewID(),
		RequestID:       request.ID,
		ReviewerID:      opts.ReviewerID,
		Decision:        opts.Decision,
		Comment:         opts.Comment,
		OverrideTimings: opts.OverrideTiming,
	}

	// update the request status, based on the review decision
	switch r.Decision {
	case access.DecisionApproved:
		request.Status = access.APPROVED
		request.OverrideTiming = opts.OverrideTiming
		start, end := request.GetInterval(access.WithNow(s.Clock.Now()))
		// this request must not overlap an existing grant for the user and rule
		// This fetches all grants which end in the future, these may or may not have a grant associated yet.
		rq := storage.ListRequestsForUserAndRuleAndRequestend{
			UserID:               request.RequestedBy,
			RuleID:               request.Rule,
			RequestEndComparator: storage.GreaterThanEqual,
			CompareTo:            end,
		}
		_, err := s.DB.Query(ctx, &rq)
		if err != nil && err != ddb.ErrNoItems {
			return nil, err
		}
		// This will check against the requests which do have grants already
		overlaps := overlapsExistingGrant(start, end, rq.Result)
		if overlaps {
			return nil, ErrRequestOverlapsExistingGrant
		}
		// if the request is approved, attempt to create the grant.
		updatedRequest, err := s.Granter.CreateGrant(ctx, grantsvc.CreateGrantOpts{Request: request, AccessRule: opts.AccessRule})
		if err != nil {
			return nil, err
		}
		reviewed := types.REVIEWED
		request.ApprovalMethod = &reviewed
		request = *updatedRequest

	case access.DecisionDECLINED:
		request.Status = access.DECLINED
	}
	request.UpdatedAt = s.Clock.Now()

	// we need to save the Review, the updated Request in the database.
	items, err := dbupdate.GetUpdateRequestItems(ctx, s.DB, request, dbupdate.WithReviewers(opts.Reviewers))
	if err != nil {
		return nil, err
	}
	items = append(items, &r)

	if request.OverrideTiming != nil {
		// audit log event
		reqEvent := access.NewTimingChangeEvent(request.ID, request.UpdatedAt, &opts.ReviewerID, request.RequestedTiming, *request.OverrideTiming)
		items = append(items, &reqEvent)
	}
	// audit log event
	reqEvent := access.NewStatusChangeEvent(request.ID, request.UpdatedAt, &opts.ReviewerID, originalStatus, request.Status)

	items = append(items, &reqEvent)
	// store the updated items in the database
	err = s.DB.PutBatch(ctx, items...)
	if err != nil {
		return nil, err
	}

	switch r.Decision {
	case access.DecisionApproved:
		err = s.EventPutter.Put(ctx, gevent.RequestApproved{Request: request, ReviewerID: r.ReviewerID})
	case access.DecisionDECLINED:
		err = s.EventPutter.Put(ctx, gevent.RequestDeclined{Request: request, ReviewerID: r.ReviewerID})
	}

	// In a future PR we will shift these events out to be triggered by dynamo db streams
	// This will currently put the app in a strange state if this fails
	if err != nil {
		return nil, err
	}

	res := AddReviewResult{
		Request: request,
	}

	return &res, nil
}

func overlapsExistingGrant(start, end time.Time, upcomingRequests []access.Request) bool {
	if len(upcomingRequests) == 0 {
		return false
	}
	// maybe we need to add a buffer here to prevent edge cases where a race condition occurs in the step functions and access is provisioned for a new grant and cancelled for an old one leaving no access.
	for _, r := range upcomingRequests {
		if r.Grant != nil {
			if (start.Before(r.Grant.End) || start.Equal(r.Grant.End)) && (end.After(r.Grant.Start) || end.Equal(r.Grant.Start)) {
				return true
			}
		}

	}
	return false
}

// users can review requests if they are a Granted administrator,
// or if they are a Reviewer on the request.
func canReview(opts AddReviewOpts) bool {
	if opts.ReviewerID == opts.Request.RequestedBy {
		return false
	}
	if opts.ReviewerIsAdmin {
		return true
	}
	for _, r := range opts.Reviewers {
		if opts.ReviewerID == r.ReviewerID {
			return true
		}
	}
	// the user isn't allowed to review the request.
	return false
}
