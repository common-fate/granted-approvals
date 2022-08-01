package gevent

import "github.com/common-fate/granted-approvals/pkg/access"

const (
	RequestCreatedType   = "request.created"
	RequestApprovedType  = "request.approved"
	RequestCancelledType = "request.cancelled"
	RequestDeclinedType  = "request.declined"
)

// RequestCreated is emitted when a user requests access
// to something in the Approvals service.
type RequestCreated struct {
	Request access.Request `json:"request"`
}

func (RequestCreated) EventType() string {
	return RequestCreatedType
}

// RequestApproved is emitted when a
// user's request is approved.
type RequestApproved struct {
	Request    access.Request `json:"request"`
	ReviewerID string         `json:"reviewerId"`
}

func (RequestApproved) EventType() string {
	return RequestApprovedType
}

type RequestCancelled struct {
	Request access.Request `json:"request"`
}

func (RequestCancelled) EventType() string {
	return RequestCancelledType
}

type RequestDeclined struct {
	Request    access.Request `json:"request"`
	ReviewerID string         `json:"reviewerId"`
}

func (RequestDeclined) EventType() string {
	return RequestDeclinedType
}

// RequestEventPayload is a payload which is common to
// all Request events. It is used to conveniently unmarshal
// the Request payloads in our event handler code.
type RequestEventPayload struct {
	Request    access.Request `json:"request"`
	ReviewerID string         `json:"reviewerId"`
}
