package slacknotifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/common-fate/granted-approvals/pkg/access"
	"github.com/common-fate/granted-approvals/pkg/gevent"
	"github.com/common-fate/granted-approvals/pkg/identity"
	"github.com/common-fate/granted-approvals/pkg/notifiers"
	"github.com/common-fate/granted-approvals/pkg/rule"
	"github.com/common-fate/granted-approvals/pkg/storage"
	"github.com/pkg/errors"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

func (n *Notifier) HandleRequestEvent(ctx context.Context, log *zap.SugaredLogger, slackClient *slack.Client, event events.CloudWatchEvent) error {
	var requestEvent gevent.RequestEventPayload
	err := json.Unmarshal(event.Detail, &requestEvent)
	if err != nil {
		return err
	}
	req := requestEvent.Request

	ruleQuery := storage.GetAccessRuleVersion{ID: req.Rule, VersionID: req.RuleVersion}
	_, err = n.DB.Query(ctx, &ruleQuery)
	if err != nil {
		return errors.Wrap(err, "getting access rule")
	}
	rule := *ruleQuery.Result

	userQuery := storage.GetUser{ID: req.RequestedBy}
	_, err = n.DB.Query(ctx, &userQuery)
	if err != nil {
		return errors.Wrap(err, "getting requestor")
	}

	switch event.DetailType {
	case gevent.RequestCreatedType:
		if ruleQuery.Result.Approval.IsRequired() {
			msg := fmt.Sprintf("Your request to access *%s* requires approval. We've notified the approvers and will let you know once your request has been reviewed.", ruleQuery.Result.Name)
			fallback := fmt.Sprintf("Your request to access %s requires approval.", ruleQuery.Result.Name)

			_, err = SendMessage(ctx, slackClient, userQuery.Result.Email, msg, fallback)
			if err != nil {
				log.Errorw("Failed to send direct message", "email", userQuery.Result.Email, "msg", msg, "error", err)
			}

			// Notify approvers
			reviewURL, err := notifiers.ReviewURL(n.FrontendURL, req.ID)
			if err != nil {
				return errors.Wrap(err, "building review URL")
			}

			// get the requestor's Slack user ID if it exists to render it nicely in the message to approvers.
			var slackUserID string
			requestor, err := slackClient.GetUserByEmailContext(ctx, userQuery.Result.Email)
			if err != nil {
				zap.S().Infow("couldn't get slack user from requestor - falling back to email address", "requestor.id", userQuery.Result.ID, zap.Error(err))
			}
			if requestor != nil {
				slackUserID = requestor.ID
			}

			var wg sync.WaitGroup

			reviewers := storage.ListRequestReviewers{RequestID: req.ID}
			_, err = n.DB.Query(ctx, &reviewers)

			if err != nil {
				return errors.Wrap(err, "getting reviewers")
			}

			log.Infow("messaging reviewers", "reviewers", reviewers)

			for _, usr := range reviewers.Result {
				if usr.ReviewerID == req.RequestedBy {
					log.Infow("skipping sending approval message to requestor", "user.id", usr)
					continue
				}

				wg.Add(1)
				go func(usr access.Reviewer) {
					defer wg.Done()
					approver := storage.GetUser{ID: usr.ReviewerID}
					_, err := n.DB.Query(ctx, &approver)
					if err != nil {
						log.Errorw("failed to fetch user by id while trying to send message in slack", "user.id", usr, zap.Error(err))
						return
					}

					summary, msg := BuildRequestMessage(RequestMessageOpts{
						Request:          req,
						Rule:             rule,
						RequestorSlackID: slackUserID,
						RequestorEmail:   userQuery.Result.Email,
						ReviewURLs:       reviewURL,
					})

					ts, err := SendMessageBlocks(ctx, slackClient, approver.Result.Email, msg, summary)
					if err != nil {
						log.Errorw("failed to send request approval message", "user", usr, zap.Error(err))
					}

					updatedUsr := usr
					updatedUsr.Notifications = access.Notifications{
						SlackMessageID: &ts,
					}
					log.Infow("updating reviewer with slack msg id", "updatedUsr.SlackMessageID", ts)

					err = n.DB.Put(ctx, &updatedUsr)

					if err != nil {
						log.Errorw("failed to update reviewer", "user", usr, zap.Error(err))
					}
				}(usr)
			}

			wg.Wait()
		} else {
			//Review not required
			msg := fmt.Sprintf(":white_check_mark: Your request to access *%s* has been automatically approved. Hang tight - we're provisioning the role now and will let you know when it's ready.", ruleQuery.Result.Name)
			fallback := fmt.Sprintf("Your request to access %s has been automatically approved.", ruleQuery.Result.Name)
			_ = n.SendDMWithLogOnError(ctx, slackClient, log, req.RequestedBy, msg, fallback)
		}
	case gevent.RequestApprovedType:
		msg := fmt.Sprintf("Your request to access *%s* has been approved. Hang tight - we're provisioning the access now and will let you know when it's ready.", ruleQuery.Result.Name)
		fallback := fmt.Sprintf("Your request to access %s has been approved.", ruleQuery.Result.Name)
		_ = n.SendDMWithLogOnError(ctx, slackClient, log, req.RequestedBy, msg, fallback)

		// Loop over the request reviewers
		reviewers := storage.ListRequestReviewers{RequestID: req.ID}
		_, err = n.DB.Query(ctx, &reviewers)
		if err != nil {
			return errors.Wrap(err, "getting reviewers")
		}

		log.Infow("messaging reviewers", "reviewers", reviewers.Result)

		for _, rev := range reviewers.Result {
			err := n.UpdateSlackMessage(ctx, slackClient, log, UpdateSlackMessageOpts{
				Review:            rev,
				Request:           req,
				RequestReviewerId: requestEvent.ReviewerID,
				Rule:              rule,
				DbRequestor:       userQuery.Result,
			})
			if err != nil {
				log.Errorw("failed to update slack message", "user", rev, zap.Error(err))
			}
		}
	case gevent.RequestCancelledType:
		// Loop over the request reviewers
		reviewers := storage.ListRequestReviewers{RequestID: req.ID}
		_, err = n.DB.Query(ctx, &reviewers)
		if err != nil {
			return errors.Wrap(err, "getting reviewers")
		}
		log.Infow("messaging reviewers", "reviewers", reviewers.Result)

		for _, usr := range reviewers.Result {
			err := n.UpdateSlackMessage(ctx, slackClient, log,
				UpdateSlackMessageOpts{
					Review:            usr,
					Request:           req,
					RequestReviewerId: req.RequestedBy, // requestor ~= reviewer (they cancelled their own)
					Rule:              rule,
					DbRequestor:       userQuery.Result,
				})
			if err != nil {
				log.Errorw("failed to update slack message", "user", usr, "req", req, zap.Error(err))
			}
		}
	case gevent.RequestDeclinedType:
		msg := fmt.Sprintf("Your request to access *%s* has been declined.", ruleQuery.Result.Name)
		fallback := fmt.Sprintf("Your request to access %s has been declined.", ruleQuery.Result.Name)
		_ = n.SendDMWithLogOnError(ctx, slackClient, log, req.RequestedBy, msg, fallback)

		// Loop over the request reviewers
		reviewers := storage.ListRequestReviewers{RequestID: req.ID}
		_, err = n.DB.Query(ctx, &reviewers)
		if err != nil {
			return errors.Wrap(err, "getting reviewers")
		}

		log.Infow("messaging reviewers", "reviewers", reviewers.Result)

		for _, usr := range reviewers.Result {
			err := n.UpdateSlackMessage(ctx, slackClient, log,
				UpdateSlackMessageOpts{
					Review:            usr,
					Request:           req,
					RequestReviewerId: requestEvent.ReviewerID,
					Rule:              rule,
					DbRequestor:       userQuery.Result,
				})
			if err != nil {
				log.Errorw("failed to update slack message", "user", usr, zap.Error(err))
			}
		}
	}
	return nil
}

type UpdateSlackMessageOpts struct {
	Review            access.Reviewer
	Request           access.Request
	RequestReviewerId string
	Rule              rule.AccessRule
	DbRequestor       *identity.User
}

func (n *Notifier) UpdateSlackMessage(ctx context.Context, slackClient *slack.Client, log *zap.SugaredLogger, opts UpdateSlackMessageOpts) error {

	// Skip if requestor == reviewer
	// if opts.Review.ReviewerID == opts.Request.RequestedBy  {
	// 	return nil
	// }

	// Get the reviewers email from db
	reviewerQuery := storage.GetUser{ID: opts.Review.ReviewerID}
	_, err := n.DB.Query(ctx, &reviewerQuery)
	if err != nil {
		return errors.Wrap(err, "getting reviewer")
	}
	// do the same but for the request reveiwer
	reqReviewer := storage.GetUser{ID: opts.RequestReviewerId}
	_, err = n.DB.Query(ctx, &reqReviewer)
	if err != nil && opts.Request.Status != access.CANCELLED {
		return errors.Wrap(err, "getting reviewer 2")
	}

	// get the requestor's Slack user ID if it exists to render it nicely in the message to approvers.
	var slackUserID string
	requestor, err := slackClient.GetUserByEmailContext(ctx, opts.DbRequestor.Email)
	if err != nil {
		// log this instead of returning
		log.Errorw("failed to get slack user id, defaulting to email", "user", opts.DbRequestor.Email, zap.Error(err))
	}
	if requestor != nil {
		slackUserID = requestor.ID
	}
	reviewURL, err := notifiers.ReviewURL(n.FrontendURL, opts.Request.ID)
	if err != nil {
		return errors.Wrap(err, "building review URL")
	}
	// Here we want to update the original approvers slack messages
	_, msg := BuildRequestMessage(RequestMessageOpts{
		Request:          opts.Request,
		Rule:             opts.Rule,
		RequestorSlackID: slackUserID,
		RequestorEmail:   opts.DbRequestor.Email,
		ReviewURLs:       reviewURL,
		Reviewer:         reviewerQuery.Result,
		RequestReviewer:  reqReviewer.Result,
	})
	msg.Timestamp = *opts.Review.Notifications.SlackMessageID

	err = UpdateMessageBlocks(ctx, slackClient, reviewerQuery.Result.Email, msg)
	if err != nil {
		return errors.Wrap(err, "failed to send updated request approval message")
	}
	return nil
}

type RequestMessageOpts struct {
	Request          access.Request
	Rule             rule.AccessRule
	ReviewURLs       notifiers.ReviewURLs
	RequestorSlackID string
	RequestorEmail   string
	Reviewer         *identity.User
	RequestReviewer  *identity.User
}

func BuildRequestMessage(o RequestMessageOpts) (summary string, msg slack.Message) {
	requestor := o.RequestorEmail
	if o.RequestorSlackID != "" {
		requestor = fmt.Sprintf("<@%s>", o.RequestorSlackID)
	}

	summary = fmt.Sprintf("New request for %s from %s", o.Rule.Name, o.RequestorEmail)

	when := "ASAP"
	if o.Request.RequestedTiming.StartTime != nil {
		t := o.Request.RequestedTiming.StartTime
		when = fmt.Sprintf("<!date^%d^{date_short_pretty} at {time}|%s>", t.Unix(), t.String())
	}

	status := strings.ToLower(string(o.Request.Status))
	status = strings.ToUpper(string(status[0])) + status[1:]

	requestDetails := []*slack.TextBlockObject{
		{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*When:*\n%s", when),
		},
		{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Duration:*\n%s", o.Request.RequestedTiming.Duration),
		},
		{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Status:*\n%s", status),
		},
	}

	// Only show the Request reason if it is not empty
	if o.Request.Data.Reason != nil && len(*o.Request.Data.Reason) > 0 {
		requestDetails = append(requestDetails, &slack.TextBlockObject{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Request Reason:*\n%s", *o.Request.Data.Reason),
		})
	}

	msg = slack.NewBlockMessage(
		slack.SectionBlock{
			Type: slack.MBTSection,
			Text: &slack.TextBlockObject{
				Type: slack.MarkdownType,
				Text: fmt.Sprintf("*<%s|New request for %s> from %s*", o.ReviewURLs.Review, o.Rule.Name, requestor),
			},
		},
		slack.SectionBlock{
			Type:   slack.MBTSection,
			Fields: requestDetails,
		},
	)

	if o.Reviewer != nil || o.Request.Status == access.CANCELLED {
		t := time.Now()
		when = fmt.Sprintf("<!date^%d^{date_short_pretty} at {time}|%s>", t.Unix(), t.String())

		text := fmt.Sprintf("*Reviewed by* %s at %s", o.RequestReviewer.Email, when)

		if o.Request.Status == access.CANCELLED {
			text = fmt.Sprintf("*Cancelled by* %s at %s", o.RequestorEmail, when)
		}

		reviewContextBlock := slack.NewContextBlock("", slack.TextBlockObject{
			Type: slack.MarkdownType,
			Text: text,
		})

		msg.Blocks.BlockSet = append(msg.Blocks.BlockSet, reviewContextBlock)
	}

	// If the request has just been sent (PENDING), then append Action Blocks
	if o.Request.Status == access.PENDING {
		msg.Blocks.BlockSet = append(msg.Blocks.BlockSet, slack.NewActionBlock("review_actions",
			slack.ButtonBlockElement{
				Type:     slack.METButton,
				Text:     &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Approve"},
				Style:    slack.StylePrimary,
				ActionID: "approve",
				Value:    "approve",
				URL:      o.ReviewURLs.Approve,
			},
			slack.ButtonBlockElement{
				Type:     slack.METButton,
				Text:     &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Close Request"},
				Style:    slack.StyleDanger,
				ActionID: "deny",
				Value:    "deny",
				URL:      o.ReviewURLs.Deny,
			},
		))

	}

	return summary, msg
}
