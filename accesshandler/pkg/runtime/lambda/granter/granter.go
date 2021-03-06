package lambdagranter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/common-fate/apikit/logger"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/config"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers"
	"github.com/common-fate/granted-approvals/pkg/gevent"

	"github.com/common-fate/granted-approvals/accesshandler/pkg/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Granter struct {
	rawLog *zap.SugaredLogger
	cfg    config.GranterConfig
}

type EventType string

const (
	ACTIVATE   EventType = "ACTIVATE"
	DEACTIVATE EventType = "DEACTIVATE"
)

type InputEvent struct {
	Action EventType   `json:"action"`
	Grant  types.Grant `json:"grant"`
}

type Output struct {
	Grant types.Grant `json:"grant"`
}

// Grant provider is an interface which combines the methods needed for the lambda
type GrantProvider interface {
	providers.Accessor
}

func NewGranter(ctx context.Context, c config.GranterConfig) (*Granter, error) {
	log, err := logger.Build(c.LogLevel)
	if err != nil {
		return nil, err
	}
	zap.ReplaceGlobals(log.Desugar())
	b, err := config.ReadProviderConfig(ctx, "lambda")
	if err != nil {
		return nil, err
	}
	err = config.ConfigureProviders(ctx, b)
	if err != nil {
		return nil, err
	}
	return &Granter{rawLog: log, cfg: c}, nil
}

func (g *Granter) HandleRequest(ctx context.Context, in InputEvent) (Output, error) {
	grant := in.Grant
	log := g.rawLog.With("grant.id", grant.ID)
	log.Infow("Handling event", "event", in)
	prov, ok := config.Providers[grant.Provider]
	if !ok {
		return Output{}, &providers.ProviderNotFoundError{Provider: grant.Provider}
	}

	log.Infow("matched provider", "provider", prov)
	args, err := json.Marshal(grant.With)
	if err != nil {
		return Output{}, err
	}

	eventsBus, err := gevent.NewSender(ctx, gevent.SenderOpts{EventBusARN: g.cfg.EventBusArn})
	if err != nil {
		return Output{}, err
	}

	switch in.Action {
	case ACTIVATE:
		log.Infow("activating grant")
		err = prov.Provider.Grant(ctx, string(grant.Subject), args)
	case DEACTIVATE:
		log.Infow("deactivating grant")
		err = prov.Provider.Revoke(ctx, string(grant.Subject), args)
	default:
		err = fmt.Errorf("invocation type: %s not supported, type must be one of [ACTIVATE, DEACTIVATE]", in.Action)
	}

	// emit an event and return early if we failed (de)provisioning the grant
	if err != nil {
		eventErr := eventsBus.Put(ctx, gevent.GrantFailed{Grant: grant, Reason: err.Error()})
		if eventErr != nil {
			return Output{}, errors.Wrapf(err, "failed to emit event, emit error: %s", eventErr.Error())
		}
		return Output{}, err
	}

	// Emit an event based on whether we activated or deactivated the grant.
	var evt gevent.EventTyper
	switch in.Action {
	case ACTIVATE:
		grant.Status = types.ACTIVE
		evt = &gevent.GrantActivated{Grant: grant}
	case DEACTIVATE:
		grant.Status = types.EXPIRED
		evt = &gevent.GrantExpired{Grant: grant}
	}

	log.Infow("emitting event", "event", evt, "action", in.Action)
	err = eventsBus.Put(ctx, evt)
	if err != nil {
		return Output{}, err
	}

	o := Output{
		Grant: grant,
	}
	return o, nil
}
