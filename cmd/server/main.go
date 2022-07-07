package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	ahConfig "github.com/common-fate/granted-approvals/accesshandler/pkg/config"

	"github.com/common-fate/apikit/logger"
	ahServer "github.com/common-fate/granted-approvals/accesshandler/pkg/server"
	"github.com/common-fate/granted-approvals/internal"
	"github.com/common-fate/granted-approvals/pkg/api"
	"github.com/common-fate/granted-approvals/pkg/auth/localauth"
	"github.com/common-fate/granted-approvals/pkg/deploy"
	"github.com/common-fate/granted-approvals/pkg/gevent"
	"github.com/common-fate/granted-approvals/pkg/identity/identitysync"

	"github.com/common-fate/granted-approvals/pkg/config"
	"github.com/common-fate/granted-approvals/pkg/server"
	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap"
)

func main() {
	go func() {
		err := runAccessHandler()
		if err != nil {
			log.Fatal(err)
		}
	}()
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var cfg config.Config
	ctx := context.Background()
	_ = godotenv.Load()

	err := envconfig.Process(ctx, &cfg)
	if err != nil {
		return err
	}

	log, err := logger.Build(cfg.LogLevel)
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(log.Desugar())

	if cfg.SentryDSN != "" {
		log.Info("sentry is enabled")
		err = sentry.Init(sentry.ClientOptions{
			Dsn: cfg.SentryDSN,
		})
		if err != nil {
			return err
		}
	}

	auth, err := localauth.New(ctx, localauth.Opts{
		UserPoolID:    cfg.CognitoUserPoolID,
		CognitoRegion: cfg.Region,
	})
	if err != nil {
		return err
	}

	ahc, err := internal.BuildAccessHandlerClient(ctx, cfg)
	if err != nil {
		return err
	}

	eventBus, err := gevent.NewSender(ctx, gevent.SenderOpts{
		EventBusARN: cfg.EventBusArn,
	})
	if err != nil {
		return err
	}

	api, err := api.New(ctx, api.Opts{
		Log:                 log,
		DynamoTable:         cfg.DynamoTable,
		AccessHandlerClient: ahc,
		EventSender:         eventBus,
		AdminGroup:          cfg.AdminGroup,
	})
	if err != nil {
		return err
	}

	var sync deploy.Identity
	err = json.Unmarshal([]byte(cfg.IdentitySettings), &sync)
	if err != nil {
		panic(err)
	}

	idsync, err := identitysync.NewIdentitySyncer(ctx, identitysync.SyncOpts{
		TableName:        cfg.DynamoTable,
		UserPoolId:       cfg.CognitoUserPoolID,
		IdpType:          cfg.IdpProvider,
		IdentitySettings: sync,
	})

	if err != nil {
		return err
	}

	s, err := server.New(ctx, server.Config{
		Config:         cfg,
		Log:            log,
		Authenticator:  auth,
		API:            api,
		IdentitySyncer: idsync,
	})
	if err != nil {
		return err
	}

	return s.Start(ctx)
}

// runAccessHandler runs a version of the access handler locally if RUN_ACCESS_HANDLER env var is not false, if not set it defaults to true
func runAccessHandler() error {
	ctx := context.Background()
	_ = godotenv.Load()

	var approvalsCfg config.Config
	err := envconfig.Process(ctx, &approvalsCfg)
	if err != nil {
		return err
	}

	// load the provider config from the granted-deployment.yml file and set the PROVIDER_CONFIG env var,
	// so that we only need to define providers in one place in local development
	do, err := deploy.LoadConfig("granted-deployment.yml")
	if err != nil {
		return err
	}
	providerJSON, err := json.Marshal(do.Providers)
	if err != nil {
		return err
	}
	os.Setenv("PROVIDER_CONFIG", string(providerJSON))

	if approvalsCfg.RunAccessHandler {
		var cfg ahConfig.Config
		err = envconfig.Process(ctx, &cfg)
		if err != nil {
			return err
		}

		s, err := ahServer.New(ctx, cfg)
		if err != nil {
			return err
		}

		return s.Start(ctx)
	}

	zap.S().Info("Not starting access handler because RUN_ACCESS_HANDLER is set to false")
	return nil

}
