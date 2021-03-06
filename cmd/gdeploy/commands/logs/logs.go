package logs

import "github.com/urfave/cli/v2"

var Command = cli.Command{
	Name:        "logs",
	Action:      cli.ShowSubcommandHelp,
	Subcommands: []*cli.Command{&getCommand, &watchCommand},
}

// ServiceLogGroupNameMap maps shorthand service labels to CFN output names
// These output names are defined in the CDK stack
// the services names are defined here for this CLI command, and may be different in other usages
var ServiceLogGroupNameMap = map[string]string{
	"api":           "APILogGroupName",
	"idp-sync":      "IDPSyncLogGroupName",
	"accesshandler": "AccessHandlerLogGroupName",
	"events":        "EventBusLogGroupName",
	"event-handler": "EventsHandlerLogGroupName",
	"granter":       "GranterLogGroupName",
	"slack-notifer": "SlackNotifierLogGroupName",
}

// the services names are defined here for this CLI command, and may be different in other usages
var ServiceNames = []string{"api",
	"idp-sync",
	"accesshandler",
	"events",
	"event-handler",
	"granter",
	"slack-notifer"}
