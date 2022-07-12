package backup

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/common-fate/granted-approvals/pkg/clio"
	"github.com/common-fate/granted-approvals/pkg/deploy"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:        "backup",
	Description: "Backup Granted Approvals",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "confirm", Usage: "if provided, will automatically deploy without asking for confirmation"},
	},
	Subcommands: []*cli.Command{&BackupStatus},
	Action: func(c *cli.Context) error {
		ctx := c.Context

		f := c.Path("file")

		dc := deploy.MustLoadConfig(f)

		// Ensure aws account session is valid
		deploy.MustHaveAWSCredentials(ctx, deploy.WithWarnExpiryIfWithinDuration(time.Minute))

		stackOutput, err := dc.LoadOutput(ctx)
		if err != nil {
			return err
		}

		p := &survey.Input{
			Message: "Enter a backup name",
		}
		var backupName string
		err = survey.AskOne(p, &backupName, survey.WithValidator(func(ans interface{}) error {
			a := ans.(string)
			r := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
			match := r.MatchString(a)
			if match {
				return fmt.Errorf("value: `%s` must satisfy regular expression pattern: [a-zA-Z0-9_.-]+", a)
			}
			return nil
		}))
		if err != nil {
			return err
		}

		clio.Info("Creating backup of Granted Approvals dynamoDB table: %s", stackOutput.DynamoDBTable)
		confirm := c.Bool("confirm")
		if !confirm {
			cp := &survey.Confirm{Message: "Do you wish to continue?", Default: true}
			err = survey.AskOne(cp, &confirm)
			if err != nil {
				return err
			}
		}

		if !confirm {
			return errors.New("user cancelled backup")
		}
		backupOutput, err := deploy.StartBackup(ctx, stackOutput.DynamoDBTable, backupName)
		if err != nil {
			return err
		}
		clio.Success("Successfully started a backup of Granted Approvals dynamoDB table: %s", stackOutput.DynamoDBTable)
		clio.Info("Backup details\n%s", deploy.BackupDetailsToString(backupOutput))
		clio.Info("To view the status of this backup, run `gdeploy backup status --arn=%s`", aws.ToString(backupOutput.BackupArn))
		clio.Info("To restore from this backup, run `gdeploy restore --arn=%s`", aws.ToString(backupOutput.BackupArn))

		return nil
	},
}
