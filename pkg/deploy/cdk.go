package deploy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CDKContextArgs returns the CDK context arguments
// in the form "-c" "ArgName=ArgValue"
//
// This should only be used in development, where the StackName variable is always of
// the form "granted-approvals-$STAGE". It panics if this is not the case.
func (c Config) CDKContextArgs() []string {
	name, err := c.GetDevStageName()
	if err != nil {
		panic(err)
	}

	name = CleanName(name)
	var args []string
	// pass context variables through as CLI arguments. This will eventually allow them to be
	// overridden in automated deployment workflows like in CI pipelines.
	args = append(args, "-c", fmt.Sprintf("stage=%s", name))
	args = append(args, "-c", fmt.Sprintf("cognitoDomainPrefix=cf-granted-%s", name))

	if c.Providers != nil {
		cfg, err := json.Marshal(c.Providers)
		if err != nil {
			panic(err)
		}

		args = append(args, "-c", fmt.Sprintf("providerConfiguration=%s", string(cfg)))
	}
	if c.Identity != nil {
		cfg, err := json.Marshal(c.Identity)
		if err != nil {
			panic(err)
		}

		args = append(args, "-c", fmt.Sprintf("identityConfiguration=%s", string(cfg)))
	}
	if c.Notifications != nil {
		if c.Notifications.Slack != nil {
			cfg, err := json.Marshal(c.Notifications.Slack)
			if err != nil {
				panic(err)
			}
			args = append(args, "-c", fmt.Sprintf("slackConfiguration=%s", string(cfg)))
		}
	}
	if c.Deployment.Parameters.IdentityProviderType != "" {
		args = append(args, "-c", fmt.Sprintf("idpType=%s", string(c.Deployment.Parameters.IdentityProviderType)))
	}
	if c.Deployment.Parameters.AdministratorGroupID != "" {
		args = append(args, "-c", fmt.Sprintf("adminGroupId=%s", string(c.Deployment.Parameters.AdministratorGroupID)))
	}
	if c.Deployment.Parameters.SamlSSOMetadata != "" {
		args = append(args, "-c", fmt.Sprintf("samlMetadata=%s", string(c.Deployment.Parameters.SamlSSOMetadata)))
	}
	if c.Deployment.Parameters.SamlSSOMetadataURL != "" {
		args = append(args, "-c", fmt.Sprintf("samlMetadataUrl=%s", string(c.Deployment.Parameters.SamlSSOMetadataURL)))
	}
	return args
}

// GetDevStageName returns the stage name to be used in a CDK deployment.
// It expects that the stack name is in the form "granted-approvals-$STAGE".
func (c Config) GetDevStageName() (string, error) {
	pre := "granted-approvals-"
	if !strings.HasPrefix(c.Deployment.StackName, pre) {
		return "", fmt.Errorf("stack name %s must start with %s for development", c.Deployment.StackName, pre)
	}
	return strings.TrimPrefix(c.Deployment.StackName, pre), nil
}
