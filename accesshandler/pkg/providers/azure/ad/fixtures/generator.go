package fixtures

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/common-fate/granted-approvals/accesshandler/pkg/genv"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers/azure/ad"
	"github.com/common-fate/granted-approvals/pkg/deploy"
	"github.com/segmentio/ksuid"
)

type Fixtures struct {
	User    string
	GroupID string
}

type Generator struct {
	client       ad.AzureClient
	tenantID     string
	clientID     string
	clientSecret string
}

// Configure the fixture generator
func (g *Generator) Config() genv.Config {
	return genv.Config{
		genv.String("clientID", &g.clientID, "the azure client ID"),
		genv.String("tenantID", &g.tenantID, "the azure tenant ID"),
		genv.SecretString("clientSecret", &g.clientSecret, "the azure API token"),
	}
}

func (g *Generator) Init(ctx context.Context) error {
	client, err := ad.NewAzure(ctx, deploy.Azure{
		TenantID:     g.tenantID,
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
	})
	if err != nil {
		return err
	}
	g.client = *client
	return nil
}

// Generate fixtures by calling the azure API.
func (g *Generator) Generate(ctx context.Context) ([]byte, error) {
	email := fmt.Sprintf("test_%s@exponentlabsio.onmicrosoft.com", ksuid.New().String())

	createUserRequest := ad.CreateADUser{
		AccountEnabled:    true,
		DisplayName:       "test",
		MailNickname:      "test",
		UserPrincipalName: email,
		PasswordProfile:   ad.PasswordProfile{ForceChangePasswordNextSignIn: true, Password: ksuid.New().String()},
	}

	err := g.client.CreateUser(ctx, createUserRequest)
	if err != nil {
		return nil, err
	}

	group := fmt.Sprintf("group_%s", ksuid.New().String())

	creategroup := ad.CreateADGroup{
		Description:     "test group",
		DisplayName:     group,
		MailNickname:    fmt.Sprintf("test_%s", ksuid.New().String()),
		GroupTypes:      []string{"Unified"},
		SecurityEnabled: false,
		MailEnabled:     true,
	}

	azureGroup, err := g.client.CreateGroup(ctx, creategroup)
	if err != nil {
		return nil, err
	}

	f := Fixtures{
		GroupID: azureGroup.ID,
		User:    email,
	}

	return json.Marshal(f)
}

func (g *Generator) Destroy(ctx context.Context, data []byte) error {
	var f Fixtures
	err := json.Unmarshal(data, &f)
	if err != nil {
		return err
	}

	err = g.client.DeleteGroup(ctx, f.GroupID)
	if err != nil {
		return err
	}

	err = g.client.DeleteUser(ctx, f.User)
	return err
}
